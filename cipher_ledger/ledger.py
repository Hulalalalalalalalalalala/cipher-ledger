"""Tenant-scoped record storage with envelope encryption and key rotation.

All operations take one process-wide re-entrant lock so the results of
concurrent creates, reads and rotations are equivalent to some total serial
ordering. Rotation verifies every old envelope first and only then performs a
single transactional write, so a damaged envelope or a storage failure leaves
the active version and all records exactly as they were before the request.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import sqlite3
import threading
from dataclasses import dataclass

from . import envelope
from . import encrypted_batch
from .config import Config
from .database import connect, initialize


class LedgerError(Exception):
    """Application-level error mapped to an HTTP status and code."""

    def __init__(self, status: int, code: str, message: str | None = None):
        super().__init__(code)
        self.status = status
        self.code = code
        # Optional human-readable detail identifying the offending input.
        # Existing endpoints leave it None, so their error bodies are unchanged.
        self.message = message


def conflict() -> LedgerError:
    return LedgerError(409, "conflict")


def not_found() -> LedgerError:
    return LedgerError(404, "not_found")


def integrity() -> LedgerError:
    return LedgerError(422, "integrity_error")


def storage() -> LedgerError:
    return LedgerError(503, "storage_error")


def invalid_request() -> LedgerError:
    return LedgerError(400, "invalid_request")


def invalid_batch(message: str) -> LedgerError:
    return LedgerError(400, "INVALID_BATCH", message)


def tenant_record_forbidden(message: str) -> LedgerError:
    return LedgerError(403, "TENANT_RECORD_FORBIDDEN", message)


def batch_write_failed(message: str) -> LedgerError:
    return LedgerError(500, "BATCH_WRITE_FAILED", message)


@dataclass(frozen=True)
class _Snapshot:
    """Immutable tenant record-id list captured at one serial point in time."""

    tenant: str
    record_ids: tuple[str, ...]


class Ledger:
    def __init__(self, config: Config):
        initialize(config.database, config.active_version)
        self._keys = dict(config.keys)
        self._connection = connect(config.database)
        self._lock = threading.RLock()
        self._cursor_secret = os.urandom(32)
        self._snapshots: dict[str, _Snapshot] = {}
        try:
            row = self._connection.execute(
                "SELECT value FROM service_metadata WHERE name='active_version'"
            ).fetchone()
            active = int(row[0])
        except (TypeError, ValueError, sqlite3.Error) as exc:
            raise ValueError("Invalid persisted active version") from exc
        if active not in self._keys:
            raise ValueError("Invalid keyring configuration")
        self._active_version = active

    # -- record listing ----------------------------------------------------

    def list_records(
        self, tenant: str, limit: int, cursor: str | None
    ) -> tuple[list[str], str | None]:
        """List a tenant's record ids from a single stable snapshot.

        A request without a cursor captures the tenant's current ids (ordered
        by id); later pages addressed by the returned opaque cursor keep
        serving that same tuple, so concurrent creates and key rotations
        neither duplicate nor drop entries. Only ids are returned, so damaged
        envelopes are still listed; reading such a record keeps failing the
        existing way. New records only become visible through a fresh request
        without a cursor. Returns (ids, next_cursor_or_None).
        """
        with self._lock:
            if cursor is None:
                offset = 0
                try:
                    rows = self._connection.execute(
                        "SELECT id FROM records WHERE tenant=? ORDER BY id ASC",
                        (tenant,),
                    ).fetchall()
                except sqlite3.Error:
                    raise storage() from None
                snapshot = _Snapshot(tenant, tuple(row["id"] for row in rows))
                token = os.urandom(18)
                token_hex = token.hex()
                # Single-page listings never hand out a cursor, so they need
                # no retained state; multi-page snapshots stay replayable.
                if len(snapshot.record_ids) > limit:
                    self._snapshots[token_hex] = snapshot
            else:
                token_hex, offset = self._parse_cursor(cursor)
                snapshot = self._snapshots.get(token_hex)
                if snapshot is None or snapshot.tenant != tenant:
                    raise invalid_request()
                if not 0 <= offset <= len(snapshot.record_ids):
                    raise invalid_request()

            end = offset + limit
            page = list(snapshot.record_ids[offset:end])
            next_cursor = (
                self._issue_cursor(token_hex, end, tenant)
                if end < len(snapshot.record_ids)
                else None
            )
            return page, next_cursor

    def _issue_cursor(self, token_hex: str, offset: int, tenant: str) -> str:
        body = base64.urlsafe_b64encode(
            json.dumps(
                {"t": token_hex, "o": offset, "n": tenant},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        # Omit base64 padding ("=") so the opaque cursor carries safely in a
        # query string without percent-encoding; padding is restored on parse.
        encoded_body = body.rstrip(b"=")
        tag = hmac.new(self._cursor_secret, encoded_body, hashlib.sha256).digest()
        encoded_tag = base64.urlsafe_b64encode(tag).rstrip(b"=")
        return (encoded_body + b"." + encoded_tag).decode("ascii")

    def _parse_cursor(self, cursor: str) -> tuple[str, int]:
        try:
            body, encoded_tag = cursor.encode("ascii").split(b".", 1)
            tag = base64.urlsafe_b64decode(encoded_tag + b"=" * (-len(encoded_tag) % 4))
            expected = hmac.new(self._cursor_secret, body, hashlib.sha256).digest()
            if len(tag) != 32 or not hmac.compare_digest(tag, expected):
                raise invalid_request()
            decoded_body = base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4))
            payload = json.loads(decoded_body)
            token_hex = payload["t"]
            offset = payload["o"]
            cursor_tenant = payload["n"]
        except (
            UnicodeEncodeError,
            ValueError,
            KeyError,
            TypeError,
            binascii.Error,
        ):
            raise invalid_request() from None
        if (
            not isinstance(payload, dict)
            or not isinstance(token_hex, str)
            or not isinstance(cursor_tenant, str)
            or type(offset) is not int
            or len(token_hex) != 36
            or not all(char in "0123456789abcdef" for char in token_hex)
        ):
            raise invalid_request()
        return token_hex, offset

    @property
    def active_version(self) -> int:
        with self._lock:
            return self._active_version

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    # -- records -----------------------------------------------------------

    def create(self, tenant: str, record_id: str, plaintext: str) -> int:
        """Create a record. Returns the key version used. Duplicate -> 409."""
        with self._lock:
            version = self._active_version
            sealed = envelope.seal(self._keys, version, tenant, record_id, plaintext)
            try:
                with self._connection:
                    self._insert(
                        tenant,
                        record_id,
                        sealed["key_version"],
                        sealed["nonce"],
                        sealed["ciphertext"],
                        sealed["wrap_nonce"],
                        sealed["wrapped_key"],
                    )
            except sqlite3.IntegrityError:
                # PRIMARY KEY (tenant, id) violation -> record already exists.
                raise conflict() from None
            except sqlite3.Error:
                raise storage() from None
            return version

    def create_batch(self, tenant: str, entries: list[tuple[str, str]]) -> tuple[int, list[str]]:
        """Create several records for one tenant atomically.

        Every record is sealed with an independent data key and nonce under the
        current active key version, then all rows are written in a single
        transaction. Duplicate ids within the batch or against existing records
        abort the whole batch with 409 before anything is written; a storage
        failure rolls the transaction back so no partial batch is observable.
        Returns (key_version, created_ids_in_input_order).
        """
        with self._lock:
            version = self._active_version
            record_ids = [record_id for record_id, _ in entries]
            # Pre-check conflicts before sealing or opening a write transaction.
            # Duplicates inside the batch and rows already present for this
            # tenant both surface as 409; nothing is written in either case.
            if len(set(record_ids)) != len(record_ids):
                raise conflict()
            try:
                rows = self._connection.execute(
                    "SELECT id FROM records WHERE tenant=? AND id IN (%s)"
                    % ",".join("?" * len(record_ids)),
                    (tenant, *record_ids),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None
            if rows:
                raise conflict()

            sealed_entries = [
                envelope.seal(self._keys, version, tenant, record_id, plaintext)
                for record_id, plaintext in entries
            ]
            try:
                with self._connection:
                    for record_id, sealed in zip(record_ids, sealed_entries):
                        self._insert(
                            tenant,
                            record_id,
                            sealed["key_version"],
                            sealed["nonce"],
                            sealed["ciphertext"],
                            sealed["wrap_nonce"],
                            sealed["wrapped_key"],
                        )
            except sqlite3.IntegrityError:
                # The conflict pre-check above ran under the same lock, so an
                # IntegrityError here can only be a storage-level failure (e.g.
                # an abort trigger); the transaction context has rolled back.
                raise storage() from None
            except sqlite3.Error:
                raise storage() from None
            return version, record_ids

    def _insert(
        self,
        tenant: str,
        record_id: str,
        version: int,
        nonce: bytes,
        ciphertext: bytes,
        wrap_nonce: bytes,
        wrapped_key: bytes,
    ) -> None:
        self._connection.execute(
            "INSERT INTO records "
            "(tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tenant, record_id, version, nonce, ciphertext, wrap_nonce, wrapped_key),
        )

    # -- client-sealed encrypted batches -----------------------------------

    def create_encrypted_batch(
        self,
        tenant: str,
        entries: list["encrypted_batch.EncryptedEntry"],
        idempotency_key: str | None,
    ) -> dict:
        """Validate then atomically commit a batch of client-sealed records.

        The server never opens, decrypts or shares the per-record envelope
        material: each entry's own envelope/nonce/ciphertext bytes are stored
        verbatim alongside the server-bound (tenant, id). Every check for the
        whole batch completes before the single write transaction opens, so
        the commit is all-or-nothing and all entries appear at one serial point.

        Returns the public 201 body. Raises LedgerError:
        403 TENANT_RECORD_FORBIDDEN - a record claims another tenant;
        400 INVALID_BATCH           - id/order/existence/idempotency conflict;
        500 BATCH_WRITE_FAILED      - any constraint or append failure, rolled
                                      back with nothing observable.
        """
        with self._lock:
            # 1) A per-record tenant claim that disagrees with the upstream
            #    identity is a cross-tenant write attempt, not a bad shape.
            for index, entry in enumerate(entries):
                if entry.tenant_claim is not None and entry.tenant_claim != tenant:
                    raise tenant_record_forbidden(
                        f"records[{index}].tenant: record claims tenant "
                        f"'{entry.tenant_claim}' but request is authenticated as '{tenant}'"
                    )

            record_ids = [entry.record_id for entry in entries]
            fingerprint = self._encrypted_batch_fingerprint(entries)

            # 2) Idempotent replay. A retried key whose content matches the
            #    original commit returns that commit exactly once more; a key
            #    reused with different content is an invalid conflicting batch.
            if idempotency_key is not None:
                replay = self._find_idempotent_commit(tenant, idempotency_key)
                if replay is not None:
                    committed_batch_id, committed_ids, committed_fingerprint = replay
                    if committed_fingerprint != fingerprint or committed_ids != record_ids:
                        raise invalid_batch(
                            "idempotency_key: key was already committed with a "
                            "different set of records"
                        )
                    return self._encrypted_batch_body(
                        committed_batch_id, tenant, idempotency_key, record_ids
                    )

            # 3) Whole-batch existence pre-check against this tenant's rows.
            #    Other tenants' ids are intentionally not matched: same id in
            #    another tenant is independent. In-batch duplicates were already
            #    rejected structurally and surface as INVALID_BATCH too.
            existing = self._existing_encrypted_ids(tenant, record_ids)
            if existing:
                conflict_id = next(record_id for record_id in record_ids if record_id in existing)
                raise invalid_batch(
                    f"records[{record_ids.index(conflict_id)}].id: record "
                    f"'{conflict_id}' already exists for tenant '{tenant}'"
                )

            # 4) One atomic commit: all record rows and the commit ledger row
            #    appear together or not at all.
            batch_id = self._new_batch_id()
            ids_json = json.dumps(record_ids, ensure_ascii=False, separators=(",", ":"))
            try:
                with self._connection:
                    for entry in entries:
                        self._connection.execute(
                            "INSERT INTO encrypted_records "
                            "(tenant, id, algorithm, envelope, nonce, ciphertext, "
                            "metadata, batch_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                tenant,
                                entry.record_id,
                                entry.algorithm_json,
                                base64.b64encode(entry.envelope).decode("ascii"),
                                entry.nonce,
                                entry.ciphertext,
                                entry.metadata_json,
                                batch_id,
                            ),
                        )
                    self._connection.execute(
                        "INSERT INTO batch_commits "
                        "(batch_id, tenant, idempotency_key, record_count, "
                        "record_ids, fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            batch_id,
                            tenant,
                            idempotency_key,
                            len(entries),
                            ids_json,
                            fingerprint,
                        ),
                    )
            except sqlite3.Error:
                # Constraint violation (including an abort trigger) or any
                # append/storage failure: the transaction has rolled back, no
                # record is visible and nothing is committed.
                raise batch_write_failed(
                    "batch could not be committed atomically; no records were written"
                ) from None

            return self._encrypted_batch_body(batch_id, tenant, idempotency_key, record_ids)

    @staticmethod
    def _encrypted_batch_fingerprint(entries: list["encrypted_batch.EncryptedEntry"]) -> str:
        """Deterministic SHA-256 over the exact sealed content of a batch."""
        digest = hashlib.sha256()
        for entry in entries:
            canonical = json.dumps(
                [
                    entry.record_id,
                    entry.tenant_claim,
                    entry.algorithm_json,
                    base64.b64encode(entry.envelope).decode("ascii"),
                    base64.b64encode(entry.nonce).decode("ascii"),
                    base64.b64encode(entry.ciphertext).decode("ascii"),
                    entry.metadata_json,
                ],
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            digest.update(str(len(canonical)).encode("ascii"))
            digest.update(b":")
            digest.update(canonical)
        return digest.hexdigest()

    def _find_idempotent_commit(
        self, tenant: str, idempotency_key: str
    ) -> tuple[str, list[str], str] | None:
        try:
            row = self._connection.execute(
                "SELECT batch_id, record_ids, fingerprint FROM batch_commits "
                "WHERE tenant=? AND idempotency_key=?",
                (tenant, idempotency_key),
            ).fetchone()
        except sqlite3.Error:
            raise batch_write_failed("could not look up idempotency key") from None
        if row is None:
            return None
        try:
            committed_ids = json.loads(row["record_ids"])
        except ValueError:
            raise batch_write_failed("stored commit metadata is unreadable") from None
        return row["batch_id"], committed_ids, row["fingerprint"]

    def _existing_encrypted_ids(self, tenant: str, record_ids: list[str]) -> set[str]:
        try:
            rows = self._connection.execute(
                "SELECT id FROM encrypted_records WHERE tenant=? AND id IN (%s)"
                % ",".join("?" * len(record_ids)),
                (tenant, *record_ids),
            ).fetchall()
        except sqlite3.Error:
            raise batch_write_failed("could not check existing records") from None
        return {row["id"] for row in rows}

    @staticmethod
    def _new_batch_id() -> str:
        token = base64.urlsafe_b64encode(os.urandom(18)).rstrip(b"=")
        return "bat_" + token.decode("ascii")

    @staticmethod
    def _encrypted_batch_body(
        batch_id: str, tenant: str, idempotency_key: str | None, record_ids: list[str]
    ) -> dict:
        body = {
            "batch_id": batch_id,
            "tenant": tenant,
            "count": len(record_ids),
            "records": [{"id": record_id, "status": "created"} for record_id in record_ids],
        }
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        return body

    def read(self, tenant: str, record_id: str) -> dict:
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT key_version, nonce, ciphertext, wrap_nonce, wrapped_key "
                    "FROM records WHERE tenant=? AND id=?",
                    (tenant, record_id),
                ).fetchone()
            except sqlite3.Error:
                raise storage() from None
            if row is None:
                raise not_found()
            try:
                plaintext = envelope.open_envelope(self._keys, tenant, record_id, row)
            except envelope.EnvelopeIntegrityError:
                raise integrity() from None
            return {"id": record_id, "plaintext": plaintext, "key_version": row["key_version"]}

    def read_batch(self, tenant: str, record_ids: list[str]) -> list[dict]:
        """Read several records of one tenant as one all-or-nothing request.

        Every envelope row is fetched in a single query. If any requested id is
        missing (or only exists for another tenant) the whole request fails
        with 404 before any envelope is opened, so a batch that mixes an
        unknown id with a damaged envelope still returns 404 and no plaintext
        is ever produced. Only once all ids are known to exist are the
        envelopes opened one by one; one authentication failure aborts the
        batch with 422. The method runs under the process-wide lock, so
        concurrent creates and rotations are observed as complete serial
        states (never a half-written batch or a half-rotated key version).
        Returns items in request order.
        """
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key "
                    "FROM records WHERE tenant=? AND id IN (%s)"
                    % ",".join("?" * len(record_ids)),
                    (tenant, *record_ids),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None
            by_id = {row["id"]: row for row in rows}
            if any(record_id not in by_id for record_id in record_ids):
                raise not_found()
            items: list[dict] = []
            for record_id in record_ids:
                row = by_id[record_id]
                try:
                    plaintext = envelope.open_envelope(self._keys, tenant, record_id, row)
                except envelope.EnvelopeIntegrityError:
                    raise integrity() from None
                items.append(
                    {"id": record_id, "plaintext": plaintext, "key_version": row["key_version"]}
                )
            return items

    # -- keys --------------------------------------------------------------

    def rotate(self, target: int) -> tuple[int, int]:
        """Rotate all records to ``target``. Returns (active_version, rewrapped)."""
        with self._lock:
            if target < self._active_version:
                raise LedgerError(409, "version_conflict")
            if target == self._active_version:
                return self._active_version, 0
            if target not in self._keys:
                raise LedgerError(400, "invalid_version")

            try:
                rows = self._connection.execute(
                    "SELECT tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key "
                    "FROM records"
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None

            # Verify and rewrap every envelope before any write. A single bad
            # envelope aborts the whole request with nothing changed.
            rewrapped: list[tuple] = []
            for row in rows:
                try:
                    new_wrap_nonce, new_wrapped = envelope.rewrap(
                        self._keys, row["tenant"], row["id"], row, target
                    )
                except envelope.EnvelopeIntegrityError:
                    raise integrity() from None
                rewrapped.append((new_wrap_nonce, new_wrapped, target, row["tenant"], row["id"]))

            try:
                with self._connection:
                    for new_wrap_nonce, new_wrapped, version, tenant, record_id in rewrapped:
                        self._connection.execute(
                            "UPDATE records SET wrap_nonce=?, wrapped_key=?, key_version=? "
                            "WHERE tenant=? AND id=?",
                            (new_wrap_nonce, new_wrapped, version, tenant, record_id),
                        )
                    self._connection.execute(
                        "UPDATE service_metadata SET value=? WHERE name='active_version'",
                        (str(target),),
                    )
            except sqlite3.Error:
                raise storage() from None

            self._active_version = target
            return target, len(rewrapped)
