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
from datetime import datetime, timezone

from . import envelope, sealed
from .config import Config
from .database import connect, initialize


class LedgerError(Exception):
    """Application-level error mapped to an HTTP status and code."""

    def __init__(self, status: int, code: str, message: str | None = None):
        super().__init__(code)
        self.status = status
        self.code = code
        # Public, human-readable detail (e.g. an input location). Existing
        # endpoints pass None so their error bodies stay {"error": code}.
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


def tenant_forbidden(message: str | None = None) -> LedgerError:
    return LedgerError(403, "TENANT_RECORD_FORBIDDEN", message)


def batch_write_failed() -> LedgerError:
    return LedgerError(500, "BATCH_WRITE_FAILED")


@dataclass(frozen=True)
class _Snapshot:
    """Immutable tenant record-id list captured at one serial point in time."""

    tenant: str
    record_ids: tuple[str, ...]


@dataclass(frozen=True)
class EncryptedEntry:
    """One already-sealed record inside an encrypted batch.

    All bytes are stored verbatim; the ledger never derives, unwraps or shares
    the body key. ``envelope_nonce`` authenticates the wrapped key and
    ``ciphertext_nonce`` the body independently.
    """

    record_id: str
    algorithm: str
    encryption_key_id: str | None
    envelope_nonce: bytes
    wrapped_key: bytes
    ciphertext: bytes
    ciphertext_nonce: bytes
    tag: bytes | None
    metadata: str | None


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

    # -- client-encrypted batch ingress ------------------------------------

    def ingest_encrypted_batch(
        self, tenant: str, entries: list[EncryptedEntry]
    ) -> tuple[str, list[str]]:
        """Atomically commit one tenant's batch of pre-sealed records.

        The caller has already validated shape, types, supported algorithm and
        cross-field consistency. This method is the authoritative conflict and
        commit boundary: it re-derives in-batch duplicate ids and existing ids
        for this tenant (both INVALID_BATCH, never distinguished), then writes
        the batch row, every record and an append-only event per record in a
        single transaction. Any constraint violation, ledger-append failure or
        storage error rolls the whole transaction back, leaving prior records
        untouched and the new records invisible (BATCH_WRITE_FAILED).

        Runs under the process-wide lock, so a concurrent retry of the same
        ids loses cleanly rather than landing a partial/duplicate batch.
        Returns (batch_id, ids_in_input_order).
        """
        with self._lock:
            record_ids = [entry.record_id for entry in entries]

            seen: set[str] = set()
            for index, record_id in enumerate(record_ids):
                if record_id in seen:
                    raise invalid_batch(
                        f"records[{index}].id is duplicated within the batch: {record_id}"
                    )
                seen.add(record_id)

            try:
                rows = self._connection.execute(
                    "SELECT id FROM encrypted_records WHERE tenant=? AND id IN (%s)"
                    % ",".join("?" * len(record_ids)),
                    (tenant, *record_ids),
                ).fetchall()
            except sqlite3.Error:
                raise batch_write_failed() from None
            if rows:
                existing = {row["id"] for row in rows}
                for index, record_id in enumerate(record_ids):
                    if record_id in existing:
                        raise invalid_batch(
                            f"records[{index}].id already exists for this tenant: {record_id}"
                        )

            batch_id = "batch_" + os.urandom(16).hex()
            created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            try:
                with self._connection:
                    self._connection.execute(
                        "INSERT INTO encrypted_batches "
                        "(batch_id, tenant, record_count, created_at) VALUES (?, ?, ?, ?)",
                        (batch_id, tenant, len(entries), created_at),
                    )
                    for position, entry in enumerate(entries):
                        self._connection.execute(
                            "INSERT INTO encrypted_records "
                            "(tenant, id, batch_id, position, algorithm, encryption_key_id, "
                            "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                tenant,
                                entry.record_id,
                                batch_id,
                                position,
                                entry.algorithm,
                                entry.encryption_key_id,
                                entry.envelope_nonce,
                                entry.wrapped_key,
                                entry.ciphertext,
                                entry.ciphertext_nonce,
                                entry.tag,
                                entry.metadata,
                            ),
                        )
                        self._connection.execute(
                            "INSERT INTO encrypted_record_events "
                            "(batch_id, tenant, record_id, position) VALUES (?, ?, ?, ?)",
                            (batch_id, tenant, entry.record_id, position),
                        )
            except sqlite3.Error:
                # PRIMARY KEY/UNIQUE violations (a same-ids commit winning the
                # race after the pre-check) and any ledger-append or storage
                # failure all roll the transaction back; nothing is observable.
                raise batch_write_failed() from None
            return batch_id, record_ids

    def read_encrypted_batch(self, tenant: str, batch_id: str) -> dict:
        """Return one tenant's whole sealed batch after a full integrity check.

        The read confirms the batch row, its records and its append events are
        one consistent structure, all under the process-wide lock so the three
        queries observe one complete serial state (a concurrent commit is seen
        either whole or not at all):

        * the batch must exist for ``tenant`` -- a batch owned by another
          tenant is reported as 404 and its contents are never inspected;
        * record_count is within the write-time 1..100 bound;
        * every record and event carrying this batch id belongs to the batch
          tenant -- no cross-tenant associations;
        * record and event counts both equal record_count, record positions
          (ordered by position) and event positions (ordered by append seq)
          each cover exactly 0..count-1 with no duplicates or gaps, and the
          (record_id, position) pairs match one-to-one;
        * each stored record still satisfies the write shape: identifier,
          algorithm, byte-field lengths, key_id and metadata JSON.

        Envelopes are never decrypted and ciphertext is never authenticated:
        shape-valid byte changes come back verbatim. Any inconsistency is a
        damaged-store 422 integrity_error with no partial records; a failed
        SQLite read is 503 storage_error. The method only SELECTs.
        """
        with self._lock:
            try:
                batch = self._connection.execute(
                    "SELECT tenant, record_count, created_at FROM encrypted_batches "
                    "WHERE batch_id=?",
                    (batch_id,),
                ).fetchone()
            except sqlite3.Error:
                raise storage() from None
            if batch is None or batch["tenant"] != tenant:
                # Another tenant's batch is indistinguishable from a missing
                # one; its details are deliberately not examined.
                raise not_found()

            count = batch["record_count"]
            created_at = batch["created_at"]
            if type(count) is not int or not 1 <= count <= sealed.MAX_BATCH_SIZE:
                raise integrity()
            if not isinstance(created_at, str):
                raise integrity()

            try:
                record_rows = self._connection.execute(
                    "SELECT tenant, id, position, algorithm, encryption_key_id, "
                    "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                    "FROM encrypted_records WHERE batch_id=? ORDER BY position",
                    (batch_id,),
                ).fetchall()
                event_rows = self._connection.execute(
                    "SELECT tenant, record_id, position FROM encrypted_record_events "
                    "WHERE batch_id=? ORDER BY seq",
                    (batch_id,),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None

            if len(record_rows) != count or len(event_rows) != count:
                raise integrity()
            if any(row["tenant"] != tenant for row in record_rows):
                raise integrity()
            if any(row["tenant"] != tenant for row in event_rows):
                raise integrity()

            positions = [row["position"] for row in record_rows]
            if any(type(position) is not int for position in positions):
                raise integrity()
            if positions != list(range(count)):
                raise integrity()

            record_ids = [row["id"] for row in record_rows]
            if any(not sealed.is_ident(record_id) for record_id in record_ids):
                raise integrity()
            if len(set(record_ids)) != count:
                raise integrity()

            # Events sorted by append sequence must line up, position by
            # position, with the records; sorted-position equality also proves
            # event positions are exactly 0..count-1 with no gaps or dupes.
            events_in_order = sorted(
                (row["position"], row["record_id"]) for row in event_rows
            )
            if any(type(position) is not int for position, _ in events_in_order):
                raise integrity()
            if events_in_order != list(enumerate(record_ids)):
                raise integrity()

            records: list[dict] = []
            for row in record_rows:
                profile = sealed.ENCRYPTED_ALGORITHMS.get(row["algorithm"])
                if profile is None:
                    raise integrity()
                if not sealed.valid_key_id(row["encryption_key_id"]):
                    raise integrity()
                envelope_nonce = row["envelope_nonce"]
                wrapped_key = row["wrapped_key"]
                body = row["ciphertext"]
                ciphertext_nonce = row["ciphertext_nonce"]
                tag = row["tag"]
                if not isinstance(envelope_nonce, bytes) or len(envelope_nonce) != profile["nonce"]:
                    raise integrity()
                if not isinstance(wrapped_key, bytes) or len(wrapped_key) != profile["wrapped_key"]:
                    raise integrity()
                if not isinstance(body, bytes) or len(body) > sealed.MAX_ENCRYPTED_BYTES:
                    raise integrity()
                if (
                    not isinstance(ciphertext_nonce, bytes)
                    or len(ciphertext_nonce) != profile["nonce"]
                ):
                    raise integrity()
                if not isinstance(tag, bytes) or len(tag) != profile["tag"]:
                    raise integrity()
                metadata_text = row["metadata"]
                if not sealed.valid_metadata_text(metadata_text):
                    raise integrity()
                metadata = json.loads(metadata_text) if metadata_text is not None else None
                records.append(
                    {
                        "id": row["id"],
                        "algorithm": row["algorithm"],
                        "key_id": row["encryption_key_id"],
                        "envelope": {
                            "nonce": sealed.encode_bytes_field(envelope_nonce),
                            "wrapped_key": sealed.encode_bytes_field(wrapped_key),
                        },
                        "ciphertext": {
                            "data": sealed.encode_bytes_field(body),
                            "nonce": sealed.encode_bytes_field(ciphertext_nonce),
                            "tag": sealed.encode_bytes_field(tag),
                        },
                        "metadata": metadata,
                    }
                )

            return {
                "batch_id": batch_id,
                "count": count,
                "created_at": created_at,
                "records": records,
            }

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
