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
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from . import envelope
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


def idempotency_conflict() -> LedgerError:
    return LedgerError(409, "IDEMPOTENCY_CONFLICT")


# Stored-shape limits mirrored from the sealed-write ingress. A batch read
# re-validates every row against these before returning it, so a batch made
# unreadable by offline tampering with types or lengths is reported as an
# integrity failure instead of echoing malformed storage.
ENCRYPTED_ALGORITHM_NONCE = 12
ENCRYPTED_ALGORITHM_TAG = 16
ENCRYPTED_ALGORITHMS = {
    "AES-256-GCM": 32 + ENCRYPTED_ALGORITHM_TAG,
    "AES-128-GCM": 16 + ENCRYPTED_ALGORITHM_TAG,
}
MAX_ENCRYPTED_BYTES = 1048576
MAX_ENCRYPTION_KEY_ID = 128
MAX_METADATA_BYTES = 16384
MAX_ENCRYPTED_BATCH_SIZE = 100
ENCRYPTED_RECORD_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
ENCRYPTED_BATCH_ID = re.compile(r"batch_[0-9a-f]{32}\Z")

# Namespacing the opaque cursors keeps a cursor minted by one listing endpoint
# from replaying on the other even though they share one HMAC key.
RECORD_LIST_CURSOR_NAMESPACE = "records"
BATCH_LIST_CURSOR_NAMESPACE = "encrypted-batches"
EVENT_LIST_CURSOR_NAMESPACE = "encrypted-record-events"

# Append-event sequences are signed 64-bit integers; after_seq/high_water
# cursors never carry a value outside this range.
MAX_EVENT_SEQ = 9_223_372_036_854_775_807


def _json_semantic_equal(left: object, right: object) -> bool:
    """Compare parsed JSON data by value, not by surface spelling.

    Object key order and document whitespace never reach this function (both
    sides are parsed), arrays keep their order, and numbers compare by numeric
    value so ``1`` and ``1.0`` are equal. Booleans are a distinct JSON type and
    are deliberately not equal to numbers despite Python treating ``bool`` as
    ``int``.
    """
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_semantic_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_semantic_equal(a, b) for a, b in zip(left, right)
        )
    # Strings, null and any remaining type mismatch compare directly; the
    # numeric branch above already prevents cross-type numeric equality.
    return left == right


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


@dataclass(frozen=True)
class EncryptedBatchReplay:
    """Outcome of a request whose idempotency key is already bound.

    The batch was committed by an earlier request; ``record_ids`` follow that
    batch's stored positions, i.e. exactly the first response's result order.
    """

    batch_id: str
    record_ids: list[str]


class Ledger:
    def __init__(self, config: Config):
        initialize(config.database, config.active_version)
        self._keys = dict(config.keys)
        self._connection = connect(config.database)
        self._lock = threading.RLock()
        self._cursor_secret = self._load_or_create_cursor_secret()
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

    def _load_or_create_cursor_secret(self) -> bytes:
        """Return the persistent HMAC key for opaque list cursors.

        The record listing keeps cursors in memory and tolerates them dying
        with the process; the encrypted-batch listing promises cursors that
        stay valid across a normal restart. One shared 32-byte secret stored in
        service_metadata backs both: an existing value is always reused (and a
        database lacking it is upgraded once), so restarting never changes a
        minted digest or invalidates a cursor. It is independent of the keyring,
        so rotating record keys leaves it untouched.
        """
        try:
            row = self._connection.execute(
                "SELECT value FROM service_metadata WHERE name='cursor_secret'"
            ).fetchone()
            if row is not None:
                secret = binascii.unhexlify(row[0])
                if len(secret) == 32:
                    return secret
            secret = os.urandom(32)
            with self._connection:
                self._connection.execute(
                    "INSERT OR IGNORE INTO service_metadata(name, value) VALUES (?, ?)",
                    ("cursor_secret", secret.hex()),
                )
            row = self._connection.execute(
                "SELECT value FROM service_metadata WHERE name='cursor_secret'"
            ).fetchone()
            secret = binascii.unhexlify(row[0])
        except (sqlite3.Error, ValueError, TypeError, binascii.Error):
            # Persisting the HMAC key is an availability optimization; a
            # storage problem here must not stop the service from starting.
            secret = os.urandom(32)
        return secret

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
                token_hex, offset = self._parse_cursor(
                    RECORD_LIST_CURSOR_NAMESPACE, cursor
                )
                snapshot = self._snapshots.get(token_hex)
                if snapshot is None or snapshot.tenant != tenant:
                    raise invalid_request()
                if not 0 <= offset <= len(snapshot.record_ids):
                    raise invalid_request()

            end = offset + limit
            page = list(snapshot.record_ids[offset:end])
            next_cursor = (
                self._issue_cursor(
                    RECORD_LIST_CURSOR_NAMESPACE, token_hex, end, tenant
                )
                if end < len(snapshot.record_ids)
                else None
            )
            return page, next_cursor

    def _issue_cursor(
        self, namespace: str, token: str, offset: int, tenant: str
    ) -> str:
        return self._issue_cursor_payload(
            namespace, {"t": token, "o": offset, "n": tenant}
        )

    def _parse_cursor(self, namespace: str, cursor: str) -> tuple[str, int]:
        payload = self._parse_cursor_payload(namespace, cursor)
        try:
            token_hex = payload["t"]
            offset = payload["o"]
            cursor_tenant = payload["n"]
        except (KeyError, TypeError):
            raise invalid_request() from None
        if (
            not isinstance(token_hex, str)
            or not isinstance(cursor_tenant, str)
            or type(offset) is not int
            or len(token_hex) not in (32, 36)
            or not all(char in "0123456789abcdef" for char in token_hex)
        ):
            raise invalid_request()
        return token_hex, offset

    def _issue_cursor_payload(self, namespace: str, payload: dict) -> str:
        body = base64.urlsafe_b64encode(
            json.dumps(
                {"ns": namespace, **payload},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        # Omit base64 padding ("=") so the opaque cursor carries safely in a
        # query string without percent-encoding; padding is restored on parse.
        encoded_body = body.rstrip(b"=")
        tag = hmac.new(self._cursor_secret, encoded_body, hashlib.sha256).digest()
        encoded_tag = base64.urlsafe_b64encode(tag).rstrip(b"=")
        return (encoded_body + b"." + encoded_tag).decode("ascii")

    def _parse_cursor_payload(self, namespace: str, cursor: str) -> dict:
        try:
            body, encoded_tag = cursor.encode("ascii").split(b".", 1)
            tag = base64.urlsafe_b64decode(encoded_tag + b"=" * (-len(encoded_tag) % 4))
            expected = hmac.new(self._cursor_secret, body, hashlib.sha256).digest()
            if len(tag) != 32 or not hmac.compare_digest(tag, expected):
                raise invalid_request()
            decoded_body = base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4))
            payload = json.loads(decoded_body)
        except (
            UnicodeEncodeError,
            ValueError,
            TypeError,
            binascii.Error,
        ):
            raise invalid_request() from None
        if not isinstance(payload, dict) or payload.get("ns") != namespace:
            raise invalid_request()
        return payload

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
        self, tenant: str, entries: list[EncryptedEntry], idempotency_key: str | None = None
    ) -> tuple[str, list[str], bool]:
        """Atomically commit one tenant's batch of pre-sealed records.

        The caller has already validated shape, types, supported algorithm and
        cross-field consistency. This method is the authoritative conflict and
        commit boundary: it re-derives in-batch duplicate ids (INVALID_BATCH),
        then, when an idempotency key is supplied, resolves the idempotency
        association before the existing-id check. It writes the batch row,
        every record, an append-only event per record and -- when keyed -- the
        idempotency binding in a single transaction. Any constraint violation,
        ledger-append failure or storage error rolls the whole transaction
        back, leaving prior records and associations untouched and leaving a
        new key unbound (BATCH_WRITE_FAILED).

        Returns (batch_id, ids_in_input_order, replayed). A first success
        returns replayed=False (HTTP 201); a same-tenant/same-key/same-content
        retry resolves the existing binding and returns replayed=True with the
        first batch id and its stored id order (HTTP 200), writing nothing. A
        key already bound to a different batch payload raises
        IDEMPOTENCY_CONFLICT (409); a binding whose batch is missing,
        cross-tenant or fails the whole-batch integrity review raises 422.

        Runs under the process-wide lock, which makes key resolution and
        concurrent same-key commits serial: exactly one request commits (201),
        same-content concurrent requests replay it (200) and different-content
        ones get 409.
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

            if idempotency_key is not None:
                replay = self._resolve_idempotent_binding(
                    tenant, idempotency_key, entries
                )
                if replay is not None:
                    return replay.batch_id, replay.record_ids, True

            try:
                rows = self._connection.execute(
                    "SELECT id FROM encrypted_records WHERE tenant=? AND id IN (%s)"
                    % ",".join("?" * len(record_ids)),
                    (tenant, *record_ids),
                ).fetchall()
            except sqlite3.Error:
                raise batch_write_failed() from None
            if rows:
                # A new key that hits an existing id is rejected exactly as the
                # keyless path and never becomes bound to the key.
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
                    if idempotency_key is not None:
                        # Committed atomically with the batch: a failure here
                        # rolls the batch, records and events back too, so a
                        # key is observable only alongside its full batch.
                        self._connection.execute(
                            "INSERT INTO encrypted_batch_idempotency_keys "
                            "(tenant, idempotency_key, batch_id, created_at) "
                            "VALUES (?, ?, ?, ?)",
                            (tenant, idempotency_key, batch_id, created_at),
                        )
            except sqlite3.Error:
                # PRIMARY KEY/UNIQUE violations (a same-key or same-ids commit
                # winning the race after the pre-check) and any ledger-append
                # or storage failure all roll the transaction back; neither
                # the batch nor a key binding is observable.
                raise batch_write_failed() from None
            return batch_id, record_ids, False

    def _resolve_idempotent_binding(
        self, tenant: str, idempotency_key: str, entries: list[EncryptedEntry]
    ) -> EncryptedBatchReplay | None:
        """Return the replay for a bound key, None for an unbound key.

        Raises 500 BATCH_WRITE_FAILED on any SQLite error of the idempotency
        lookup/replay reads, 422 when a bound batch is missing, misbound to
        another tenant or fails the existing whole-batch integrity review, and
        409 IDEMPOTENCY_CONFLICT when the bound batch holds different content.
        """
        try:
            binding = self._connection.execute(
                "SELECT tenant, idempotency_key, batch_id, created_at "
                "FROM encrypted_batch_idempotency_keys "
                "WHERE tenant=? AND idempotency_key=?",
                (tenant, idempotency_key),
            ).fetchone()
        except sqlite3.Error:
            raise batch_write_failed() from None
        if binding is None:
            return None

        batch_id = binding["batch_id"]
        try:
            batch = self._connection.execute(
                "SELECT batch_id, tenant, record_count, created_at "
                "FROM encrypted_batches WHERE batch_id=?",
                (batch_id,),
            ).fetchone()
            if batch is None or batch["tenant"] != tenant:
                # Missing batch or a binding repointed at another tenant's
                # batch is an integrity failure, not a conflict.
                raise integrity()
            record_rows = self._connection.execute(
                "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                "FROM encrypted_records WHERE batch_id=? ORDER BY position ASC",
                (batch_id,),
            ).fetchall()
            event_rows = self._connection.execute(
                "SELECT batch_id, tenant, record_id, position "
                "FROM encrypted_record_events WHERE batch_id=? ORDER BY seq ASC",
                (batch_id,),
            ).fetchall()
        except LedgerError:
            raise
        except sqlite3.Error:
            raise batch_write_failed() from None

        # Same cross-table / stored-shape review as the batch read endpoint.
        self._validate_encrypted_batch(batch, record_rows, event_rows)

        if not self._entries_match_bound_batch(entries, record_rows):
            raise idempotency_conflict()

        return EncryptedBatchReplay(batch_id, [row["id"] for row in record_rows])

    def read_idempotency_receipt(self, tenant: str, idempotency_key: str) -> dict:
        """Return the write receipt previously bound to one idempotency key.

        Allows a client to confirm a sealed-batch write by its key alone,
        without resubmitting ciphertext. The caller has already settled the
        403/400 precedence (tenant, then key shape).

        Resolution is deliberately staged, mirroring the cross-batch sealed
        read:

        1. Read this tenant's binding. A SQLite failure is 503; no row for
           ``(tenant, key)`` is 404 -- another tenant binding the same key
           name is invisible and stays a 404. Keyless legacy batches never
           have a binding row.
        2. The bound batch id itself must be a legal ``batch_`` id; then the
           batch row is read (503 on SQLite failure). A missing or
           foreign-tenant batch, a binding ``created_at`` that is not a string
           or differs from the batch row's verbatim value are 422.
        3. Only once every read has succeeded are the batch, every record and
           every append event reviewed with the same whole-batch validation as
           the by-batch read (count, positions, tenant/id correspondence,
           stored field shapes); any drift is 422. Corruption in an unrelated
           batch is never loaded.

        The receipt is {"batch_id", "count", "results", "created_at"}: the
        first three match the key's first successful write response exactly
        (results in stored submission order, each ``{"id", "status":
        "created"}``) and ``created_at`` is the batch's stored string. Read-only
        -- no binding, batch, record or event is added, changed or repaired,
        and envelopes are never opened. Runs under the process-wide lock, so a
        same-key commit in flight is observed only as unbound (404) or as the
        complete committed receipt, never a partial one; a rolled-back failed
        commit leaves the key unbound and an idempotent replay changes
        nothing.
        """
        with self._lock:
            try:
                binding = self._connection.execute(
                    "SELECT tenant, idempotency_key, batch_id, created_at "
                    "FROM encrypted_batch_idempotency_keys "
                    "WHERE tenant=? AND idempotency_key=?",
                    (tenant, idempotency_key),
                ).fetchone()
            except sqlite3.Error:
                raise storage() from None
            # Scoped by tenant in the WHERE clause: a same-named key bound by
            # another tenant is indistinguishable from an unbound key.
            if binding is None:
                raise not_found()

            batch_id = binding["batch_id"]
            # The associated id comes from stored rows rather than a
            # path-validated URL, so its type/shape are themselves part of the
            # review (a non-string or malformed link is integrity drift).
            if not isinstance(batch_id, str) or ENCRYPTED_BATCH_ID.fullmatch(batch_id) is None:
                raise integrity()

            try:
                batch = self._connection.execute(
                    "SELECT batch_id, tenant, record_count, created_at "
                    "FROM encrypted_batches WHERE batch_id=?",
                    (batch_id,),
                ).fetchone()
            except sqlite3.Error:
                raise storage() from None
            if batch is None or batch["tenant"] != tenant:
                # Missing batch or a binding repointed at another tenant's
                # batch is an integrity failure, not a missing binding.
                raise integrity()

            binding_created_at = binding["created_at"]
            # The binding was written in the same transaction as the batch with
            # the identical created_at string; a non-string or drifted value is
            # corruption, reported only after the batch read itself succeeded.
            if not isinstance(binding_created_at, str) or binding_created_at != batch["created_at"]:
                raise integrity()

            try:
                record_rows = self._connection.execute(
                    "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                    "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                    "FROM encrypted_records WHERE batch_id=? ORDER BY position ASC",
                    (batch_id,),
                ).fetchall()
                event_rows = self._connection.execute(
                    "SELECT batch_id, tenant, record_id, position "
                    "FROM encrypted_record_events WHERE batch_id=? ORDER BY seq ASC",
                    (batch_id,),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None

            # All required reads succeeded; only now may stored-state drift be
            # judged: the exact whole-batch review used by the batch read and
            # the idempotent replay path.
            self._validate_encrypted_batch(batch, record_rows, event_rows)

            return {
                "batch_id": batch["batch_id"],
                "count": len(record_rows),
                "results": [
                    {"id": row["id"], "status": "created"} for row in record_rows
                ],
                "created_at": batch["created_at"],
            }

    def _entries_match_bound_batch(
        self, entries: list[EncryptedEntry], record_rows
    ) -> bool:
        """Semantic equality of the request with the actually stored fields.

        Record count and order participate, bytes are compared by their
        decoded values (so base64 spelling cannot matter), and metadata is
        compared as JSON data: object key order and whitespace are ignored,
        numbers compare by numeric value, but booleans are never equal to
        numbers. Only stored fields take part, so request-only/ignored fields
        cannot influence the verdict.
        """
        if len(entries) != len(record_rows):
            return False
        for entry, row in zip(entries, record_rows):
            if entry.record_id != row["id"]:
                return False
            if entry.algorithm != row["algorithm"]:
                return False
            if entry.encryption_key_id != row["encryption_key_id"]:
                return False
            if entry.envelope_nonce != bytes(row["envelope_nonce"]):
                return False
            if entry.wrapped_key != bytes(row["wrapped_key"]):
                return False
            if entry.ciphertext != bytes(row["ciphertext"]):
                return False
            if entry.ciphertext_nonce != bytes(row["ciphertext_nonce"]):
                return False
            if entry.tag != bytes(row["tag"]):
                return False
            try:
                stored_metadata = (
                    json.loads(row["metadata"]) if row["metadata"] is not None else None
                )
                request_metadata = (
                    json.loads(entry.metadata) if entry.metadata is not None else None
                )
            except (ValueError, RecursionError, TypeError):
                # The stored document was already verified to parse during the
                # integrity review; a failure here is a mismatch.
                return False
            if not _json_semantic_equal(request_metadata, stored_metadata):
                return False
        return True

    def read_encrypted_batch(self, tenant: str, batch_id: str) -> dict:
        """Return one client-sealed batch in submission order.

        Existence and ownership are a single decision: a batch that is missing
        or belongs to another tenant is 404 without any of its details being
        inspected. Once the batch is known to belong to the caller, every
        batch/record/event relationship and every stored shape is re-validated
        before anything is returned: counts must agree, positions must cover
        exactly 0..count-1 on both sides, and tenants/record ids/positions must
        correspond one by one. Any missing, extra, duplicate, misplaced or
        cross-tenant association -- like a corrupted metadata JSON document or
        a stored field of the wrong type or length -- is 422.

        Envelopes are never opened and ciphertext authentication is never
        evaluated: equal-length ciphertext changes are stored and returned
        verbatim. Read-only; runs under the process-wide lock, so it observes
        one complete serial state and never the half-written rows of an
        uncommitted batch.
        """
        with self._lock:
            try:
                batch = self._connection.execute(
                    "SELECT batch_id, tenant, record_count, created_at "
                    "FROM encrypted_batches WHERE batch_id=?",
                    (batch_id,),
                ).fetchone()
            except sqlite3.Error:
                raise storage() from None
            # Lookup is by batch id alone; a foreign tenant gets the same
            # indistinguishable 404 as a missing batch and no detail check.
            if batch is None or batch["tenant"] != tenant:
                raise not_found()

            try:
                record_rows = self._connection.execute(
                    "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                    "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                    "FROM encrypted_records WHERE batch_id=? ORDER BY position ASC",
                    (batch_id,),
                ).fetchall()
                event_rows = self._connection.execute(
                    "SELECT batch_id, tenant, record_id, position "
                    "FROM encrypted_record_events WHERE batch_id=? ORDER BY seq ASC",
                    (batch_id,),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None

            self._validate_encrypted_batch(batch, record_rows, event_rows)

            records = [self._shape_encrypted_record(row) for row in record_rows]
            return {
                "batch_id": batch["batch_id"],
                "count": len(records),
                "created_at": batch["created_at"],
                "records": records,
            }

    def _shape_encrypted_record(self, row) -> dict:
        """Project one validated sealed-record row to the read response shape.

        The row has already passed :meth:`_validate_encrypted_record`, so the
        metadata document is known to parse to an object (or be null). Bytes
        are standard padded base64; the empty ciphertext stays an empty string.
        """
        metadata = None
        if row["metadata"] is not None:
            # The JSON document was validated for shape on write and again on
            # read; a document that no longer parses to an object is corruption.
            metadata = json.loads(row["metadata"])
        return {
            "id": row["id"],
            "algorithm": row["algorithm"],
            "key_id": row["encryption_key_id"],
            "envelope": {
                "nonce": base64.b64encode(bytes(row["envelope_nonce"])).decode("ascii"),
                "wrapped_key": base64.b64encode(bytes(row["wrapped_key"])).decode("ascii"),
            },
            "ciphertext": {
                "data": base64.b64encode(bytes(row["ciphertext"])).decode("ascii"),
                "nonce": base64.b64encode(bytes(row["ciphertext_nonce"])).decode("ascii"),
                "tag": base64.b64encode(bytes(row["tag"])).decode("ascii"),
            },
            "metadata": metadata,
        }

    def read_encrypted_records_batch(self, tenant: str, record_ids: list[str]) -> list[dict]:
        """Fetch several sealed records of one tenant by id, across batches.

        The caller has already validated the id list shape. Resolution is
        deliberately staged so the error precedence never depends on stored
        detail:

        1. One existence query over *this tenant's* sealed rows. A SQLite
           failure is 503; if any requested id is absent -- because it does
           not exist, belongs to another tenant, or is only a plaintext
           ``records`` row -- the whole request is 404 before any batch is
           inspected, so a missing id paired with a damaged batch still 404s.
        2. Only once every id is known to exist are the complete batch rows,
           every record and every append event of the *involved* batches read;
           any SQLite failure here is 503.
        3. Only after all data is fetched is each involved batch reviewed with
           the same whole-batch validation as the by-batch read: count,
           positions, tenant/event correspondence and stored field shapes --
           including records of the same batch that were not requested. A
           record whose associated batch is missing, owned by another tenant or
           carries an illegal batch id fails the review with 422. An unrelated
           batch is never loaded and cannot affect the result.

        Items are returned in request order, each carrying its ``batch_id`` and
        that batch's verbatim ``created_at``. Envelopes are never opened.
        Read-only; runs under the process-wide lock, so it observes one complete
        serial state and never a half-committed batch.
        """
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT id, batch_id FROM encrypted_records "
                    "WHERE tenant=? AND id IN (%s)" % ",".join("?" * len(record_ids)),
                    (tenant, *record_ids),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None
            by_id = {row["id"]: row for row in rows}
            # Other tenants' same-named rows and plaintext records are excluded
            # by the tenant-scoped query against encrypted_records alone.
            if any(record_id not in by_id for record_id in record_ids):
                raise not_found()

            # Preserve first-appearance order purely for a deterministic review;
            # every involved batch is reviewed regardless of order.
            batch_ids: list[str] = []
            seen_batches: set[str] = set()
            for record_id in record_ids:
                associated_batch = by_id[record_id]["batch_id"]
                if associated_batch not in seen_batches:
                    seen_batches.add(associated_batch)
                    batch_ids.append(associated_batch)

            placeholders = ",".join("?" * len(batch_ids))
            try:
                batch_rows = self._connection.execute(
                    "SELECT batch_id, tenant, record_count, created_at "
                    "FROM encrypted_batches WHERE batch_id IN (%s)" % placeholders,
                    batch_ids,
                ).fetchall()
                record_rows = self._connection.execute(
                    "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                    "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                    "FROM encrypted_records WHERE batch_id IN (%s) ORDER BY position ASC"
                    % placeholders,
                    batch_ids,
                ).fetchall()
                event_rows = self._connection.execute(
                    "SELECT batch_id, tenant, record_id, position "
                    "FROM encrypted_record_events WHERE batch_id IN (%s) ORDER BY seq ASC"
                    % placeholders,
                    batch_ids,
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None

            batches_by_id = {row["batch_id"]: row for row in batch_rows}
            records_by_batch: dict[str, list] = {}
            events_by_batch: dict[str, list] = {}
            for row in record_rows:
                records_by_batch.setdefault(row["batch_id"], []).append(row)
            for event in event_rows:
                events_by_batch.setdefault(event["batch_id"], []).append(event)

            # Review every involved batch as a whole before shaping anything.
            for batch_id in batch_ids:
                # The associated batch id comes from stored rows, not a
                # path-validated URL, so its shape is itself part of the
                # review (a non-string or malformed link is integrity drift).
                if (
                    not isinstance(batch_id, str)
                    or ENCRYPTED_BATCH_ID.fullmatch(batch_id) is None
                ):
                    raise integrity()
                batch = batches_by_id.get(batch_id)
                # A dangling association (the batch row is missing) is a
                # relationship failure, not the 404 above (all ids existed).
                if batch is None or batch["tenant"] != tenant:
                    raise integrity()
                self._validate_encrypted_batch(
                    batch,
                    records_by_batch.get(batch_id, []),
                    events_by_batch.get(batch_id, []),
                )

            record_index = {
                (row["batch_id"], row["id"]): row for row in record_rows
            }
            items: list[dict] = []
            for record_id in record_ids:
                batch_id = by_id[record_id]["batch_id"]
                batch = batches_by_id[batch_id]
                item = self._shape_encrypted_record(record_index[(batch_id, record_id)])
                item["batch_id"] = batch["batch_id"]
                item["created_at"] = batch["created_at"]
                items.append(item)
            return items

    def _validate_encrypted_batch(self, batch, record_rows, event_rows) -> None:
        """Cross-check batch, records and append events; raise 422 on any drift."""
        count = batch["record_count"]
        if type(count) is not int or not 1 <= count <= MAX_ENCRYPTED_BATCH_SIZE:
            raise integrity()
        if not isinstance(batch["tenant"], str) or not isinstance(batch["batch_id"], str):
            raise integrity()
        if not isinstance(batch["created_at"], str):
            raise integrity()
        if len(record_rows) != count or len(event_rows) != count:
            raise integrity()

        expected_positions = set(range(count))
        records_by_position: dict[int, object] = {}
        for row in record_rows:
            position = row["position"]
            if type(position) is not int or position not in expected_positions:
                raise integrity()
            if position in records_by_position:
                raise integrity()
            records_by_position[position] = row
            if row["tenant"] != batch["tenant"] or row["batch_id"] != batch["batch_id"]:
                raise integrity()
            self._validate_encrypted_record(row)
        if set(records_by_position) != expected_positions:
            raise integrity()

        events_by_position: dict[int, object] = {}
        for event in event_rows:
            position = event["position"]
            if type(position) is not int or position not in expected_positions:
                raise integrity()
            if position in events_by_position:
                raise integrity()
            events_by_position[position] = event
            if event["batch_id"] != batch["batch_id"] or event["tenant"] != batch["tenant"]:
                raise integrity()
        if set(events_by_position) != expected_positions:
            raise integrity()

        for position in range(count):
            row = records_by_position[position]
            event = events_by_position[position]
            if event["record_id"] != row["id"]:
                raise integrity()

    def _validate_encrypted_record(self, row) -> None:
        """Re-check one stored sealed record against the write-time shape."""
        if not isinstance(row["id"], str) or ENCRYPTED_RECORD_ID.fullmatch(row["id"]) is None:
            raise integrity()
        wrapped_len = ENCRYPTED_ALGORITHMS.get(row["algorithm"]) if isinstance(
            row["algorithm"], str
        ) else None
        if wrapped_len is None:
            raise integrity()
        key_id = row["encryption_key_id"]
        if key_id is not None and (
            not isinstance(key_id, str) or not 1 <= len(key_id) <= MAX_ENCRYPTION_KEY_ID
        ):
            raise integrity()
        blob_fields = (
            ("envelope_nonce", ENCRYPTED_ALGORITHM_NONCE, ENCRYPTED_ALGORITHM_NONCE),
            ("wrapped_key", wrapped_len, wrapped_len),
            ("ciphertext", 0, MAX_ENCRYPTED_BYTES),
            ("ciphertext_nonce", ENCRYPTED_ALGORITHM_NONCE, ENCRYPTED_ALGORITHM_NONCE),
            ("tag", ENCRYPTED_ALGORITHM_TAG, ENCRYPTED_ALGORITHM_TAG),
        )
        for name, minimum, maximum in blob_fields:
            value = row[name]
            if not isinstance(value, bytes) or not minimum <= len(value) <= maximum:
                raise integrity()
        metadata = row["metadata"]
        if metadata is not None:
            if not isinstance(metadata, str) or len(metadata.encode("utf-8")) > MAX_METADATA_BYTES:
                raise integrity()
            try:
                parsed = json.loads(metadata)
            except (ValueError, RecursionError):
                raise integrity() from None
            if not isinstance(parsed, dict):
                raise integrity()

    def list_encrypted_batches(
        self, tenant: str, limit: int, cursor: str | None
    ) -> tuple[list[dict], str | None]:
        """List a tenant's sealed-batch summaries from one frozen state.

        A request without a cursor captures the tenant's current batches in
        ascending batch_id order; the summary tuples are frozen into a snapshot
        row set committed in a single transaction (once more than one page is
        possible). Later pages addressed by the returned opaque cursor serve
        only that frozen set, so concurrent commits neither duplicate nor drop
        entries and batches committed afterwards stay invisible until a fresh
        cursorless listing. Snapshots persist, so a cursor survives a normal
        restart and is unaffected by key rotation.

        Only the summary shape (batch_id/count/created_at) is reviewed here;
        the per-batch records and append events remain the exclusive concern of
        the whole-batch read. Read-only with respect to the protocol tables: it
        adds no batches, records, events or idempotency bindings.
        Returns (items, next_cursor_or_None).
        """
        with self._lock:
            if cursor is None:
                try:
                    rows = self._connection.execute(
                        "SELECT batch_id, record_count, created_at "
                        "FROM encrypted_batches WHERE tenant=? ORDER BY batch_id ASC",
                        (tenant,),
                    ).fetchall()
                except sqlite3.Error:
                    raise storage() from None
                summaries = [
                    (row["batch_id"], row["record_count"], row["created_at"]) for row in rows
                ]
                total = len(summaries)
                offset = 0
                snapshot_id = os.urandom(16).hex()
                # Review the page being returned before any snapshot state is
                # written, so a 422 on the first page leaves no state behind.
                page_summaries = summaries[:limit]
                items = [self._batch_summary(*summary) for summary in page_summaries]
                # As with record listings, a one-page answer hands out no
                # cursor and therefore needs no retained snapshot.
                if total > limit:
                    try:
                        with self._connection:
                            self._connection.execute(
                                "INSERT INTO encrypted_batch_list_snapshots "
                                "(snapshot_id, tenant, total, created_at) "
                                "VALUES (?, ?, ?, ?)",
                                (
                                    snapshot_id,
                                    tenant,
                                    total,
                                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                ),
                            )
                            self._connection.executemany(
                                "INSERT INTO encrypted_batch_list_snapshot_items "
                                "(snapshot_id, position, summary) VALUES (?, ?, ?)",
                                [
                                    (
                                        snapshot_id,
                                        position,
                                        self._freeze_batch_summary(
                                            batch_id, count, created_at
                                        ),
                                    )
                                    for position, (
                                        batch_id,
                                        count,
                                        created_at,
                                    ) in enumerate(summaries)
                                ],
                            )
                    except sqlite3.Error:
                        raise storage() from None
                # A malformed later batch is frozen untouched and only
                # surfaces when its own page is served.
            else:
                snapshot_id, offset = self._parse_cursor(
                    BATCH_LIST_CURSOR_NAMESPACE, cursor
                )
                try:
                    snapshot = self._connection.execute(
                        "SELECT tenant, total FROM encrypted_batch_list_snapshots "
                        "WHERE snapshot_id=?",
                        (snapshot_id,),
                    ).fetchone()
                except sqlite3.Error:
                    raise storage() from None
                # Unknown snapshot (e.g. pruned or never minted) and a snapshot
                # bound to another tenant are indistinguishable bad cursors.
                if snapshot is None or snapshot["tenant"] != tenant:
                    raise invalid_request()
                total = snapshot["total"]
                if type(total) is not int or total < 1:
                    raise integrity()
                try:
                    actual_total = self._connection.execute(
                        "SELECT COUNT(*) FROM encrypted_batch_list_snapshot_items "
                        "WHERE snapshot_id=?",
                        (snapshot_id,),
                    ).fetchone()[0]
                    rows = self._connection.execute(
                        "SELECT position, summary "
                        "FROM encrypted_batch_list_snapshot_items "
                        "WHERE snapshot_id=? AND position>=? ORDER BY position ASC LIMIT ?",
                        (snapshot_id, offset, limit),
                    ).fetchall()
                except sqlite3.Error:
                    raise storage() from None
                if not 0 <= offset <= total:
                    raise invalid_request()
                # The frozen item count is recorded on the header; missing or
                # extra offline rows are integrity drift, never a silent gap.
                if actual_total != total:
                    raise integrity()
                expected_count = min(limit, total - offset)
                if len(rows) != expected_count:
                    raise integrity()
                page_summaries = []
                for index, row in enumerate(rows):
                    if row["position"] != offset + index:
                        # Frozen positions must be contiguous from offset.
                        raise integrity()
                    try:
                        summary = json.loads(row["summary"])
                        batch_id, count, created_at = self._thaw_batch_summary(summary)
                    except (LedgerError, ValueError, TypeError):
                        # Corrupt frozen summary on the page being served.
                        raise integrity() from None
                    page_summaries.append(
                        (batch_id, count, created_at)
                    )
                items = [self._batch_summary(*summary) for summary in page_summaries]

            end = offset + limit
            next_cursor = (
                self._issue_cursor(BATCH_LIST_CURSOR_NAMESPACE, snapshot_id, end, tenant)
                if end < total
                else None
            )
            return items, next_cursor

    def _batch_summary(self, batch_id: object, count: object, created_at: object) -> dict:
        """Validate one stored summary tuple; raise 422 on any shape drift."""
        if (
            not isinstance(batch_id, str)
            or ENCRYPTED_BATCH_ID.fullmatch(batch_id) is None
            or type(count) is not int
            or not 1 <= count <= MAX_ENCRYPTED_BATCH_SIZE
            or not isinstance(created_at, str)
        ):
            raise integrity()
        return {"batch_id": batch_id, "count": count, "created_at": created_at}

    def _freeze_batch_summary(
        self, batch_id: object, count: object, created_at: object
    ) -> str:
        """Type-tag one stored summary tuple as compact JSON.

        Freezing preserves the *exact* stored types across SQLite's type
        affinity -- notably a non-string BLOB in a TEXT-affinity column -- so a
        later page can still raise 422 on it. A value whose type cannot appear
        in a column declared here is encoded as an explicit marker rather than
        raising, keeping snapshot creation from failing on a malformed page the
        caller never requests.
        """
        def encode(value: object) -> object:
            if value is None or isinstance(value, (str, int, float, bool)):
                return value
            if isinstance(value, bytes):
                return {"__blob__": base64.b64encode(value).decode("ascii")}
            return {"__invalid__": True}

        return json.dumps(
            [encode(batch_id), encode(count), encode(created_at)],
            separators=(",", ":"),
        )

    def _thaw_batch_summary(self, summary: object) -> tuple[object, object, object]:
        """Reverse :meth:`_freeze_batch_summary`; 422 on an unreadable marker."""
        if not isinstance(summary, list) or len(summary) != 3:
            raise integrity()

        def decode(value: object) -> object:
            if isinstance(value, dict) and set(value) == {"__blob__"}:
                encoded = value["__blob__"]
                if not isinstance(encoded, str):
                    raise integrity()
                try:
                    return base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError):
                    raise integrity() from None
            if isinstance(value, dict) and value.get("__invalid__") is True:
                # An original type that could not be represented; validation
                # below rejects it (it is not str/int).
                return object()
            return value

        return decode(summary[0]), decode(summary[1]), decode(summary[2])

    # -- append-event listing ----------------------------------------------

    def list_encrypted_record_events(
        self,
        tenant: str,
        limit: int,
        after_seq: int | None = None,
        cursor: str | None = None,
    ) -> tuple[list[dict], int, str | None]:
        """Incrementally list this tenant's append events from one serial point.

        A request without a cursor fixes one complete serial instant: the water
        is ``max(after_seq, this tenant's largest committed seq)`` -- an empty
        tenant has largest seq 0 -- and only events with
        ``after_seq < seq <= water`` are ever served by this query chain.
        Batches committed afterwards stay invisible until the caller starts a
        fresh cursorless query using the returned ``high_water`` as its new
        ``after_seq``. Sequence gaps are legitimate; the ordinary
        server-encrypted ``records`` table and other tenants' events never
        appear.

        A continuation cursor freezes (tenant, after_seq, water); a later page
        may use a different ``limit`` and replays deterministically, including
        across a normal restart -- the cursor carries no server-side snapshot
        state, only HMAC-signed integers. Key rotation does not touch these
        tables and cannot change the result.

        As on the cross-batch record read, every batch touched by the served
        page is loaded whole (batch row, every record, every event) and passes
        the same whole-batch consistency and stored-shape review before the
        page is returned; a missing, malformed or foreign associated batch is
        422. Corruption in a batch the page does not touch is irrelevant.

        Read-only: no batch, record, event or idempotency binding is added or
        changed. Returns (items, high_water, next_cursor_or_None); each item is
        {"seq", "batch_id", "id", "position", "created_at"} in ascending seq,
        and no ciphertext or envelope material is included.
        """
        with self._lock:
            if cursor is None:
                # One serial instant: the maximum read and the page reads all
                # run under the process-wide lock, so no commit can interleave.
                try:
                    max_row = self._connection.execute(
                        "SELECT MAX(seq) FROM encrypted_record_events WHERE tenant=?",
                        (tenant,),
                    ).fetchone()
                except sqlite3.Error:
                    raise storage() from None
                current_max = max_row[0]
                if current_max is None:
                    current_max = 0
                elif type(current_max) is not int or current_max < 0:
                    raise integrity()
                start = after_seq
                water = max(start, current_max)
            else:
                start, water = self._parse_event_cursor(tenant, cursor)

            if not 0 <= start <= water <= MAX_EVENT_SEQ:
                # A well-signed cursor whose bounds drifted out of range is
                # stored-state corruption rather than a forged cursor.
                raise integrity()

            try:
                # Fetch one extra row solely to learn whether another page
                # exists. This also terminates the chain when the caller asked
                # past the current tip (water pinned by after_seq): an empty
                # remainder is a final page, never an endless run of empty
                # pages whose cursor chases the water.
                fetched = self._connection.execute(
                    "SELECT seq, batch_id, tenant, record_id, position "
                    "FROM encrypted_record_events "
                    "WHERE tenant=? AND seq>? AND seq<=? "
                    "ORDER BY seq ASC LIMIT ?",
                    (tenant, start, water, limit + 1),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None
            has_more = len(fetched) > limit
            event_rows = fetched[:limit]

            # Identify every batch touched by this page (first-touch order).
            # The associated ids come from stored rows and are themselves
            # reviewed only after every read has succeeded.
            batch_ids: list[str] = []
            seen_batches: set[str] = set()
            for event in event_rows:
                if event["batch_id"] not in seen_batches:
                    seen_batches.add(event["batch_id"])
                    batch_ids.append(event["batch_id"])

            # Read phase: the batch rows, every record and every append event
            # of the involved batches are all fetched before any shape is
            # reviewed, so a SQLite failure always surfaces as 503 rather than
            # as a 422 built on partially read storage.
            if batch_ids:
                placeholders = ",".join("?" * len(batch_ids))
                try:
                    batch_rows = self._connection.execute(
                        "SELECT batch_id, tenant, record_count, created_at "
                        "FROM encrypted_batches WHERE batch_id IN (%s)" % placeholders,
                        batch_ids,
                    ).fetchall()
                    record_rows = self._connection.execute(
                        "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                        "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                        "FROM encrypted_records WHERE batch_id IN (%s) ORDER BY position ASC"
                        % placeholders,
                        batch_ids,
                    ).fetchall()
                    all_event_rows = self._connection.execute(
                        "SELECT batch_id, tenant, record_id, position "
                        "FROM encrypted_record_events WHERE batch_id IN (%s) ORDER BY seq ASC"
                        % placeholders,
                        batch_ids,
                    ).fetchall()
                except sqlite3.Error:
                    raise storage() from None
            else:
                batch_rows = []
                record_rows = []
                all_event_rows = []

            batches_by_id = {row["batch_id"]: row for row in batch_rows}
            records_by_batch: dict[str, list] = {}
            events_by_batch: dict[str, list] = {}
            for row in record_rows:
                records_by_batch.setdefault(row["batch_id"], []).append(row)
            for event in all_event_rows:
                events_by_batch.setdefault(event["batch_id"], []).append(event)

            # Review phase: first the page's own event rows -- their stored
            # types and their position in the fixed (start, water] window.
            for event in event_rows:
                if type(event["seq"]) is not int or not start < event["seq"] <= water:
                    raise integrity()
                if (
                    event["tenant"] != tenant
                    or not isinstance(event["record_id"], str)
                    or type(event["position"]) is not int
                    or not 0 <= event["position"] < MAX_ENCRYPTED_BATCH_SIZE
                ):
                    raise integrity()

            # Then every involved batch as a whole, in first-touch order.
            for batch_id in batch_ids:
                # The associated batch id comes from stored rows, so its type
                # and shape are themselves part of the review (a BLOB or
                # malformed link is integrity drift), exactly as on the
                # cross-batch sealed-record read.
                if (
                    not isinstance(batch_id, str)
                    or ENCRYPTED_BATCH_ID.fullmatch(batch_id) is None
                ):
                    raise integrity()
                batch = batches_by_id.get(batch_id)
                # A dangling association (missing batch row) or one repointed
                # at another tenant is a relationship failure.
                if batch is None or batch["tenant"] != tenant:
                    raise integrity()
                self._validate_encrypted_batch(
                    batch,
                    records_by_batch.get(batch_id, []),
                    events_by_batch.get(batch_id, []),
                )

            items: list[dict] = []
            for event in event_rows:
                batch = batches_by_id[event["batch_id"]]
                items.append(
                    {
                        "seq": event["seq"],
                        "batch_id": event["batch_id"],
                        "id": event["record_id"],
                        "position": event["position"],
                        "created_at": batch["created_at"],
                    }
                )

            end_seq = event_rows[-1]["seq"] if event_rows else start
            next_cursor = (
                self._issue_event_cursor(tenant, end_seq, water)
                if has_more
                else None
            )
            return items, water, next_cursor

    def _issue_event_cursor(self, tenant: str, after_seq: int, water: int) -> str:
        return self._issue_cursor_payload(
            EVENT_LIST_CURSOR_NAMESPACE,
            {"a": after_seq, "w": water, "n": tenant},
        )

    def _parse_event_cursor(self, tenant: str, cursor: str) -> tuple[int, int]:
        """Validate an event-chain cursor for this tenant; (after_seq, water)."""
        payload = self._parse_cursor_payload(EVENT_LIST_CURSOR_NAMESPACE, cursor)
        try:
            after_seq = payload["a"]
            water = payload["w"]
            cursor_tenant = payload["n"]
        except (KeyError, TypeError):
            raise invalid_request() from None
        if (
            not isinstance(cursor_tenant, str)
            or cursor_tenant != tenant
            or type(after_seq) is not int
            or type(water) is not int
            or not 0 <= after_seq <= water <= MAX_EVENT_SEQ
        ):
            raise invalid_request()
        return after_seq, water

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
