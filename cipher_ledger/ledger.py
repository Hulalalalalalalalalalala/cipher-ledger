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
        body = base64.urlsafe_b64encode(
            json.dumps(
                {"ns": namespace, "t": token, "o": offset, "n": tenant},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        # Omit base64 padding ("=") so the opaque cursor carries safely in a
        # query string without percent-encoding; padding is restored on parse.
        encoded_body = body.rstrip(b"=")
        tag = hmac.new(self._cursor_secret, encoded_body, hashlib.sha256).digest()
        encoded_tag = base64.urlsafe_b64encode(tag).rstrip(b"=")
        return (encoded_body + b"." + encoded_tag).decode("ascii")

    def _parse_cursor(self, namespace: str, cursor: str) -> tuple[str, int]:
        try:
            body, encoded_tag = cursor.encode("ascii").split(b".", 1)
            tag = base64.urlsafe_b64decode(encoded_tag + b"=" * (-len(encoded_tag) % 4))
            expected = hmac.new(self._cursor_secret, body, hashlib.sha256).digest()
            if len(tag) != 32 or not hmac.compare_digest(tag, expected):
                raise invalid_request()
            decoded_body = base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4))
            payload = json.loads(decoded_body)
            cursor_namespace = payload["ns"]
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
            or cursor_namespace != namespace
            or not isinstance(token_hex, str)
            or not isinstance(cursor_tenant, str)
            or type(offset) is not int
            or len(token_hex) not in (32, 36)
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

            records = [
                self._serialize_encrypted_record(row) for row in record_rows
            ]
            return {
                "batch_id": batch["batch_id"],
                "count": len(records),
                "created_at": batch["created_at"],
                "records": records,
            }

    def _serialize_encrypted_record(self, row) -> dict:
        """Render one validated sealed-record row in the public read shape."""
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

    def read_encrypted_records_batch(
        self, tenant: str, record_ids: list[str]
    ) -> list[dict]:
        """Fetch sealed records of one tenant by id, possibly across batches.

        Existence is settled first in a single tenant-scoped query: only the
        client-sealed ``encrypted_records`` table counts, so a plain
        server-encrypted ``records`` row or another tenant's same-named id
        counts as missing. Any missing id fails the whole request with 404
        before any batch detail is read, so a request mixing a missing id with
        a damaged batch deterministically returns 404.

        Only once every id is known to exist are the involved batches, their
        full record sets and their append events loaded; any read failure is
        503. Every involved batch then passes the exact whole-batch review used
        by the single-batch read -- counts, positions, tenant/event
        correspondence and stored field shapes -- including records that share
        a batch but were not requested. A batch unrelated to any requested id
        is never inspected. Items come back strictly in request order, each
        carrying its batch id and that batch's verbatim ``created_at``.

        Envelopes are never opened and ciphertext authentication is never
        evaluated. Read-only; runs under the process-wide lock, so it observes
        one complete serial state relative to concurrent writes and rotations.
        """
        with self._lock:
            # Phase 1: tenant-scoped existence over sealed record ids only.
            try:
                rows = self._connection.execute(
                    "SELECT id, batch_id FROM encrypted_records "
                    "WHERE tenant=? AND id IN (%s)"
                    % ",".join("?" * len(record_ids)),
                    (tenant, *record_ids),
                ).fetchall()
            except sqlite3.Error:
                raise storage() from None
            batch_by_id = {row["id"]: row["batch_id"] for row in rows}
            if any(record_id not in batch_by_id for record_id in record_ids):
                raise not_found()

            # Phase 2: load every involved batch with its complete record and
            # event sets; storage failure here precedes the integrity review.
            batch_ids: list[str] = []
            seen_batches: set[str] = set()
            for record_id in record_ids:
                batch_id = batch_by_id[record_id]
                if batch_id not in seen_batches:
                    seen_batches.add(batch_id)
                    batch_ids.append(batch_id)

            batches: dict[str, object] = {}
            record_rows_by_batch: dict[str, list[object]] = {}
            events_by_batch: dict[str, list[object]] = {}
            try:
                for batch_id in batch_ids:
                    batch = self._connection.execute(
                        "SELECT batch_id, tenant, record_count, created_at "
                        "FROM encrypted_batches WHERE batch_id=?",
                        (batch_id,),
                    ).fetchone()
                    record_rows = self._connection.execute(
                        "SELECT tenant, id, batch_id, position, algorithm, "
                        "encryption_key_id, envelope_nonce, wrapped_key, ciphertext, "
                        "ciphertext_nonce, tag, metadata "
                        "FROM encrypted_records WHERE batch_id=? ORDER BY position ASC",
                        (batch_id,),
                    ).fetchall()
                    event_rows = self._connection.execute(
                        "SELECT batch_id, tenant, record_id, position "
                        "FROM encrypted_record_events WHERE batch_id=? ORDER BY seq ASC",
                        (batch_id,),
                    ).fetchall()
                    batches[batch_id] = batch
                    record_rows_by_batch[batch_id] = record_rows
                    events_by_batch[batch_id] = event_rows
            except sqlite3.Error:
                raise storage() from None

            # Phase 3: only after all data is in hand, review each involved
            # batch as a whole. A requested record whose batch row vanished
            # between the two queries, a malformed batch id stored on the link,
            # an ownership mismatch, or any record/event drift or shape problem
            # in the batch (even on an unrequested sibling record) is 422.
            records_by_id: dict[str, object] = {}
            for batch_id in batch_ids:
                batch = batches[batch_id]
                record_rows = record_rows_by_batch[batch_id]
                event_rows = events_by_batch[batch_id]
                if (
                    batch is None
                    or not isinstance(batch["batch_id"], str)
                    or ENCRYPTED_BATCH_ID.fullmatch(batch["batch_id"]) is None
                ):
                    raise integrity()
                # The batch a requested record links to must be owned by the
                # requesting tenant; a cross-tenant link is attribution drift.
                if batch["tenant"] != tenant:
                    raise integrity()
                self._validate_encrypted_batch(batch, record_rows, event_rows)
                for row in record_rows:
                    records_by_id[(batch_id, row["id"])] = row

            items: list[dict] = []
            for record_id in record_ids:
                batch_id = batch_by_id[record_id]
                row = records_by_id.get((batch_id, record_id))
                # The link found in phase 1 must still resolve to the caller's
                # record in the reviewed batch; anything else is drift.
                if row is None or row["tenant"] != tenant:
                    raise integrity()
                item = self._serialize_encrypted_record(row)
                item["batch_id"] = batch_id
                item["created_at"] = batches[batch_id]["created_at"]
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
