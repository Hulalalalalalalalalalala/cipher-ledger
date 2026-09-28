"""Tenant-scoped record storage with envelope encryption and key rotation.

All operations take one process-wide re-entrant lock so the results of
concurrent creates, reads and rotations are equivalent to some total serial
ordering. Rotation verifies every old envelope first and only then performs a
single transactional write, so a damaged envelope or a storage failure leaves
the active version and all records exactly as they were before the request.
"""

import sqlite3
import threading

from . import envelope
from .config import Config
from .database import connect, initialize


class LedgerError(Exception):
    """Application-level error mapped to an HTTP status and code."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def conflict() -> LedgerError:
    return LedgerError(409, "conflict")


def not_found() -> LedgerError:
    return LedgerError(404, "not_found")


def integrity() -> LedgerError:
    return LedgerError(422, "integrity_error")


def storage() -> LedgerError:
    return LedgerError(503, "storage_error")


class Ledger:
    def __init__(self, config: Config):
        initialize(config.database, config.active_version)
        self._keys = dict(config.keys)
        self._connection = connect(config.database)
        self._lock = threading.RLock()
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
                    self._connection.execute(
                        "INSERT INTO records "
                        "(tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant,
                            record_id,
                            sealed["key_version"],
                            sealed["nonce"],
                            sealed["ciphertext"],
                            sealed["wrap_nonce"],
                            sealed["wrapped_key"],
                        ),
                    )
            except sqlite3.IntegrityError:
                # PRIMARY KEY (tenant, id) violation -> record already exists.
                raise conflict() from None
            except sqlite3.Error:
                raise storage() from None
            return version

    def create_batch(self, tenant: str, items: list[tuple[str, str]]) -> int:
        """Create many records in one transaction.

        ``items`` is an ordered list of ``(id, plaintext)`` pairs already
        validated by the HTTP layer. Every record is sealed independently with
        its own data key and nonces under the single active version. A duplicate
        id (within the batch or against stored rows) or any storage failure
        aborts the whole batch: nothing is inserted.
        """
        with self._lock:
            version = self._active_version
            record_ids = [record_id for record_id, _plaintext in items]

            try:
                existing = {
                    row[0]
                    for row in self._connection.execute(
                        "SELECT id FROM records WHERE tenant=?",
                        (tenant,),
                    ).fetchall()
                }
            except sqlite3.Error:
                raise storage() from None

            seen: set[str] = set()
            for record_id in record_ids:
                if record_id in seen or record_id in existing:
                    raise conflict()
                seen.add(record_id)

            sealed_rows = []
            for record_id, plaintext in items:
                sealed = envelope.seal(self._keys, version, tenant, record_id, plaintext)
                sealed_rows.append(
                    (
                        tenant,
                        record_id,
                        version,
                        sealed["nonce"],
                        sealed["ciphertext"],
                        sealed["wrap_nonce"],
                        sealed["wrapped_key"],
                    )
                )

            try:
                with self._connection:
                    self._connection.executemany(
                        "INSERT INTO records "
                        "(tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        sealed_rows,
                    )
            except sqlite3.IntegrityError:
                # PRIMARY KEY (tenant, id) violation from a concurrent writer
                # that committed between the pre-check and this transaction.
                raise conflict() from None
            except sqlite3.Error:
                raise storage() from None
            return version

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
