"""Encrypted record storage on top of SQLite.

A single lock serializes create/read/rotate so concurrent HTTP requests
observe results consistent with some complete serial order. Rotation
re-wraps every data key in one SQLite transaction: any integrity or
storage failure leaves all records and the active version untouched.
"""

import sqlite3
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag

from . import envelope
from .config import Config
from .database import connect


class NotFoundError(Exception):
    """The record does not exist for this tenant."""


class ConflictError(Exception):
    """A record with this tenant and id already exists."""


class IntegrityError(Exception):
    """An envelope failed authentication."""


class StorageError(Exception):
    """The database rejected a write."""


class InvalidVersionError(Exception):
    """The requested rotation target is not in the keyring."""


class VersionConflictError(Exception):
    """The requested rotation target is below the active version."""


class RecordStore:
    def __init__(self, database: str | Path, config: Config):
        self._keys = dict(config.keys)
        self._lock = threading.Lock()
        self._connection = connect(database, check_same_thread=False)
        with self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS records ("
                "tenant TEXT NOT NULL, "
                "id TEXT NOT NULL, "
                "key_version INTEGER NOT NULL, "
                "nonce BLOB NOT NULL, "
                "ciphertext BLOB NOT NULL, "
                "wrap_nonce BLOB NOT NULL, "
                "wrapped_key BLOB NOT NULL, "
                "PRIMARY KEY (tenant, id))"
            )
            # The persisted active version wins over the configured initial
            # value once the record feature has been enabled.
            self._connection.execute(
                "INSERT OR IGNORE INTO service_metadata(name, value) VALUES ('active_version', ?)",
                (str(config.active_version),),
            )
        row = self._connection.execute(
            "SELECT value FROM service_metadata WHERE name='active_version'"
        ).fetchone()
        self._active_version = int(row["value"])
        if self._active_version not in self._keys:
            raise ValueError("Invalid keyring configuration")
        referenced = {
            record["key_version"]
            for record in self._connection.execute("SELECT DISTINCT key_version FROM records")
        }
        if not referenced <= self._keys.keys():
            raise ValueError("Invalid keyring configuration")

    def close(self) -> None:
        self._connection.close()

    def active_version(self) -> int:
        with self._lock:
            return self._active_version

    def _unwrap(self, row: sqlite3.Row) -> bytes:
        master = self._keys.get(row["key_version"])
        if master is None:
            raise IntegrityError()
        try:
            return envelope.unwrap_key(
                master, row["tenant"], row["id"], row["key_version"], row["wrap_nonce"], row["wrapped_key"]
            )
        except (InvalidTag, TypeError, ValueError) as exc:
            raise IntegrityError() from exc

    def create(self, tenant: str, record_id: str, plaintext: str) -> int:
        with self._lock:
            version = self._active_version
            data_key = envelope.new_data_key()
            nonce, ciphertext = envelope.encrypt_content(data_key, tenant, record_id, plaintext.encode("utf-8"))
            wrap_nonce, wrapped_key = envelope.wrap_key(self._keys[version], data_key, tenant, record_id, version)
            try:
                with self._connection:
                    self._connection.execute(
                        "INSERT INTO records(tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (tenant, record_id, version, nonce, ciphertext, wrap_nonce, wrapped_key),
                    )
            except sqlite3.IntegrityError as exc:
                raise ConflictError() from exc
            except sqlite3.Error as exc:
                raise StorageError() from exc
            return version

    def read(self, tenant: str, record_id: str) -> tuple[str, int]:
        with self._lock:
            row = self._connection.execute(
                "SELECT tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key "
                "FROM records WHERE tenant = ? AND id = ?",
                (tenant, record_id),
            ).fetchone()
            if row is None:
                raise NotFoundError()
            data_key = self._unwrap(row)
            try:
                plaintext = envelope.decrypt_content(data_key, row["tenant"], row["id"], row["nonce"], row["ciphertext"])
            except (InvalidTag, TypeError, ValueError) as exc:
                raise IntegrityError() from exc
            return plaintext.decode("utf-8"), row["key_version"]

    def rotate(self, target: int) -> tuple[int, int]:
        with self._lock:
            if target not in self._keys:
                raise InvalidVersionError()
            current = self._active_version
            if target < current:
                raise VersionConflictError()
            if target == current:
                return current, 0
            rows = self._connection.execute(
                "SELECT tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key FROM records"
            ).fetchall()
            # Verify and re-wrap every envelope before touching the database,
            # so a corrupted record aborts the rotation with no writes at all.
            updates = []
            for row in rows:
                data_key = self._unwrap(row)
                try:
                    envelope.decrypt_content(data_key, row["tenant"], row["id"], row["nonce"], row["ciphertext"])
                except (InvalidTag, TypeError, ValueError) as exc:
                    raise IntegrityError() from exc
                wrap_nonce, wrapped_key = envelope.wrap_key(
                    self._keys[target], data_key, row["tenant"], row["id"], target
                )
                updates.append((target, wrap_nonce, wrapped_key, row["tenant"], row["id"]))
            try:
                with self._connection:
                    self._connection.executemany(
                        "UPDATE records SET key_version = ?, wrap_nonce = ?, wrapped_key = ? "
                        "WHERE tenant = ? AND id = ?",
                        updates,
                    )
                    self._connection.execute(
                        "UPDATE service_metadata SET value = ? WHERE name = 'active_version'",
                        (str(target),),
                    )
            except sqlite3.Error as exc:
                raise StorageError() from exc
            self._active_version = target
            return target, len(rows)
