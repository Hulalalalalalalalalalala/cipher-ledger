"""SQLite connection, schema and service metadata foundation."""

import sqlite3
from pathlib import Path


def connect(database: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(database), timeout=15, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=15000")
    return connection


def initialize(database: str | Path, initial_version: int | None = None) -> None:
    """Create base schema.

    When ``initial_version`` is given (service startup with record support
    enabled) it also creates the public ``records`` table and seeds the
    persisted active key version the first time records are enabled. On later
    restarts the database value wins and the config seed is ignored.
    """
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    connection = connect(database)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS service_metadata "
                "(name TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO service_metadata(name, value) VALUES (?, ?)",
                ("service_name", "cipher-ledger"),
            )
            connection.execute(
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
            # Client-sealed records submitted through the encrypted batch
            # ingress. The server never wraps or unwraps these envelopes: the
            # body key arrives already wrapped under a client-chosen algorithm,
            # so metadata/algorithm are stored verbatim alongside the bytes.
            connection.execute(
                "CREATE TABLE IF NOT EXISTS encrypted_batches ("
                "batch_id TEXT NOT NULL PRIMARY KEY, "
                "tenant TEXT NOT NULL, "
                "record_count INTEGER NOT NULL, "
                "created_at TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS encrypted_records ("
                "tenant TEXT NOT NULL, "
                "id TEXT NOT NULL, "
                "batch_id TEXT NOT NULL, "
                "position INTEGER NOT NULL, "
                "algorithm TEXT NOT NULL, "
                "encryption_key_id TEXT, "
                "envelope_nonce BLOB NOT NULL, "
                "wrapped_key BLOB NOT NULL, "
                "ciphertext BLOB NOT NULL, "
                "ciphertext_nonce BLOB NOT NULL, "
                "tag BLOB, "
                "metadata TEXT, "
                "PRIMARY KEY (tenant, id))"
            )
            # Append-only ledger: one row per record that ever became visible,
            # inserted in the same transaction as its record. It makes every
            # committed batch observable as one indivisible append.
            connection.execute(
                "CREATE TABLE IF NOT EXISTS encrypted_record_events ("
                "seq INTEGER NOT NULL PRIMARY KEY, "
                "batch_id TEXT NOT NULL, "
                "tenant TEXT NOT NULL, "
                "record_id TEXT NOT NULL, "
                "position INTEGER NOT NULL)"
            )
            # Idempotency bindings for the sealed batch ingress. A key is
            # inserted in the same transaction as the batch it points to, so a
            # row here exists only for a fully committed batch. The binding is
            # tenant scoped, never expires and survives restarts; batches
            # written before this table existed simply have no row.
            connection.execute(
                "CREATE TABLE IF NOT EXISTS encrypted_batch_idempotency_keys ("
                "tenant TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, "
                "batch_id TEXT NOT NULL, "
                "created_at TEXT NOT NULL, "
                "PRIMARY KEY (tenant, idempotency_key))"
            )
            # Frozen snapshots behind GET .../batches pagination. A cursorless
            # request captures one complete serial state: one snapshot row plus
            # one item row per batch visible at that instant, committed in a
            # single transaction. Later pages read those rows, so concurrent
            # commits neither duplicate nor drop entries; the tables persist so
            # a cursor keeps working across a normal database restart.
            connection.execute(
                "CREATE TABLE IF NOT EXISTS encrypted_batch_list_snapshots ("
                "snapshot_id TEXT NOT NULL PRIMARY KEY, "
                "tenant TEXT NOT NULL, "
                "total INTEGER NOT NULL, "
                "created_at TEXT NOT NULL)"
            )
            # Upgrade a database created before ``total`` was recorded on the
            # snapshot header; such databases contain no real snapshots, so the
            # default is never observed by a cursor (a zero-item snapshot is
            # itself treated as corruption).
            snapshot_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(encrypted_batch_list_snapshots)"
                )
            }
            if "total" not in snapshot_columns:
                connection.execute(
                    "ALTER TABLE encrypted_batch_list_snapshots "
                    "ADD COLUMN total INTEGER NOT NULL DEFAULT 0"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS encrypted_batch_list_snapshot_items ("
                "snapshot_id TEXT NOT NULL, "
                "position INTEGER NOT NULL, "
                # Compact JSON [batch_id, record_count, created_at]. JSON keeps
                # the original stored types intact (unlike type-affinity
                # columns), so a later page can still detect offline tampering
                # such as a non-string created_at.
                "summary TEXT NOT NULL, "
                "PRIMARY KEY (snapshot_id, position))"
            )
            if initial_version is not None:
                connection.execute(
                    "INSERT OR IGNORE INTO service_metadata(name, value) VALUES (?, ?)",
                    ("active_version", str(initial_version)),
                )
    finally:
        connection.close()
