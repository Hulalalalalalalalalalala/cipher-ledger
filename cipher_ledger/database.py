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
            # Client-sealed envelope rows written by the encrypted batch
            # endpoint. The server never unwraps the envelope and never sees a
            # plaintext data key; ``envelope`` keeps the caller's wrapping
            # material verbatim while nonce/ciphertext are the body AEAD. The
            # (tenant, id) primary key binds each sealed record server-side so
            # no other tenant can read or overwrite it; batch_id links the row
            # to the single atomic commit that created it.
            connection.execute(
                "CREATE TABLE IF NOT EXISTS encrypted_records ("
                "tenant TEXT NOT NULL, "
                "id TEXT NOT NULL, "
                "algorithm TEXT NOT NULL, "
                "envelope TEXT NOT NULL, "
                "nonce BLOB NOT NULL, "
                "ciphertext BLOB NOT NULL, "
                "metadata TEXT, "
                "batch_id TEXT NOT NULL, "
                "created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), "
                "PRIMARY KEY (tenant, id))"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_encrypted_records_batch "
                "ON encrypted_records(batch_id)"
            )
            # One append per accepted batch; batch_id is an opaque, globally
            # unique server-generated identifier. idempotency_key is the
            # caller-supplied retry token (unique per tenant) and may be null.
            connection.execute(
                "CREATE TABLE IF NOT EXISTS batch_commits ("
                "batch_id TEXT PRIMARY KEY, "
                "tenant TEXT NOT NULL, "
                "idempotency_key TEXT, "
                "record_count INTEGER NOT NULL, "
                "record_ids TEXT NOT NULL, "
                "fingerprint TEXT NOT NULL, "
                "created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_batch_commits_idempotency "
                "ON batch_commits(tenant, idempotency_key) WHERE idempotency_key IS NOT NULL"
            )
            if initial_version is not None:
                connection.execute(
                    "INSERT OR IGNORE INTO service_metadata(name, value) VALUES (?, ?)",
                    ("active_version", str(initial_version)),
                )
    finally:
        connection.close()
