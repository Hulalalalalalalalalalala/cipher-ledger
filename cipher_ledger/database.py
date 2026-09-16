"""SQLite connection and service metadata foundation."""

import sqlite3
from pathlib import Path


def connect(database: str | Path, check_same_thread: bool = True) -> sqlite3.Connection:
    connection = sqlite3.connect(str(database), timeout=15, check_same_thread=check_same_thread)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=15000")
    return connection


def initialize(database: str | Path) -> None:
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
    finally:
        connection.close()
