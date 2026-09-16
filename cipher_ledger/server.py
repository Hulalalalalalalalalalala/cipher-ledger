"""Threaded HTTP service exposing the encrypted record protocol."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import Config
from .database import initialize
from .store import (
    ConflictError,
    IntegrityError,
    InvalidVersionError,
    NotFoundError,
    RecordStore,
    StorageError,
    VersionConflictError,
)

IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}")
MAX_PLAINTEXT_BYTES = 65536


class LedgerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], config: Config):
        initialize(config.database)
        self.config = config
        self.store = RecordStore(config.database, config)
        super().__init__(address, LedgerHandler)

    def server_close(self) -> None:
        super().server_close()
        self.store.close()


class LedgerHandler(BaseHTTPRequestHandler):
    server: LedgerServer

    def send_json(self, status: int, value: dict) -> None:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_error_json(self, status: int, code: str) -> None:
        self.send_json(status, {"error": code})

    def tenant(self) -> str | None:
        value = self.headers.get("X-Tenant-ID")
        if value is None or not IDENTIFIER.fullmatch(value):
            return None
        return value

    def read_json_object(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health":
            self.send_json(200, {"status": "ok", "service": "cipher-ledger"})
        elif path == "/v1/keys":
            self.send_json(200, {"active_version": self.server.store.active_version()})
        elif path.startswith("/v1/records/"):
            self.get_record(path[len("/v1/records/"):])
        else:
            self.send_error_json(404, "not_found")

    def get_record(self, record_id: str) -> None:
        tenant = self.tenant()
        if tenant is None or not IDENTIFIER.fullmatch(record_id):
            self.send_error_json(400, "invalid_request")
            return
        try:
            plaintext, key_version = self.server.store.read(tenant, record_id)
        except NotFoundError:
            self.send_error_json(404, "not_found")
        except IntegrityError:
            self.send_error_json(422, "integrity_error")
        else:
            self.send_json(200, {"id": record_id, "plaintext": plaintext, "key_version": key_version})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/v1/records":
            self.create_record()
        elif path == "/v1/keys/rotate":
            self.rotate_keys()
        else:
            self.send_error_json(404, "not_found")

    def create_record(self) -> None:
        tenant = self.tenant()
        body = self.read_json_object()
        if tenant is None or body is None:
            self.send_error_json(400, "invalid_request")
            return
        record_id = body.get("id")
        plaintext = body.get("plaintext")
        if not isinstance(record_id, str) or not IDENTIFIER.fullmatch(record_id):
            self.send_error_json(400, "invalid_request")
            return
        if not isinstance(plaintext, str) or len(plaintext.encode("utf-8")) > MAX_PLAINTEXT_BYTES:
            self.send_error_json(400, "invalid_request")
            return
        try:
            key_version = self.server.store.create(tenant, record_id, plaintext)
        except ConflictError:
            self.send_error_json(409, "conflict")
        except StorageError:
            self.send_error_json(503, "storage_error")
        else:
            self.send_json(201, {"id": record_id, "key_version": key_version})

    def rotate_keys(self) -> None:
        body = self.read_json_object()
        if body is None:
            self.send_error_json(400, "invalid_request")
            return
        version = body.get("version")
        if type(version) is not int or version < 1:
            self.send_error_json(400, "invalid_request")
            return
        try:
            active, rewrapped = self.server.store.rotate(version)
        except InvalidVersionError:
            self.send_error_json(400, "invalid_version")
        except VersionConflictError:
            self.send_error_json(409, "version_conflict")
        except IntegrityError:
            self.send_error_json(422, "integrity_error")
        except StorageError:
            self.send_error_json(503, "storage_error")
        else:
            self.send_json(200, {"active_version": active, "rewrapped": rewrapped})

    def log_message(self, format: str, *args) -> None:
        # Access logs contain only the usual request line and status information.
        super().log_message(format, *args)
