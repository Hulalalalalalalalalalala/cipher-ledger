"""Threaded HTTP server exposing the public record and key protocol."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import Config
from . import encrypted_batch
from .ledger import Ledger, LedgerError

IDENT_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
IDEMPOTENCY_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
MAX_PLAINTEXT_BYTES = 65536
MAX_BATCH_SIZE = 100
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 100
TENANT_HEADER = "X-Tenant-ID"


def is_ident(value: object) -> bool:
    return isinstance(value, str) and IDENT_PATTERN.fullmatch(value) is not None


def valid_plaintext(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(value.encode("utf-8")) <= MAX_PLAINTEXT_BYTES
    except UnicodeEncodeError:
        return False


class LedgerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], config: Config):
        self.config = config
        self.ledger = Ledger(config)
        super().__init__(address, LedgerHandler)

    def server_close(self) -> None:
        try:
            self.ledger.close()
        finally:
            super().server_close()


class LedgerHandler(BaseHTTPRequestHandler):
    server: LedgerServer

    def send_json(self, status: int, value: dict) -> None:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def error(self, status: int, code: str) -> None:
        self.send_json(status, {"error": code})

    def error_detail(self, status: int, code: str, message: str) -> None:
        self.send_json(status, {"error": code, "message": message})

    def ledger_error(self, exc: LedgerError) -> None:
        if exc.message is None:
            self.error(exc.status, exc.code)
        else:
            self.error_detail(exc.status, exc.code, exc.message)

    def tenant(self) -> str | None:
        value = self.headers.get(TENANT_HEADER)
        return value if is_ident(value) else None

    def read_json_object(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            return None
        if length < 0:
            return None
        try:
            raw = self.rfile.read(length)
            value = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return value if isinstance(value, dict) else None

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:
        split = urlsplit(self.path)
        path = split.path
        try:
            if path == "/health":
                self.send_json(200, {"status": "ok", "service": "cipher-ledger"})
            elif path == "/v1/keys":
                self.send_json(200, {"active_version": self.server.ledger.active_version})
            elif path == "/v1/records":
                self.list_records(split.query)
            elif path.startswith("/v1/records/"):
                self.get_record(path[len("/v1/records/") :])
            else:
                self.error(404, "not_found")
        except LedgerError as exc:
            self.ledger_error(exc)
        except Exception:
            # Never leak stack traces or crypto library details.
            self.error(500, "internal_error")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        try:
            if path == "/v1/records":
                self.create_record()
            elif path == "/v1/records/batch":
                self.create_records_batch()
            elif path == "/v1/records/batch/read":
                self.read_records_batch()
            elif path == "/v1/encrypted-records/batches":
                self.create_encrypted_batch()
            elif path == "/v1/keys/rotate":
                self.rotate_keys()
            else:
                self.error(404, "not_found")
        except LedgerError as exc:
            self.ledger_error(exc)
        except Exception:
            self.error(500, "internal_error")

    # -- endpoints ---------------------------------------------------------

    def list_records(self, raw_query: str) -> None:
        tenant = self.tenant()
        limit: int | None = None
        cursor: str | None = None
        if tenant is None:
            self.error(400, "invalid_request")
            return
        for segment in raw_query.split("&") if raw_query else ():
            name, equals, value = segment.partition("=")
            if not equals:
                continue
            if name == "limit":
                # Pure ASCII digits, 1..100; duplicate or malformed -> 400.
                if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= MAX_PAGE_LIMIT:
                    self.error(400, "invalid_request")
                    return
                if limit is not None:
                    self.error(400, "invalid_request")
                    return
                limit = int(value)
            elif name == "cursor":
                if cursor is not None:
                    self.error(400, "invalid_request")
                    return
                cursor = value
            # Any other query parameter is ignored.
        if limit is None:
            limit = DEFAULT_PAGE_LIMIT
        items, next_cursor = self.server.ledger.list_records(tenant, limit, cursor)
        body = {"items": [{"id": record_id} for record_id in items]}
        if next_cursor is not None:
            body["next_cursor"] = next_cursor
        self.send_json(200, body)

    def get_record(self, record_id: str) -> None:
        tenant = self.tenant()
        if tenant is None or not is_ident(record_id):
            self.error(400, "invalid_request")
            return
        result = self.server.ledger.read(tenant, record_id)
        self.send_json(200, result)

    def create_record(self) -> None:
        tenant = self.tenant()
        payload = self.read_json_object()
        if tenant is None or payload is None:
            self.error(400, "invalid_request")
            return
        record_id = payload.get("id")
        plaintext = payload.get("plaintext")
        if not is_ident(record_id) or not valid_plaintext(plaintext):
            self.error(400, "invalid_request")
            return
        version = self.server.ledger.create(tenant, record_id, plaintext)
        self.send_json(201, {"id": record_id, "key_version": version})

    def create_records_batch(self) -> None:
        tenant = self.tenant()
        payload = self.read_json_object()
        if tenant is None or payload is None:
            self.error(400, "invalid_request")
            return
        raw_records = payload.get("records")
        if not isinstance(raw_records, list) or not 1 <= len(raw_records) <= MAX_BATCH_SIZE:
            self.error(400, "invalid_request")
            return
        entries: list[tuple[str, str]] = []
        for item in raw_records:
            if not isinstance(item, dict):
                self.error(400, "invalid_request")
                return
            record_id = item.get("id")
            plaintext = item.get("plaintext")
            if not is_ident(record_id) or not valid_plaintext(plaintext):
                self.error(400, "invalid_request")
                return
            entries.append((record_id, plaintext))
        version, created = self.server.ledger.create_batch(tenant, entries)
        self.send_json(201, {"key_version": version, "created": created})

    def create_encrypted_batch(self) -> None:
        """POST /v1/encrypted-records/batches: one atomic client-sealed batch.

        Records arrive already encrypted by the caller. The service validates
        shape, identifiers, algorithm metadata and consistency, then commits
        every row in one transaction. It never decrypts, unwraps, derives or
        shares the per-record envelope key material.
        """
        tenant = self.tenant()
        payload = self.read_json_object()
        # On this endpoint an identity that cannot determine a tenant is a
        # forbidden request (existing endpoints keep their own 400 behavior).
        if tenant is None:
            self.error_detail(
                403,
                "TENANT_RECORD_FORBIDDEN",
                "request identity could not determine a tenant: "
                "missing or invalid X-Tenant-ID",
            )
            return
        if payload is None:
            self.error_detail(
                400, "INVALID_BATCH", "request body must be a UTF-8 JSON object"
            )
            return

        idempotency_key = payload.get("idempotency_key")
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not IDEMPOTENCY_PATTERN.fullmatch(
                idempotency_key
            ):
                self.error_detail(
                    400,
                    "INVALID_BATCH",
                    "idempotency_key: must match [A-Za-z0-9_-]{1,128} when present",
                )
                return

        try:
            entries = encrypted_batch.validate_records(payload.get("records"))
        except encrypted_batch.InvalidBatch as exc:
            self.error_detail(400, "INVALID_BATCH", str(exc))
            return

        result = self.server.ledger.create_encrypted_batch(tenant, entries, idempotency_key)
        self.send_json(201, result)

    def read_records_batch(self) -> None:
        tenant = self.tenant()
        payload = self.read_json_object()
        if tenant is None or payload is None:
            self.error(400, "invalid_request")
            return
        record_ids = payload.get("ids")
        if (
            not isinstance(record_ids, list)
            or not 1 <= len(record_ids) <= MAX_BATCH_SIZE
            or any(not is_ident(record_id) for record_id in record_ids)
            or len(set(record_ids)) != len(record_ids)
        ):
            self.error(400, "invalid_request")
            return
        items = self.server.ledger.read_batch(tenant, record_ids)
        self.send_json(200, {"items": items})

    def rotate_keys(self) -> None:
        payload = self.read_json_object()
        if payload is None:
            self.error(400, "invalid_request")
            return
        version = payload.get("version")
        # Booleans are ints in Python; they are not accepted as versions.
        if type(version) is not int or version < 1:
            self.error(400, "invalid_request")
            return
        active, rewrapped = self.server.ledger.rotate(version)
        self.send_json(200, {"active_version": active, "rewrapped": rewrapped})

    def log_message(self, format: str, *args) -> None:
        # Access logs contain only the usual request line and status information;
        # request bodies, plaintext and key material are never logged.
        super().log_message(format, *args)
