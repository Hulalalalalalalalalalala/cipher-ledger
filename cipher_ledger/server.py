"""Threaded HTTP server exposing the public record and key protocol."""

import base64
import hashlib
import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

from .config import Config
from .ledger import Ledger, LedgerError

IDENT_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
LIMIT_PATTERN = re.compile(r"[0-9]+\Z")
MAX_PLAINTEXT_BYTES = 65536
MAX_BATCH_SIZE = 100
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 100
TENANT_HEADER = "X-Tenant-ID"
LIST_CURSOR_VERSION = 1


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
        self.cursor_secret = os.urandom(32)
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
            self.error(exc.status, exc.code)
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
            elif path == "/v1/keys/rotate":
                self.rotate_keys()
            else:
                self.error(404, "not_found")
        except LedgerError as exc:
            self.error(exc.status, exc.code)
        except Exception:
            self.error(500, "internal_error")

    # -- endpoints ---------------------------------------------------------

    def encode_cursor(self, tenant: str, snapshot: int, last_id: str) -> str:
        body = json.dumps(
            [LIST_CURSOR_VERSION, tenant, snapshot, last_id],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        signature = hmac.new(self.server.cursor_secret, body, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(body + signature).rstrip(b"=").decode("ascii")

    def decode_cursor(self, tenant: str, token: str) -> tuple[int, str] | None:
        """Validate an opaque cursor for ``tenant``.

        Returns (snapshot, last_id) or None for any malformed or forged token.
        """
        try:
            raw = base64.b64decode(
                token + "=" * (-len(token) % 4), altchars=b"-_", validate=True
            )
            body, signature = raw[: -hashlib.sha256().digest_size], raw[-hashlib.sha256().digest_size :]
            expected = hmac.new(self.server.cursor_secret, body, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                return None
            value = json.loads(body.decode("utf-8"))
            if not isinstance(value, list) or len(value) != 4:
                return None
            version, cursor_tenant, snapshot, last_id = value
            if (
                version != LIST_CURSOR_VERSION
                or cursor_tenant != tenant
                or type(snapshot) is not int
                or snapshot < 1
                or not is_ident(last_id)
            ):
                return None
            return snapshot, last_id
        except (ValueError, UnicodeDecodeError):
            return None

    def list_records(self, query: str) -> None:
        tenant = self.tenant()
        if tenant is None:
            self.error(400, "invalid_request")
            return
        parameters = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
        limit_values = [value for name, value in parameters if name == "limit"]
        cursor_values = [value for name, value in parameters if name == "cursor"]
        if len(limit_values) > 1 or len(cursor_values) > 1:
            self.error(400, "invalid_request")
            return
        limit = DEFAULT_LIST_LIMIT
        if limit_values:
            if LIMIT_PATTERN.fullmatch(limit_values[0]) is None:
                self.error(400, "invalid_request")
                return
            limit = int(limit_values[0])
            if not 1 <= limit <= MAX_LIST_LIMIT:
                self.error(400, "invalid_request")
                return
        snapshot = None
        after_id = None
        if cursor_values:
            decoded = self.decode_cursor(tenant, cursor_values[0])
            if decoded is None:
                self.error(400, "invalid_request")
                return
            snapshot, after_id = decoded
        items, snapshot, has_more = self.server.ledger.list_records(
            tenant, limit, snapshot, after_id
        )
        body = {"items": items}
        if has_more:
            body["next_cursor"] = self.encode_cursor(tenant, snapshot, items[-1])
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
