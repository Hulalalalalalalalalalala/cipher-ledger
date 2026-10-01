"""Threaded HTTP server exposing the public record and key protocol."""

import base64
import binascii
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import Config
from .ledger import EncryptedEntry, Ledger, LedgerError

IDENT_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
BATCH_ID_PATTERN = re.compile(r"batch_[0-9a-f]{32}\Z")
MAX_PLAINTEXT_BYTES = 65536
MAX_BATCH_SIZE = 100
MAX_ENCRYPTED_BYTES = 1048576
MAX_METADATA_BYTES = 16384
MAX_ENCRYPTION_KEY_ID = 128
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 100
TENANT_HEADER = "X-Tenant-ID"

# Algorithms accepted on the encrypted ingress. Each pins the exact byte
# lengths the service validates and stores, so an unsupported value or a body
# whose fields do not match its algorithm is rejected before any write.
ENCRYPTED_ALGORITHMS = {
    # wrapped_key = data-key length + 16-byte GCM auth tag.
    "AES-256-GCM": {"nonce": 12, "tag": 16, "wrapped_key": 32 + 16},
    "AES-128-GCM": {"nonce": 12, "tag": 16, "wrapped_key": 16 + 16},
}


def is_ident(value: object) -> bool:
    return isinstance(value, str) and IDENT_PATTERN.fullmatch(value) is not None


def valid_plaintext(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(value.encode("utf-8")) <= MAX_PLAINTEXT_BYTES
    except UnicodeEncodeError:
        return False


def decode_bytes_field(value: object) -> bytes | None:
    """Decode one base64 (standard, padded) field; None covers absent/non-str."""
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


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

    def error(self, status: int, code: str, message: str | None = None) -> None:
        body = {"error": code}
        if message is not None:
            body["message"] = message
        self.send_json(status, body)

    def raise_ledger_error(self, exc: LedgerError) -> None:
        self.error(exc.status, exc.code, exc.message)

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
            elif path.startswith("/v1/encrypted-records/batches/"):
                # Any query string is part of the route split but ignored.
                self.get_encrypted_batch(path[len("/v1/encrypted-records/batches/") :])
            else:
                self.error(404, "not_found")
        except LedgerError as exc:
            self.raise_ledger_error(exc)
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
            elif path == "/v1/encrypted-records/batch":
                self.ingest_encrypted_batch()
            elif path == "/v1/keys/rotate":
                self.rotate_keys()
            else:
                self.error(404, "not_found")
        except LedgerError as exc:
            self.raise_ledger_error(exc)
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

    def ingest_encrypted_batch(self) -> None:
        # Tenant resolution is an authorization decision on this ingress:
        # a missing/unverifiable identity can never be bound to a tenant.
        tenant = self.tenant()
        if tenant is None:
            self.error(
                403,
                "TENANT_RECORD_FORBIDDEN",
                f"request identity is missing or not a valid {TENANT_HEADER}",
            )
            return
        payload = self.read_json_object()
        if payload is None:
            self.error(400, "INVALID_BATCH", "request body must be a JSON object")
            return
        raw_records = payload.get("records")
        if not isinstance(raw_records, list) or not 1 <= len(raw_records) <= MAX_BATCH_SIZE:
            self.error(
                400,
                "INVALID_BATCH",
                "records must be an array containing 1 to %d items" % MAX_BATCH_SIZE,
            )
            return

        # Pass 1: every explicit per-record tenant claim must match the
        # authenticated tenant. A record claiming another tenant is a cross
        # tenant write attempt, regardless of any other shape problem.
        for index, item in enumerate(raw_records):
            if isinstance(item, dict) and "tenant" in item:
                claimed = item["tenant"]
                if not is_ident(claimed) or claimed != tenant:
                    self.error(
                        403,
                        "TENANT_RECORD_FORBIDDEN",
                        f"records[{index}].tenant does not belong to the authenticated tenant",
                    )
                    return

        # Pass 2: validate and decode every record before the ledger is
        # touched. Any failure aborts the whole batch and names its location.
        entries: list[EncryptedEntry] = []
        for index, item in enumerate(raw_records):
            location = f"records[{index}]"
            if not isinstance(item, dict):
                self.error(400, "INVALID_BATCH", f"{location} must be an object")
                return

            record_id = item.get("id")
            if not is_ident(record_id):
                self.error(400, "INVALID_BATCH", f"{location}.id must match [A-Za-z0-9_-]{{1,64}}")
                return

            algorithm = item.get("algorithm")
            profile = ENCRYPTED_ALGORITHMS.get(algorithm) if isinstance(algorithm, str) else None
            if profile is None:
                self.error(
                    400,
                    "INVALID_BATCH",
                    f"{location}.algorithm is unsupported: {algorithm!r}",
                )
                return

            key_id = item.get("key_id")
            if key_id is not None and (
                not isinstance(key_id, str)
                or not 1 <= len(key_id) <= MAX_ENCRYPTION_KEY_ID
            ):
                self.error(
                    400,
                    "INVALID_BATCH",
                    f"{location}.key_id must be a string of 1 to {MAX_ENCRYPTION_KEY_ID} chars",
                )
                return

            envelope = item.get("envelope")
            if not isinstance(envelope, dict):
                self.error(400, "INVALID_BATCH", f"{location}.envelope must be an object")
                return
            envelope_nonce = decode_bytes_field(envelope.get("nonce"))
            if envelope_nonce is None or len(envelope_nonce) != profile["nonce"]:
                self.error(
                    400,
                    "INVALID_BATCH",
                    f"{location}.envelope.nonce must be base64 of exactly {profile['nonce']} bytes",
                )
                return
            wrapped_key = decode_bytes_field(envelope.get("wrapped_key"))
            # The declared algorithm fixes the data-key size, so the wrapped
            # data key (plus its 16-byte GCM tag) has one expected length; a
            # different length contradicts the declared algorithm.
            if wrapped_key is None or len(wrapped_key) != profile["wrapped_key"]:
                self.error(
                    400,
                    "INVALID_BATCH",
                    f"{location}.envelope.wrapped_key must be base64 of exactly "
                    f"{profile['wrapped_key']} bytes for {algorithm}",
                )
                return

            cipher = item.get("ciphertext")
            if not isinstance(cipher, dict):
                self.error(400, "INVALID_BATCH", f"{location}.ciphertext must be an object")
                return
            body = decode_bytes_field(cipher.get("data"))
            if body is None or len(body) > MAX_ENCRYPTED_BYTES:
                self.error(
                    400,
                    "INVALID_BATCH",
                    f"{location}.ciphertext.data must be base64 of at most {MAX_ENCRYPTED_BYTES} bytes",
                )
                return
            cipher_nonce = decode_bytes_field(cipher.get("nonce"))
            if cipher_nonce is None or len(cipher_nonce) != profile["nonce"]:
                self.error(
                    400,
                    "INVALID_BATCH",
                    f"{location}.ciphertext.nonce must be base64 of exactly {profile['nonce']} bytes",
                )
                return
            tag = decode_bytes_field(cipher.get("tag"))
            if tag is None or len(tag) != profile["tag"]:
                self.error(
                    400,
                    "INVALID_BATCH",
                    f"{location}.ciphertext.tag must be base64 of exactly {profile['tag']} bytes",
                )
                return

            metadata_value = item.get("metadata")
            metadata_text = None
            if metadata_value is not None:
                if not isinstance(metadata_value, dict):
                    self.error(
                        400,
                        "INVALID_BATCH",
                        f"{location}.metadata must be an object when present",
                    )
                    return
                metadata_text = json.dumps(metadata_value, ensure_ascii=False, separators=(",", ":"))
                if len(metadata_text.encode("utf-8")) > MAX_METADATA_BYTES:
                    self.error(
                        400,
                        "INVALID_BATCH",
                        f"{location}.metadata must serialize to at most {MAX_METADATA_BYTES} bytes",
                    )
                    return

            entries.append(
                EncryptedEntry(
                    record_id=record_id,
                    algorithm=algorithm,
                    encryption_key_id=key_id,
                    envelope_nonce=envelope_nonce,
                    wrapped_key=wrapped_key,
                    ciphertext=body,
                    ciphertext_nonce=cipher_nonce,
                    tag=tag,
                    metadata=metadata_text,
                )
            )

        batch_id, record_ids = self.server.ledger.ingest_encrypted_batch(tenant, entries)
        self.send_json(
            201,
            {
                "batch_id": batch_id,
                "count": len(record_ids),
                "results": [{"id": record_id, "status": "created"} for record_id in record_ids],
            },
        )

    def get_encrypted_batch(self, batch_id: str) -> None:
        # Tenant resolution is an authorization decision, as on the sealed
        # ingress: a missing/invalid header fails before the batch id is read.
        tenant = self.tenant()
        if tenant is None:
            self.error(403, "TENANT_RECORD_FORBIDDEN")
            return
        # A well-formed tenant but malformed batch id is a plain bad request.
        if BATCH_ID_PATTERN.fullmatch(batch_id) is None:
            self.error(400, "invalid_request")
            return
        # Query parameters are ignored by design; urlsplit already stripped them.
        result = self.server.ledger.read_encrypted_batch(tenant, batch_id)
        self.send_json(200, result)

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
