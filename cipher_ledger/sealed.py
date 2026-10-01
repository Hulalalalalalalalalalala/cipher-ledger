"""Shape rules shared by client-sealed record writes and batch reads.

Write validation (in the HTTP layer) and read-time shape verification (in the
ledger) must agree exactly, so the algorithm profiles, byte limits, identifier
rules and (en/de)coders live here once. Nothing in this module ever decrypts a
client envelope or judges its cryptographic authenticity: bytes that satisfy
the declared shape are stored and returned verbatim.
"""

import base64
import binascii
import json
import re

IDENT_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
# Batch ids are "batch_" followed by 32 lowercase hexadecimal characters.
BATCH_ID_PATTERN = re.compile(r"batch_[0-9a-f]{32}\Z")

MAX_PLAINTEXT_BYTES = 65536
MAX_BATCH_SIZE = 100
MAX_ENCRYPTED_BYTES = 1048576
MAX_METADATA_BYTES = 16384
MAX_ENCRYPTION_KEY_ID = 128

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


def is_batch_id(value: object) -> bool:
    return isinstance(value, str) and BATCH_ID_PATTERN.fullmatch(value) is not None


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


def encode_bytes_field(value: bytes) -> str:
    """Encode stored bytes as standard Base64 with padding (empty -> "")."""
    return base64.b64encode(value).decode("ascii")


def valid_key_id(value: object) -> bool:
    return value is None or (
        isinstance(value, str) and 1 <= len(value) <= MAX_ENCRYPTION_KEY_ID
    )


def valid_metadata_text(value: object) -> bool:
    """Stored metadata must be NULL or a JSON object within the size limit.

    The write ingress serializes object metadata with compact separators, so a
    row whose text is not a JSON object or exceeds the byte cap can only come
    from damaged storage; a batch read rejects such a batch.
    """
    if value is None:
        return True
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_METADATA_BYTES:
        return False
    try:
        parsed = json.loads(value)
    except ValueError:
        return False
    return isinstance(parsed, dict)
