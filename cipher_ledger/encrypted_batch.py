"""Validation for the client-sealed encrypted-record batch protocol.

Unlike :mod:`cipher_ledger.envelope`, the server never seals these records and
never sees a plaintext or a data key: every record arrives as an already sealed
envelope plus ciphertext. The validation here is therefore structural only --
shape, identifiers, supported algorithm metadata and byte-length consistency.
It never attempts to decrypt, unwrap, derive or reuse envelope key material.

Each record is validated independently and kept independent at storage time:
the opaque ``envelope`` bytes of one record are never shared with, copied to or
used to seal another record.
"""

import base64
import binascii
import json
import re
from dataclasses import dataclass

IDENT_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")

IDENT_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
MAX_RECORDS_PER_BATCH = 100
# The body ciphertext is plaintext plus the 16-byte GCM tag; the plaintext cap
# mirrors the single-record endpoint (65536 bytes).
MAX_CIPHERTEXT_BYTES = 65536 + 16
MAX_ENVELOPE_BYTES = 8192
MAX_KEY_ID_LENGTH = 256
MAX_METADATA_BYTES = 8192

# name -> (body nonce size, authentication tag size)
SUPPORTED_ALGORITHMS = {
    "AES-256-GCM": (12, 16),
}


class InvalidBatch(Exception):
    """The batch failed request-level validation. Message names the location."""


@dataclass(frozen=True)
class EncryptedEntry:
    """One structurally valid record, in the caller's input order."""

    record_id: str
    tenant_claim: str | None
    algorithm_name: str
    algorithm_json: str
    key_id: str | None
    envelope: bytes
    nonce: bytes
    ciphertext: bytes
    metadata_json: str | None


def _field_message(index: int, field: str, detail: str) -> InvalidBatch:
    return InvalidBatch(f"records[{index}].{field}: {detail}")


def _decode_base64(value: object) -> bytes:
    """Decode canonical standard Base64 or raise ValueError."""
    if not isinstance(value, str) or not value:
        raise ValueError("must be a non-empty Base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("must be valid standard Base64") from None
    # Require canonical encoding including padding so one byte value cannot be
    # submitted under several different spellings.
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("must be canonical standard Base64")
    return decoded


def _validate_algorithm(value: object, index: int) -> tuple[str, str, str | None]:
    if not isinstance(value, dict):
        raise _field_message(index, "algorithm", "must be an object")
    name = value.get("name")
    if not isinstance(name, str) or not name:
        raise _field_message(index, "algorithm.name", "must be a non-empty string")
    if name not in SUPPORTED_ALGORITHMS:
        raise _field_message(index, "algorithm.name", f"unsupported algorithm '{name}'")
    key_id = value.get("key_id")
    if key_id is not None:
        if not isinstance(key_id, str):
            raise _field_message(index, "algorithm.key_id", "must be a string when present")
        if not 1 <= len(key_id) <= MAX_KEY_ID_LENGTH:
            raise _field_message(
                index,
                "algorithm.key_id",
                f"length must be between 1 and {MAX_KEY_ID_LENGTH}",
            )
    canonical = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return name, canonical, key_id


def _validate_metadata(value: object, index: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _field_message(index, "metadata", "must be an object when present")
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(serialized.encode("utf-8")) > MAX_METADATA_BYTES:
        raise _field_message(index, "metadata", f"must not exceed {MAX_METADATA_BYTES} bytes")
    return serialized


def validate_records(raw: object) -> list[EncryptedEntry]:
    """Validate the whole ordered batch structurally.

    Raises :class:`InvalidBatch` with a message pointing at the first offending
    input location. Duplicate ids inside the batch are rejected here with the
    same INVALID_BATCH result as every other validation failure.
    """
    if not isinstance(raw, list):
        raise InvalidBatch("records: must be an array")
    if not 1 <= len(raw) <= MAX_RECORDS_PER_BATCH:
        raise InvalidBatch(
            f"records: must contain between 1 and {MAX_RECORDS_PER_BATCH} items"
        )

    entries: list[EncryptedEntry] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise InvalidBatch(f"records[{index}]: must be an object")

        record_id = item.get("id")
        if not isinstance(record_id, str) or not record_id:
            raise _field_message(index, "id", "must be a non-empty string")
        if IDENT_PATTERN.fullmatch(record_id) is None:
            raise _field_message(
                index,
                "id",
                "must match [A-Za-z0-9_-]{1,64}",
            )
        if record_id in seen:
            raise _field_message(index, "id", f"duplicate record id '{record_id}' in batch")
        seen.add(record_id)

        # Optional per-item tenant claim. A present, well-formed claim that
        # differs from the authenticated tenant is a cross-tenant attempt and
        # is handled by the ledger as TENANT_RECORD_FORBIDDEN; a malformed
        # claim is an invalid field.
        tenant_claim: str | None = None
        if "tenant" in item:
            claim = item.get("tenant")
            if not isinstance(claim, str) or not claim:
                raise _field_message(index, "tenant", "must be a non-empty string when present")
            if IDENT_PATTERN.fullmatch(claim) is None:
                raise _field_message(
                    index,
                    "tenant",
                    "must match [A-Za-z0-9_-]{1,64}",
                )
            tenant_claim = claim

        algorithm_name, algorithm_json, _ = _validate_algorithm(item.get("algorithm"), index)
        expected_nonce, tag_size = SUPPORTED_ALGORITHMS[algorithm_name]

        try:
            envelope = _decode_base64(item.get("envelope"))
        except ValueError as exc:
            raise _field_message(index, "envelope", str(exc)) from None
        if len(envelope) > MAX_ENVELOPE_BYTES:
            raise _field_message(
                index, "envelope", f"must not exceed {MAX_ENVELOPE_BYTES} bytes"
            )

        try:
            nonce = _decode_base64(item.get("nonce"))
        except ValueError as exc:
            raise _field_message(index, "nonce", str(exc)) from None
        if len(nonce) != expected_nonce:
            raise _field_message(
                index,
                "nonce",
                f"length {len(nonce)} contradicts algorithm "
                f"'{algorithm_name}' (requires {expected_nonce} bytes)",
            )

        try:
            ciphertext = _decode_base64(item.get("ciphertext"))
        except ValueError as exc:
            raise _field_message(index, "ciphertext", str(exc)) from None
        if len(ciphertext) < tag_size:
            raise _field_message(
                index,
                "ciphertext",
                f"length {len(ciphertext)} contradicts algorithm '{algorithm_name}': "
                f"shorter than its {tag_size}-byte authentication tag",
            )
        if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
            raise _field_message(
                index, "ciphertext", f"must not exceed {MAX_CIPHERTEXT_BYTES} bytes"
            )

        metadata_json = _validate_metadata(item.get("metadata"), index)

        entries.append(
            EncryptedEntry(
                record_id=record_id,
                tenant_claim=tenant_claim,
                algorithm_name=algorithm_name,
                algorithm_json=algorithm_json,
                key_id=item["algorithm"].get("key_id"),
                envelope=envelope,
                nonce=nonce,
                ciphertext=ciphertext,
                metadata_json=metadata_json,
            )
        )
    return entries
