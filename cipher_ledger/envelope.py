"""AES-256-GCM envelope encryption bound to tenant, record and key version.

The public envelope format uses compact UTF-8 JSON arrays as AAD:
content AAD is ``[1,"tenant","record id"]`` and wrap AAD is
``[1,"tenant","record id",key version]``. Plaintext and key material never
touch the database or logs; only nonces and ciphertexts leave this module.
"""

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_FORMAT_VERSION = 1
NONCE_SIZE = 12
DATA_KEY_SIZE = 32


def content_aad(tenant: str, record_id: str) -> bytes:
    parts = [ENVELOPE_FORMAT_VERSION, tenant, record_id]
    return json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def wrap_aad(tenant: str, record_id: str, key_version: int) -> bytes:
    parts = [ENVELOPE_FORMAT_VERSION, tenant, record_id, key_version]
    return json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def new_data_key() -> bytes:
    return os.urandom(DATA_KEY_SIZE)


def encrypt_content(data_key: bytes, tenant: str, record_id: str, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, content_aad(tenant, record_id))
    return nonce, ciphertext


def decrypt_content(data_key: bytes, tenant: str, record_id: str, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(data_key).decrypt(nonce, ciphertext, content_aad(tenant, record_id))


def wrap_key(master_key: bytes, data_key: bytes, tenant: str, record_id: str, key_version: int) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_SIZE)
    wrapped = AESGCM(master_key).encrypt(nonce, data_key, wrap_aad(tenant, record_id, key_version))
    return nonce, wrapped


def unwrap_key(master_key: bytes, tenant: str, record_id: str, key_version: int, nonce: bytes, wrapped: bytes) -> bytes:
    return AESGCM(master_key).decrypt(nonce, wrapped, wrap_aad(tenant, record_id, key_version))


__all__ = [
    "InvalidTag",
    "NONCE_SIZE",
    "DATA_KEY_SIZE",
    "content_aad",
    "wrap_aad",
    "new_data_key",
    "encrypt_content",
    "decrypt_content",
    "wrap_key",
    "unwrap_key",
]
