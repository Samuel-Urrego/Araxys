"""AES-256-GCM encryption for audit log entries.

Uses PBKDF2-HMAC-SHA256 for key derivation from the master secret,
and AES-256-GCM for authenticated encryption (confidentiality + integrity).

Each encrypted entry includes:
- 16-byte salt (for key derivation)
- 12-byte nonce (IV for GCM)
- Ciphertext + 16-byte GCM authentication tag
"""


from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from araxys.core.exceptions import EncryptionError

if TYPE_CHECKING:
    from araxys.core.types import AuditEntry

# Constants
SALT_LENGTH = 16  # bytes
NONCE_LENGTH = 12  # bytes — GCM standard
KEY_LENGTH = 32  # bytes — AES-256
KDF_ITERATIONS = 480_000  # OWASP 2023 recommendation for PBKDF2-SHA256


class AuditEncryption:
    """Encrypts and decrypts audit log entries using AES-256-GCM.

    Parameters
    ----------
    master_key:
        The master secret key from AraxysConfig. A unique encryption
        key is derived per entry using PBKDF2.
    """

    def __init__(self, master_key: str) -> None:
        self._master_key = master_key.encode()

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 256-bit encryption key using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(self._master_key)

    @staticmethod
    def _serialize_entry(entry: AuditEntry) -> bytes:
        """Convert an AuditEntry to JSON bytes for encryption."""
        data = asdict(entry)
        # Convert datetime objects to ISO format strings
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return json.dumps(data, default=str).encode()

    @staticmethod
    def _serialize_dict(data: dict[str, Any]) -> bytes:
        """Convert a dict to JSON bytes for encryption."""
        data = dict(data)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return json.dumps(data, default=str).encode()

    def encrypt_data(self, data: dict[str, Any]) -> str:
        """Encrypt a pre-serialised dict.

        Like :meth:`encrypt_entry` but accepts a plain dict, useful
        when the caller has already applied transformations such as
        PII masking.

        Returns a base64-encoded string with the same
        ``salt || nonce || ciphertext+tag`` format.
        """
        try:
            plaintext = self._serialize_dict(data)

            salt = os.urandom(SALT_LENGTH)
            nonce = os.urandom(NONCE_LENGTH)
            key = self._derive_key(salt)

            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            packed = salt + nonce + ciphertext
            return base64.b64encode(packed).decode()

        except Exception as exc:
            raise EncryptionError("encryption") from exc

    def encrypt_entry(self, entry: AuditEntry) -> str:
        """Encrypt an audit entry.

        Returns a base64-encoded string containing:
        ``salt || nonce || ciphertext+tag``

        Raises
        ------
        EncryptionError
            If encryption fails for any reason.
        """
        try:
            plaintext = self._serialize_entry(entry)

            salt = os.urandom(SALT_LENGTH)
            nonce = os.urandom(NONCE_LENGTH)
            key = self._derive_key(salt)

            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Pack: salt + nonce + ciphertext (includes GCM tag)
            packed = salt + nonce + ciphertext
            return base64.b64encode(packed).decode()

        except Exception as exc:
            raise EncryptionError("encryption") from exc

    def decrypt_entry(self, encrypted: str) -> dict:  # type: ignore
        """Decrypt an audit entry.

        Parameters
        ----------
        encrypted:
            Base64-encoded encrypted entry from ``encrypt_entry``.

        Returns
        -------
        The original audit entry data as a dict.

        Raises
        ------
        EncryptionError
            If decryption fails (wrong key, tampered data, etc.)
        """
        try:
            packed = base64.b64decode(encrypted)

            salt = packed[:SALT_LENGTH]
            nonce = packed[SALT_LENGTH : SALT_LENGTH + NONCE_LENGTH]
            ciphertext = packed[SALT_LENGTH + NONCE_LENGTH :]

            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return json.loads(plaintext)  # type: ignore

        except Exception as exc:
            raise EncryptionError("decryption") from exc
