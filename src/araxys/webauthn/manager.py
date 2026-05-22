"""WebAuthn ceremony orchestrator.

``WebAuthnManager`` coordinates registration and authentication
ceremonies: generating challenges, verifying attestations and
assertions, and managing credential storage.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from araxys.webauthn.attestation import verify_none, verify_packed
from araxys.webauthn.cose import cose_alg_to_hash, parse_cose_key
from araxys.webauthn.exceptions import WebAuthnError
from araxys.webauthn.models import CredentialRecord, RelyingPartyConfig

if TYPE_CHECKING:
    from araxys.webauthn.challenges import ChallengeStore
    from araxys.webauthn.storage import CredentialStore


_CHALLENGE_TTL = 300  # seconds


class WebAuthnManager:
    """Orchestrates WebAuthn registration and authentication ceremonies.

    Parameters
    ----------
    rp:
        Relying Party configuration (RP ID, display name, expected origin).
    credential_store:
        Persistent storage for credential records.
    challenge_store:
        Ephemeral challenge storage for replay protection and TTL enforcement.
    """

    def __init__(
        self,
        rp: RelyingPartyConfig,
        credential_store: CredentialStore,
        challenge_store: ChallengeStore | None = None,
    ) -> None:
        self._rp = rp
        self._credential_store = credential_store
        self._challenge_store = challenge_store

    # ── Registration ──────────────────────────────────────────────────────

    async def create_registration_challenge(
        self, user_id: str, user_name: str
    ) -> dict[str, Any]:
        """Generate a ``PublicKeyCredentialCreationOptions`` dict.

        This creates a random 32-byte challenge and returns the options
        dict for the client. The challenge is returned as raw bytes in
        the ``"challenge"`` key. The caller should preserve these bytes
        and pass them to ``verify_registration``.

        The caller is responsible for base64url-encoding the challenge
        when serializing to JSON for the client.
        """
        challenge = secrets.token_bytes(32)
        if self._challenge_store is not None:
            try:
                await asyncio.wait_for(
                    self._challenge_store.set(
                        user_id or "anon", challenge, _CHALLENGE_TTL
                    ),
                    timeout=2.0,
                )
            except TimeoutError:
                raise WebAuthnError("Challenge store operation timed out") from None
            except Exception as exc:
                raise WebAuthnError(
                    f"Failed to store challenge: {exc}"
                ) from exc

        return {
            "rp": {
                "id": self._rp.rp_id,
                "name": self._rp.rp_name,
            },
            "user": {
                "id": user_id,
                "name": user_name,
                "displayName": user_name,
            },
            "challenge": challenge,
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},   # ES256
                {"type": "public-key", "alg": -257},  # RS256
            ],
            "timeout": 60000,
            "attestation": "none",
        }

    async def verify_registration(
        self,
        response: dict[str, Any],
        challenge: bytes,
        origin: str,
        user_id: str = "",
    ) -> CredentialRecord:
        """Verify a registration (attestation) response.

        Args:
            response: The credential response from the client.
            challenge: The raw 32-byte challenge that was returned by
                ``create_registration_challenge``.
            origin: The expected origin for this RP.
            user_id: The user identifier to associate with the credential.
                If not provided, the caller must set it on the returned
                ``CredentialRecord`` before persisting.

        Returns:
            A ``CredentialRecord`` with the verified credential data.
            The caller should persist this record.

        Raises:
            WebAuthnError: If verification fails for any reason.
        """
        client_data_json_b64: str = response["response"]["clientDataJSON"]
        client_data_json = self._b64_decode_str(client_data_json_b64)
        client_data = json.loads(client_data_json)

        # Validate origin
        actual_origin = client_data["origin"]
        if actual_origin != origin:
            raise WebAuthnError(
                f"Origin mismatch: expected '{origin}', got '{actual_origin}'"
            )

        # Validate challenge
        actual_challenge_b64 = client_data["challenge"]
        actual_challenge = self._b64_decode(actual_challenge_b64)

        stored_challenge: bytes | None = None
        challenge_store = self._challenge_store
        if challenge_store is not None:
            stored_challenge = await challenge_store.get(user_id or "anon")

        if stored_challenge is not None:
            if not hmac.compare_digest(actual_challenge, stored_challenge):
                raise WebAuthnError("Challenge mismatch")
            assert challenge_store is not None
            await challenge_store.delete(user_id or "anon")
        else:
            if not hmac.compare_digest(actual_challenge, challenge):
                raise WebAuthnError("Challenge mismatch")

        # Validate type
        if client_data["type"] != "webauthn.create":
            raise WebAuthnError(
                f"Invalid clientData type: {client_data['type']}"
            )

        # Parse attestation object
        att_obj_b64: str = response["response"]["attestationObject"]
        att_obj_raw = self._b64_decode(att_obj_b64)
        import cbor2

        try:
            att_obj = cbor2.loads(att_obj_raw)
            if not isinstance(att_obj, dict):
                raise WebAuthnError("Malformed attestation object")
        except (cbor2.CBORDecodeError, ValueError) as exc:
            raise WebAuthnError("Malformed attestation object") from exc

        fmt: str = att_obj["fmt"]
        auth_data: bytes = att_obj["authData"]

        # Verify RP ID hash
        rp_id_hash = hashlib.sha256(self._rp.rp_id.encode()).digest()
        if not hmac.compare_digest(auth_data[:32], rp_id_hash):
            raise WebAuthnError("RP ID hash mismatch")

        # Verify attestation
        client_data_hash = hashlib.sha256(client_data_json.encode()).digest()

        if fmt == "none":
            cred_data = verify_none(att_obj)
        elif fmt == "packed":
            cred_data = verify_packed(att_obj, rp_id_hash, client_data_hash)
        else:
            raise WebAuthnError(f"Unsupported attestation format: {fmt}")

        # Build credential record
        record = CredentialRecord(
            credential_id=cred_data["credential_id"],
            user_id=user_id,
            public_key_cbor=cred_data["public_key_cbor"],
            sign_count=cred_data["sign_count"],
            alg=cred_data.get("alg", -7),
            created_at=datetime.now(UTC),
            attestation_type=fmt,
        )

        # Store the credential
        await self._credential_store.save(record)

        return record

    # ── Authentication ────────────────────────────────────────────────────

    async def create_authentication_challenge(
        self, user_id: str
    ) -> dict[str, Any]:
        """Generate a ``PublicKeyCredentialRequestOptions`` dict.

        Enumerates the stored credentials for the user and returns
        them as ``allowCredentials``.
        """
        challenge = secrets.token_bytes(32)
        if self._challenge_store is not None:
            try:
                await asyncio.wait_for(
                    self._challenge_store.set(user_id, challenge, _CHALLENGE_TTL),
                    timeout=2.0,
                )
            except TimeoutError:
                raise WebAuthnError("Challenge store operation timed out") from None
            except Exception as exc:
                raise WebAuthnError(
                    f"Failed to store challenge: {exc}"
                ) from exc
        credentials = await self._credential_store.list_by_user(user_id)

        allow_creds = [
            {
                "type": "public-key",
                "id": cred.credential_id,
            }
            for cred in credentials
        ]

        return {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": self._rp.rp_id,
            "allowCredentials": allow_creds,
        }

    async def verify_authentication(
        self, response: dict[str, Any], challenge: bytes, origin: str,
        user_id: str = "",
    ) -> CredentialRecord:
        """Verify an authentication (assertion) response.

        Args:
            response: The assertion response from the client.
            challenge: The raw 32-byte challenge from the auth challenge.
            origin: The expected origin for this RP.
            user_id: The user identifier used when creating the challenge.
                Must match the user_id passed to
                ``create_authentication_challenge``. If not provided,
                falls back to the credential's stored ``user_id``.

        Returns:
            The updated ``CredentialRecord`` with the new sign count.

        Raises:
            WebAuthnError: If verification fails.
        """
        # Parse response
        credential_id_b64: str = response["id"]
        credential_id = self._b64_decode(credential_id_b64)

        client_data_json_b64: str = response["response"]["clientDataJSON"]
        client_data_json = self._b64_decode_str(client_data_json_b64)
        client_data = json.loads(client_data_json)

        # Validate origin
        actual_origin = client_data["origin"]
        if actual_origin != origin:
            raise WebAuthnError(
                f"Origin mismatch: expected '{origin}', got '{actual_origin}'"
            )

        # Validate challenge
        actual_challenge_b64 = client_data["challenge"]
        actual_challenge = self._b64_decode(actual_challenge_b64)

        # Load stored credential (also used for challenge lookup)
        stored = await self._credential_store.get(credential_id)
        if stored is None:
            raise WebAuthnError("Credential not found")

        stored_challenge = None
        if self._challenge_store is not None:
            lookup_id = user_id if user_id else stored.user_id
            stored_challenge = await self._challenge_store.get(lookup_id)
            if stored_challenge is not None:
                await self._challenge_store.delete(lookup_id)

        if stored_challenge is not None:
            if not hmac.compare_digest(actual_challenge, stored_challenge):
                raise WebAuthnError("Challenge mismatch")
        else:
            if not hmac.compare_digest(actual_challenge, challenge):
                raise WebAuthnError("Challenge mismatch")

        # Validate type
        if client_data["type"] != "webauthn.get":
            raise WebAuthnError(
                f"Invalid clientData type: {client_data['type']}"
            )

        # Parse assertion data
        auth_data_b64: str = response["response"]["authenticatorData"]
        auth_data = self._b64_decode(auth_data_b64)

        sig_b64: str = response["response"]["signature"]
        sig = self._b64_decode(sig_b64)

        # Verify RP ID hash
        rp_id_hash = hashlib.sha256(self._rp.rp_id.encode()).digest()
        if not hmac.compare_digest(auth_data[:32], rp_id_hash):
            raise WebAuthnError("RP ID hash mismatch")

        # Sign count check (monotonic enforcement).
        # When both counts are 0 the authenticator does not support
        # sign count (platform authenticators: Windows Hello, Apple
        # Touch ID, Android biometric). Accept the assertion.
        new_sign_count = struct_unpack_sign_count(auth_data)
        if new_sign_count == 0 and stored.sign_count == 0:
            pass
        elif new_sign_count <= stored.sign_count:
            raise WebAuthnError(
                f"Sign count not greater than stored count: "
                f"{new_sign_count} <= {stored.sign_count}"
            )

        # Verify signature
        client_data_hash = hashlib.sha256(client_data_json.encode()).digest()
        sig_input = auth_data + client_data_hash

        pub_key = parse_cose_key(stored.public_key_cbor)
        hash_cls = cose_alg_to_hash(stored.alg)

        try:
            if isinstance(pub_key, ec_mod.EllipticCurvePublicKey):
                pub_key.verify(sig, sig_input, ec_mod.ECDSA(hash_cls()))
            else:
                pub_key.verify(sig, sig_input, PKCS1v15(), hash_cls())
        except InvalidSignature as exc:
            raise WebAuthnError("Invalid assertion signature") from exc

        # Update sign count
        stored.sign_count = new_sign_count
        await self._credential_store.update_sign_count(
            credential_id, new_sign_count
        )

        return stored

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        """Base64url-encode with no padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        """Base64url-decode with padding restored."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _b64_decode_str(data: str) -> str:
        """Base64url-decode a string to UTF-8 string."""
        return WebAuthnManager._b64_decode(data).decode()


def struct_unpack_sign_count(auth_data: bytes) -> int:
    """Extract the sign count (4 bytes, big-endian) from authenticator data."""
    import struct

    count: int = struct.unpack(">I", auth_data[33:37])[0]
    return count
