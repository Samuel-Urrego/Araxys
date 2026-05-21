"""WebAuthn attestation verification.

Supports the ``"none"`` (skip) and ``"packed"`` (direct attestation)
attestation formats as defined in the WebAuthn specification.
"""

from __future__ import annotations

import struct
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from araxys.webauthn.cose import cose_alg_to_hash, parse_cose_key
from araxys.webauthn.exceptions import WebAuthnError


def verify_none(attestation_object: dict[str, Any]) -> dict[str, Any]:
    """Verify a ``"none"`` format attestation.

    ``"none"`` attestation indicates no attestation statement is
    provided — the authenticator is trusted by the caller. This
    function extracts the credential data from the authenticator
    data embedded in the attestation object.

    Args:
        attestation_object: Decoded CBOR attestation object.

    Returns:
        A dict with ``credential_id``, ``public_key_cbor``,
        ``sign_count``, ``attestation_type`` (``"none"``).

    Raises:
        WebAuthnError: If the auth data is malformed.
    """
    auth_data = attestation_object["authData"]
    return _extract_credential_data(auth_data)


def verify_packed(
    attestation_object: dict[str, Any],
    rp_id_hash: bytes,
    client_data_hash: bytes,
) -> dict[str, Any]:
    """Verify a ``"packed"`` format attestation.

    Verifies the attestation signature over ``authData + clientDataHash``
    using the attestation public key embedded in the credential data.
    If ``x5c`` is present in the attestation statement, the signature is
    verified against that certificate's public key; otherwise the
    credential public key is used (self-attestation).

    Args:
        attestation_object: Decoded CBOR attestation object.
        rp_id_hash: SHA-256 of the RP ID.
        client_data_hash: SHA-256 of the clientDataJSON.

    Returns:
        A dict with ``credential_id``, ``public_key_cbor``,
        ``sign_count``, ``attestation_type`` (``"packed"``).

    Raises:
        WebAuthnError: If the signature is invalid or data malformed.
    """
    auth_data: bytes = attestation_object["authData"]
    att_stmt: dict[str, Any] = attestation_object["attStmt"]

    alg: int = att_stmt["alg"]
    sig: bytes = att_stmt["sig"]

    # Build the signature verification input
    sig_input = auth_data + client_data_hash

    # Determine the public key for verification
    x5c = att_stmt.get("x5c")
    if x5c:
        # Full attestation — extract pubkey from the first x5c cert
        from cryptography import x509

        cert_der = x5c[0]
        cert = x509.load_der_x509_certificate(cert_der)
        pub_key = cert.public_key()
    else:
        # Self-attestation — use the credential public key from authData
        cred_data = _extract_credential_data(auth_data)
        pub_key = parse_cose_key(cred_data["public_key_cbor"])

    # Verify signature
    hash_cls = cose_alg_to_hash(alg)

    try:
        if isinstance(pub_key, ec_mod.EllipticCurvePublicKey):
            pub_key.verify(sig, sig_input, ec_mod.ECDSA(hash_cls()))
        elif isinstance(pub_key, RSAPublicKey):
            pub_key.verify(sig, sig_input, PKCS1v15(), hash_cls())
        else:
            raise WebAuthnError("Unsupported public key type for packed attestation")
    except InvalidSignature as exc:
        raise WebAuthnError("Invalid packed attestation signature") from exc

    return _extract_credential_data(auth_data)


def _extract_credential_data(auth_data: bytes) -> dict[str, Any]:
    """Extract credential data from authenticator data.

    Args:
        auth_data: The raw authenticator data bytes.

    Returns:
        Dict with ``credential_id``, ``public_key_cbor``,
        ``sign_count``, and ``aaguid``.

    Raises:
        WebAuthnError: If the AT (attested credential data) flag
            is not set in the authenticator data.
    """
    if len(auth_data) < 37:
        raise WebAuthnError("Authenticator data too short")

    # RP ID hash (32 bytes) + Flags (1 byte) + Sign Count (4 bytes)
    flags = auth_data[32]
    sign_count = struct.unpack(">I", auth_data[33:37])[0]

    # Check AT flag (bit 6)
    if not (flags & 0x40):
        raise WebAuthnError(
            "Authenticator data missing attested credential data (AT flag)"
        )

    # Attested credential data starts at byte 37
    offset = 37
    aaguid = auth_data[offset : offset + 16]
    offset += 16

    cred_id_len = struct.unpack(">H", auth_data[offset : offset + 2])[0]
    offset += 2

    credential_id = auth_data[offset : offset + cred_id_len]
    offset += cred_id_len

    # The remaining bytes are the COSE_Key CBOR
    public_key_cbor = auth_data[offset:]

    return {
        "credential_id": credential_id,
        "public_key_cbor": public_key_cbor,
        "sign_count": sign_count,
        "aaguid": aaguid,
    }
