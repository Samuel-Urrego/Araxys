"""COSE key parsing utilities for WebAuthn.

Translates COSE_Key CBOR payloads (RFC 8152) into ``cryptography``
library key objects for signature verification.

Supported algorithms:
    - ``-7`` (ES256): ECDSA over P-256 / SHA-256
    - ``-257`` (RS256): RSA PKCS1-v1_5 with SHA-256
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm

from araxys.webauthn.exceptions import COSEAlgorithmError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# COSE key types
_KTY_EC2 = 2
_KTY_RSA = 3

# COSE elliptic curves
_CRV_P256 = 1

# Supported COSE algorithm labels
_COSE_ALG_ES256 = -7
_COSE_ALG_RS256 = -257

# COSE key label constants
_LABEL_KTY = 1
_LABEL_ALG = 3
_LABEL_CRV = -1
_LABEL_X = -2
_LABEL_Y = -3
_LABEL_N = -1  # RSA modulus (reuses label -1 but kty=3)
_LABEL_E = -2  # RSA exponent (reuses label -2 but kty=3)


def cose_alg_to_hash(alg: int) -> type[HashAlgorithm]:
    """Return the hash algorithm class for a given COSE algorithm.

    Supported algorithms:
        - ``-7``: SHA-256
        - ``-257``: SHA-256
    """
    if alg in (_COSE_ALG_ES256, _COSE_ALG_RS256):
        return SHA256
    raise COSEAlgorithmError(alg)


def parse_cose_key(cbor_data: bytes) -> EllipticCurvePublicKey | RSAPublicKey:
    """Parse a COSE_Key CBOR payload into a ``cryptography`` public key.

    Args:
        cbor_data: Raw CBOR-encoded COSE_Key bytes.

    Returns:
        An ``EllipticCurvePublicKey`` (EC2) or ``RSAPublicKey`` (RSA).

    Raises:
        COSEAlgorithmError: If the algorithm is unsupported.
        WebAuthnError: If the COSE key is malformed.
    """
    cose = cast("dict[int, object]", cbor2.loads(cbor_data))

    kty = cose.get(_LABEL_KTY)

    if kty == _KTY_EC2:
        return _parse_ec2_key(cose)
    if kty == _KTY_RSA:
        return _parse_rsa_key(cose)

    alg = cose.get(_LABEL_ALG, 0)
    raise COSEAlgorithmError(cast("int", alg))


def _parse_ec2_key(cose: dict[int, object]) -> EllipticCurvePublicKey:
    """Parse an EC2 (kty=2) COSE key into an ``EllipticCurvePublicKey``."""
    alg = cast("int", cose.get(_LABEL_ALG, 0))
    if alg not in (_COSE_ALG_ES256,):
        raise COSEAlgorithmError(alg)

    crv = cose.get(_LABEL_CRV)
    if crv != _CRV_P256:
        raise COSEAlgorithmError(alg)

    x_bytes = cast("bytes", cose[_LABEL_X])
    y_bytes = cast("bytes", cose[_LABEL_Y])

    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b"\x04" + x_bytes + y_bytes
    )


def _parse_rsa_key(cose: dict[int, object]) -> RSAPublicKey:
    """Parse an RSA (kty=3) COSE key into an ``RSAPublicKey``."""
    alg = cast("int", cose.get(_LABEL_ALG, 0))
    if alg != _COSE_ALG_RS256:
        raise COSEAlgorithmError(alg)

    n_bytes = cast("bytes", cose[_LABEL_N])
    e_bytes = cast("bytes", cose[_LABEL_E])

    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")

    return rsa.RSAPublicNumbers(e, n).public_key()
