"""MFA — Multi-Factor Authentication (TOTP) for Araxys.

Provides RFC 6238 TOTP with zero external dependencies, plus
one-time recovery codes.

Modules:
    - ``totp.py`` — TOTP generation, QR URI, and verification
    - ``manager.py`` — Full MFA lifecycle manager
    - ``dependencies.py`` — FastAPI dependency for MFA enforcement
    - ``models.py`` — Pydantic data models
"""

from araxys.mfa.manager import MFAManager
from araxys.mfa.totp import TOTP

__all__ = ["MFAManager", "TOTP"]
