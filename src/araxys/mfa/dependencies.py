"""FastAPI dependencies for MFA (TOTP) enforcement.

Usage::

    from fastapi import Depends, Header
    from araxys.mfa.dependencies import mfa_required

    @app.post("/sensitive-action")
    async def sensitive(
        mfa_code: str = Header(alias="X-MFA-Code"),
        _: None = Depends(mfa_required(secret="USER_SECRET", code_header=...)),
    ):
        ...
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, status

if TYPE_CHECKING:
    from araxys.core.config import AccountProtectionConfig
    from araxys.mfa.manager import MFAManager

# Module-level config set by AraxysShield when account_protection is enabled.
# When set and enabled, error messages are normalized to prevent enumeration.
_account_protection_config: AccountProtectionConfig | None = None


def _get_verification_message() -> str:
    """Return the generic verification message when protection is active."""
    if (
        _account_protection_config is not None
        and _account_protection_config.enabled
    ):
        return _account_protection_config.generic_verification_message
    return ""


def verify_mfa_code(
    mfa_manager: MFAManager,
    secret: str,
    code: str,
) -> None:
    """Verify a TOTP code.  Raises ``HTTPException(401)`` on failure."""
    if not mfa_manager.verify(secret, code):
        msg = _get_verification_message()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=msg or "Invalid MFA code",
            headers={"X-MFA-Required": "true"},
        )


def verify_recovery_code(
    code: str,
    hashed_codes: list[str],
    *,
    save_codes: Any = None,
) -> list[str]:
    """Verify a recovery code and return the updated list.

    Raises ``HTTPException(401)`` on failure.  On success, the used
    code is removed from the list.

    Parameters
    ----------
    code:
        The recovery code entered by the user.
    hashed_codes:
        Current list of SHA-256 hashed recovery codes.
    save_codes:
        Optional async callable to persist the updated codes.
    """
    from araxys.mfa.manager import MFAManager

    valid, remaining = MFAManager.verify_recovery_code(code, hashed_codes)
    if not valid:
        msg = _get_verification_message()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=msg or "Invalid recovery code",
        )
    return remaining
