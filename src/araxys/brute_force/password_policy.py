"""Password policy validation and HIBP breach checking.

Provides a stateless ``PasswordPolicy`` validator with configurable
complexity rules and an optional HaveIBeenPwned (HIBP) k-anonymity
check via the HIBP API.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from araxys.core.exceptions import PasswordValidationError

if TYPE_CHECKING:
    from starlette.requests import Request


# ── Password Policy Config ─────────────────────────────────────────────────


class PasswordPolicyConfig(BaseModel):
    """Configuration for password complexity rules.

    Each rule can be independently enabled/disabled. Setting a rule
    to ``False`` skips that check.
    """

    min_length: int = Field(default=8, ge=1, description="Minimum password length")
    max_length: int = Field(
        default=128, ge=1, description="Maximum password length"
    )
    require_uppercase: bool = Field(
        default=True, description="Require at least one uppercase letter"
    )
    require_lowercase: bool = Field(
        default=True, description="Require at least one lowercase letter"
    )
    require_digit: bool = Field(
        default=True, description="Require at least one digit"
    )
    require_special: bool = Field(
        default=True, description="Require at least one special character"
    )
    check_hibp: bool = Field(
        default=False,
        description="Check password against HaveIBeenPwned API",
    )


# ── Password Policy ────────────────────────────────────────────────────────


class PasswordPolicy:
    """Stateless password validation policy.

    Validates passwords against a set of configurable complexity rules.
    Each rule produces a human-readable error message when violated.

    Parameters
    ----------
    config:
        The password policy configuration.
    """

    def __init__(self, config: PasswordPolicyConfig) -> None:
        self._config = config

    def validate(self, password: str) -> list[str]:
        """Validate a password against all configured rules.

        Returns a list of error messages (one per failed rule).
        An empty list means the password is valid.

        Parameters
        ----------
        password:
            The password to validate.
        """
        errors: list[str] = []
        cfg = self._config

        if len(password) < cfg.min_length:
            errors.append(
                f"Password must be at least {cfg.min_length} characters"
            )

        if len(password) > cfg.max_length:
            errors.append(
                f"Password must be at most {cfg.max_length} characters"
            )

        if cfg.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if cfg.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if cfg.require_digit and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if cfg.require_special and not any(
            not c.isalnum() for c in password
        ):
            errors.append(
                "Password must contain at least one special character"
            )

        return errors


# ── HIBP Check ──────────────────────────────────────────────────────────────


async def check_hibp(password: str) -> bool:
    """Check if a password appears in known breaches via the HIBP API.

    Uses the k-anonymity model: sends only the first 5 characters of
    the SHA-1 hash to the API, then checks whether the remaining
    hash suffix appears in the response.

    Parameters
    ----------
    password:
        The password to check.

    Returns
    -------
    ``True`` if the password appears in a known breach, ``False``
    if it was not found or the API call fails.
    """
    try:
        import httpx

        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
                timeout=5.0,
            )
            response.raise_for_status()
            body = response.text
            for line in body.splitlines():
                line_hash_suffix, count = line.split(":")
                if line_hash_suffix.strip() == suffix:
                    return True
        return False
    except Exception:
        # Fail open: if the API is unreachable, don't block the request
        return False


# ── FastAPI Dependency ────────────────────────────────────────────────────────


def password_policy_dependency(config: PasswordPolicyConfig) -> Any:
    """FastAPI dependency that validates the ``password`` field in request body.

    Usage::

        from fastapi import Depends
        from araxys.brute_force.password_policy import (
            PasswordPolicyConfig,
            password_policy_dependency,
        )

        @app.post("/register")
        async def register(
            _: None = Depends(
                password_policy_dependency(PasswordPolicyConfig())
            ),
            ...
        ):
            ...

    Parameters
    ----------
    config:
        The password policy configuration.
    """

    policy = PasswordPolicy(config)

    async def dependency(request: Request) -> None:
        body = await request.json()
        password = body.get("password", "")
        errors = policy.validate(password)
        if errors:
            raise PasswordValidationError(errors)

    return dependency
