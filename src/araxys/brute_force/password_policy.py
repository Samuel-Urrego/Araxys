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

    def estimate_strength(self, password: str) -> dict:
        """Estimate password strength (0-4, like zxcvbn).

        Returns a dict with ``score`` (0=weakest, 4=strongest) and
        ``feedback`` (list of human-readable suggestions).
        """
        score = 0
        feedback: list[str] = []
        length = len(password)

        # Length bonus
        if length >= 12:
            score += 2
        elif length >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters")

        # Character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        diversity = sum([has_upper, has_lower, has_digit, has_special])
        if diversity >= 3:
            score += 1
        if diversity < 2:
            feedback.append("Mix uppercase, lowercase, digits, and special chars")

        # Penalty: common patterns
        if self._is_sequential(password):
            score = max(0, score - 2)
            feedback.append("Avoid sequential characters (abc, 123)")
        if self._is_repeated(password):
            score = max(0, score - 2)
            feedback.append("Avoid repeated characters (aaa, 111)")

        # Cap at 4
        score = min(score, 4)

        return {"score": score, "feedback": feedback}

    @staticmethod
    def _is_sequential(s: str) -> bool:
        """Detect 4+ sequential chars (abc, 123, cba, 321)."""
        lower = s.lower()
        for i in range(len(lower) - 3):
            a, b, c, d = map(ord, lower[i : i + 4])
            if b - a == 1 and c - b == 1 and d - c == 1:
                return True
            if a - b == 1 and b - c == 1 and c - d == 1:
                return True
        return False

    @staticmethod
    def _is_repeated(s: str) -> bool:
        """Detect 4+ repeated chars (aaaa, 1111)."""
        lower = s.lower()
        for i in range(len(lower) - 3):
            if lower[i] == lower[i + 1] == lower[i + 2] == lower[i + 3]:
                return True
        return False


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
