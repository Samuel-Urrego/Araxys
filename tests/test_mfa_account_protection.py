"""Tests for MFA dependencies with account enumeration protection.

Tests that:
- verify_mfa_code returns "Invalid verification code" when protection enabled
- verify_recovery_code returns "Invalid verification code" when protection enabled
- Original messages preserved when protection disabled
- Original messages preserved when protection config is None
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from araxys.core.config import AccountProtectionConfig

# ── Test: verify_mfa_code with protection enabled ──


@pytest.fixture(autouse=True)
def _cleanup_module_state() -> Any:
    """Reset module-level state after each test to avoid leaks."""
    yield
    import araxys.account_protection.middleware as ap_mw
    import araxys.mfa.dependencies as mfa_deps

    mfa_deps._account_protection_config = None
    ap_mw._event_bus = None


class TestVerifyMFACodeWithProtection:
    """verify_mfa_code with AccountProtectionConfig enabled."""

    @pytest.fixture(autouse=True)
    def _setup_protection(self) -> Any:
        """Set account_protection module-level config to enabled."""
        import araxys.mfa.dependencies as mfa_deps

        config = AccountProtectionConfig(
            enabled=True,
            generic_verification_message="Invalid verification code",
        )
        mfa_deps._account_protection_config = config
        yield
        mfa_deps._account_protection_config = None

    def test_mfa_code_wrong_returns_generic_message(self) -> None:
        """Wrong TOTP code should raise 401 with 'Invalid verification code'."""
        from araxys.mfa.dependencies import verify_mfa_code

        mock_manager = MagicMock()
        mock_manager.verify.return_value = False

        with pytest.raises(HTTPException) as exc_info:
            verify_mfa_code(mock_manager, "secret123", "000000")

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid verification code"

    def test_mfa_code_valid_still_passes(self) -> None:
        """Valid TOTP code should still pass verification."""
        from araxys.mfa.dependencies import verify_mfa_code

        mock_manager = MagicMock()
        mock_manager.verify.return_value = True

        # Should not raise
        verify_mfa_code(mock_manager, "secret123", "123456")


class TestVerifyRecoveryCodeWithProtection:
    """verify_recovery_code with AccountProtectionConfig enabled."""

    @pytest.fixture(autouse=True)
    def _setup_protection(self) -> Any:
        import araxys.mfa.dependencies as mfa_deps

        config = AccountProtectionConfig(
            enabled=True,
            generic_verification_message="Invalid verification code",
        )
        mfa_deps._account_protection_config = config
        yield
        mfa_deps._account_protection_config = None

    def test_recovery_code_wrong_returns_generic_message(self) -> None:
        """Wrong recovery code should raise 401 with 'Invalid verification code'."""
        from araxys.mfa.dependencies import verify_recovery_code

        with pytest.raises(HTTPException) as exc_info:
            verify_recovery_code("FAKE-CODE-1234", ["hash1", "hash2"])

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid verification code"

    def test_recovery_code_valid_still_passes(self) -> None:
        """Valid recovery code should still pass verification."""
        from araxys.mfa.dependencies import verify_recovery_code
        from araxys.mfa.manager import MFAManager

        codes = ["ABCD-EFGH-IJKL"]
        hashed = [MFAManager.hash_recovery_code(c) for c in codes]
        remaining = verify_recovery_code(codes[0], hashed)
        assert len(remaining) == 0


# ── Test: backward compat (protection disabled) ──


class TestVerifyMFACodeWithoutProtection:
    """verify_mfa_code without protection (backward compat)."""

    @pytest.fixture(autouse=True)
    def _ensure_no_protection(self) -> Any:
        import araxys.mfa.dependencies as mfa_deps

        mfa_deps._account_protection_config = None
        yield

    def test_mfa_code_wrong_original_message(self) -> None:
        """Without protection, wrong code should use original 'Invalid MFA code'."""
        from araxys.mfa.dependencies import verify_mfa_code

        mock_manager = MagicMock()
        mock_manager.verify.return_value = False

        with pytest.raises(HTTPException) as exc_info:
            verify_mfa_code(mock_manager, "secret123", "000000")

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid MFA code"

    def test_recovery_code_wrong_original_message(self) -> None:
        """Without protection, wrong recovery code should use original message."""
        from araxys.mfa.dependencies import verify_recovery_code

        with pytest.raises(HTTPException) as exc_info:
            verify_recovery_code("FAKE-CODE", ["hash1"])

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid recovery code"
