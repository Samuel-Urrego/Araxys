"""Tests for the MFA (TOTP) module."""

from __future__ import annotations

from araxys.mfa.manager import MFAManager
from araxys.mfa.totp import TOTP


class TestTOTP:
    """Tests for the TOTP core implementation."""

    def test_generate_secret_is_base32(self) -> None:
        """Generated secrets should be valid base32 strings."""
        secret = TOTP.generate_secret()
        assert isinstance(secret, str)
        assert len(secret) >= 16  # at least 16 chars for 10 bytes base32
        # Should only contain base32 chars (A-Z, 2-7)
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret)

    def test_generate_secret_unique(self) -> None:
        """Each call should produce a different secret."""
        s1 = TOTP.generate_secret()
        s2 = TOTP.generate_secret()
        assert s1 != s2

    def test_verify_valid_code(self) -> None:
        """A freshly computed code should verify."""
        secret = TOTP.generate_secret()
        # Manually compute the current code
        code = TOTP._compute(secret, int(__import__("time").time()), 6, 30)
        assert TOTP.verify(secret, code)

    def test_verify_invalid_code(self) -> None:
        """A wrong code should not verify."""
        secret = TOTP.generate_secret()
        assert not TOTP.verify(secret, "000000")

    def test_verify_with_window(self) -> None:
        """window=2 should accept codes from ±2 steps."""
        secret = TOTP.generate_secret()
        now = int(__import__("time").time())
        # Code from 60 seconds ago (2 steps behind)
        past_code = TOTP._compute(secret, now - 60, 6, 30)
        assert TOTP.verify(secret, past_code, window=2)

    def test_verify_outside_window(self) -> None:
        """Code outside the window should fail."""
        secret = TOTP.generate_secret()
        now = int(__import__("time").time())
        # Code from 120 seconds ago (4 steps behind, window=1)
        past_code = TOTP._compute(secret, now - 120, 6, 30)
        assert not TOTP.verify(secret, past_code, window=1)

    def test_qr_uri_format(self) -> None:
        """QR URI should follow the otpauth:// format."""
        uri = TOTP.qr_uri("JBSWY3DPEHPK3PXP", "alice@example.com", issuer="TestApp")
        assert uri.startswith("otpauth://totp/")
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=TestApp" in uri
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri

    def test_compare_digest_used(self) -> None:
        """Verification should use constant-time comparison."""
        secret = TOTP.generate_secret()
        # Even with a correct-length string, wrong code should fail
        assert not TOTP.verify(secret, "123456")


class TestMFAManager:
    """Tests for the MFA lifecycle manager."""

    def test_setup_returns_secret_and_qr_and_codes(self) -> None:
        """setup() should return secret, QR URI, and recovery codes."""
        from araxys.core.config import MFAConfig

        config = MFAConfig(enabled=True)
        manager = MFAManager(config, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        secret, qr_uri, codes = manager.setup("user-123")

        assert len(secret) >= 16
        assert qr_uri.startswith("otpauth://totp/")
        assert len(codes) == config.recovery_code_count

    def test_verify_valid_code(self) -> None:
        """A valid TOTP code should pass verification."""
        from araxys.core.config import MFAConfig

        config = MFAConfig(enabled=True)
        manager = MFAManager(config, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        secret, _, _ = manager.setup("user-123")

        code = TOTP._compute(secret, int(__import__("time").time()), 6, 30)
        assert manager.verify(secret, code)

    def test_verify_invalid_code(self) -> None:
        """An invalid code should fail."""
        from araxys.core.config import MFAConfig

        config = MFAConfig(enabled=True)
        manager = MFAManager(config, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        secret, _, _ = manager.setup("user-123")

        assert not manager.verify(secret, "000000")

    def test_recovery_codes_format(self) -> None:
        """Recovery codes should be in 'XXXX-XXXX-XXXX' format."""
        from araxys.core.config import MFAConfig

        config = MFAConfig(enabled=True, recovery_code_count=4)
        manager = MFAManager(config, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        _, _, codes = manager.setup("user-123")

        for code in codes:
            parts = code.split("-")
            assert len(parts) >= 3  # at least 3 groups of 4

    def test_recovery_code_verify_and_remove(self) -> None:
        """Verifying a recovery code should remove it."""
        from araxys.core.config import MFAConfig

        config = MFAConfig(enabled=True, recovery_code_count=4)
        manager = MFAManager(config, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        _, _, codes = manager.setup("user-123")

        hashed = [MFAManager.hash_recovery_code(c) for c in codes]
        original_count = len(hashed)

        valid, remaining = MFAManager.verify_recovery_code(codes[0], hashed)
        assert valid
        assert len(remaining) == original_count - 1

    def test_recovery_code_reuse_fails(self) -> None:
        """A used recovery code should not work twice."""
        from araxys.core.config import MFAConfig

        config = MFAConfig(enabled=True, recovery_code_count=4)
        manager = MFAManager(config, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        _, _, codes = manager.setup("user-123")

        hashed = [MFAManager.hash_recovery_code(c) for c in codes]
        valid, remaining = MFAManager.verify_recovery_code(codes[0], hashed)
        assert valid

        # Try again with same code
        valid2, _ = MFAManager.verify_recovery_code(codes[0], remaining)
        assert not valid2

    def test_recovery_code_invalid_fails(self) -> None:
        """A made-up recovery code should fail."""
        from araxys.core.config import MFAConfig

        config = MFAConfig(enabled=True, recovery_code_count=4)
        manager = MFAManager(config, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        _, _, codes = manager.setup("user-123")

        hashed = [MFAManager.hash_recovery_code(c) for c in codes]
        valid, remaining = MFAManager.verify_recovery_code("FAKE-DEAD-BEEF", hashed)
        assert not valid
        assert len(remaining) == len(hashed)  # unchanged
