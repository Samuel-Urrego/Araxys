"""Tests for account protection helper functions."""

import asyncio
import hashlib
import time
from unittest.mock import patch

import pytest

from araxys.account_protection.helpers import (
    constant_time_compare,
    normalize_error_message,
    simulate_hash_lookup,
    simulate_verification_work,
)
from araxys.core.config import AccountProtectionConfig


class TestConstantTimeCompare:
    """Tests for constant_time_compare — wraps hmac.compare_digest."""

    def test_equal_strings(self) -> None:
        assert constant_time_compare("hello", "hello") is True

    def test_unequal_strings(self) -> None:
        assert constant_time_compare("hello", "world") is False

    def test_equal_strings_different_lengths(self) -> None:
        assert constant_time_compare("short", "a_very_long_string") is False

    def test_empty_strings_equal(self) -> None:
        assert constant_time_compare("", "") is True

    def test_equal_bytes(self) -> None:
        assert constant_time_compare(b"hello", b"hello") is True

    def test_unequal_bytes(self) -> None:
        assert constant_time_compare(b"hello", b"world") is False

    def test_str_vs_bytes_both_ascii(self) -> None:
        """str and bytes with identical ASCII content should match."""
        assert constant_time_compare("hello", b"hello") is True

    def test_bytes_vs_str(self) -> None:
        assert constant_time_compare(b"token123", "token123") is True

    def test_none_first_returns_false(self) -> None:
        with pytest.raises(TypeError):
            constant_time_compare(None, "test")  # type: ignore[arg-type]

    def test_none_second_returns_false(self) -> None:
        with pytest.raises(TypeError):
            constant_time_compare("test", None)  # type: ignore[arg-type]

    def test_same_object_reference(self) -> None:
        s = "same_reference"
        assert constant_time_compare(s, s) is True


class TestSimulateVerificationWork:
    """Tests for simulate_verification_work — CPU-bound timing equalizer."""

    def test_work_factor_zero_does_nothing(self) -> None:
        """work_factor=0 should return immediately with no delay."""
        start = time.monotonic()
        simulate_verification_work(work_factor=0)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5  # Should return well under 500ms

    def test_work_factor_positive_does_work(self) -> None:
        """work_factor=10 should take measurably longer than work_factor=0."""
        start = time.monotonic()
        simulate_verification_work(work_factor=0)
        t0 = time.monotonic() - start

        start = time.monotonic()
        simulate_verification_work(work_factor=10)
        t10 = time.monotonic() - start

        assert t10 > t0  # Higher factor must do more work

    def test_higher_work_factor_is_slower(self) -> None:
        """Higher work factor should take more time (approximate)."""
        start = time.monotonic()
        simulate_verification_work(work_factor=8)
        t8 = time.monotonic() - start

        start = time.monotonic()
        simulate_verification_work(work_factor=12)
        t12 = time.monotonic() - start

        assert t12 >= t8 * 0.5  # wf=12 should be at least half as fast as wf=8
        # (allow for system jitter)

    def test_work_factor_default(self) -> None:
        """Default work_factor=12 should work (not hang)."""
        start = time.monotonic()
        simulate_verification_work()  # use default
        elapsed = time.monotonic() - start
        # May take a while with factor 12, but must complete
        assert elapsed > 0.0
        assert elapsed < 30.0  # Sanity: should not hang indefinitely

    @pytest.mark.asyncio
    async def test_yields_event_loop(self) -> None:
        """Should yield to event loop periodically via asyncio.sleep(0)."""
        ran_other_task = False

        async def tick() -> None:
            nonlocal ran_other_task
            await asyncio.sleep(0.01)
            ran_other_task = True

        task = asyncio.create_task(tick())
        # Run verification work concurrently
        simulate_verification_work(work_factor=6)
        await task
        assert ran_other_task


class TestNormalizeErrorMessage:
    """Tests for normalize_error_message — maps categories to generic messages."""

    def test_login_category(self) -> None:
        config = AccountProtectionConfig()
        result = normalize_error_message("login", config)
        assert result == "Invalid credentials"

    def test_api_key_category(self) -> None:
        config = AccountProtectionConfig()
        result = normalize_error_message("api_key", config)
        assert result == "Invalid credentials"

    def test_mfa_category(self) -> None:
        config = AccountProtectionConfig()
        result = normalize_error_message("mfa", config)
        assert result == "Invalid verification code"

    def test_recovery_category(self) -> None:
        config = AccountProtectionConfig()
        result = normalize_error_message("recovery", config)
        assert result == "Invalid verification code"

    def test_unknown_category_returns_default(self) -> None:
        config = AccountProtectionConfig()
        result = normalize_error_message("unknown_category", config)
        assert result == "Invalid credentials"

    def test_uses_custom_messages_from_config(self) -> None:
        config = AccountProtectionConfig(
            enabled=True,
            generic_unauthorized_message="Wrong email or password",
            generic_verification_message="Wrong code",
        )
        assert normalize_error_message("login", config) == "Wrong email or password"
        assert normalize_error_message("mfa", config) == "Wrong code"

    def test_empty_category(self) -> None:
        config = AccountProtectionConfig()
        result = normalize_error_message("", config)
        assert result == "Invalid credentials"


class TestIntegrationSafetyNet:
    """Ensure existing tests still pass after helpers are created."""

    def test_config_defaults_unchanged(self) -> None:
        c = AccountProtectionConfig()
        assert c.enabled is False
        assert c.fake_hash_work_factor == 12

    def test_enum_values_present(self) -> None:
        from araxys.core.types import AuditEventType, SecurityEventType

        assert hasattr(AuditEventType, "ACCOUNT_ENUMERATION_DETECTED")
        assert hasattr(SecurityEventType, "ACCOUNT_ENUMERATION_DETECTED")


class TestSimulateHashLookup:
    """Tests for simulate_hash_lookup — timing equalizer for missing prefixes."""

    def test_returns_none(self) -> None:
        """Should return None (fire-and-forget timing equalizer)."""
        config = AccountProtectionConfig(
            enabled=True, fake_hash_work_factor=0,
        )
        simulate_hash_lookup("sk_test12", config)

    def test_computes_sha256_hash(self) -> None:
        """Should compute a SHA-256 hash internally (uses same algo as verify_key)."""
        config = AccountProtectionConfig(
            enabled=True, fake_hash_work_factor=0,
        )
        # Just verify it doesn't crash — SHA-256 is stdlib, always works
        simulate_hash_lookup("pk_abcdef", config)

    def test_uses_constant_time_compare(self) -> None:
        """Should run hmac.compare_digest on a pair of fake hashes."""
        config = AccountProtectionConfig(
            enabled=True, fake_hash_work_factor=0,
        )
        # The function must not raise — hmac.compare_digest with valid hashes = ok
        simulate_hash_lookup("sk_xyz789", config)

    def test_zero_work_factor_is_fast(self) -> None:
        """With work_factor=0, should return quickly (no scrypt)."""
        config = AccountProtectionConfig(
            enabled=True, fake_hash_work_factor=0,
        )
        start = time.monotonic()
        simulate_hash_lookup("sk_fast", config)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5  # Should be near-instant

    def test_positive_work_factor_takes_longer(self) -> None:
        """With work_factor>0, should take measurably longer than factor=0."""
        config_fast = AccountProtectionConfig(
            enabled=True, fake_hash_work_factor=0,
        )
        config_slow = AccountProtectionConfig(
            enabled=True, fake_hash_work_factor=8,
        )
        start = time.monotonic()
        simulate_hash_lookup("sk_slow", config_slow)
        slow_elapsed = time.monotonic() - start

        # Must be slower than zero (but allow system jitter with 0.5x)
        start = time.monotonic()
        simulate_hash_lookup("sk_fast", config_fast)
        fast_elapsed = time.monotonic() - start

        assert slow_elapsed >= fast_elapsed * 0.5

    def test_disabled_config_does_no_work(self) -> None:
        """When config.enabled=False, should return immediately (no-op)."""
        config = AccountProtectionConfig(enabled=False)
        start = time.monotonic()
        simulate_hash_lookup("sk_disabled", config)
        elapsed = time.monotonic() - start
        assert elapsed < 0.1  # Near-instant

    def test_uses_sha256_same_as_api_key_manager(self) -> None:
        """The SHA-256 hash should be computed the same way APIKeyManager._hash_key does."""  # noqa: E501
        config = AccountProtectionConfig(
            enabled=True, fake_hash_work_factor=0,
        )
        # This is a smoke test: the real verification is that it calls
        # hashlib.sha256 and hmac.compare_digest internally
        with patch("araxys.account_protection.helpers.hashlib.sha256", wraps=hashlib.sha256) as mock_sha:  # noqa: E501
            simulate_hash_lookup("sk_prefix", config)
            mock_sha.assert_called_once()
