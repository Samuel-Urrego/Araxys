"""Tests for AccountProtectionMiddleware registration via AraxysShield.

Tests that:
- _register_account_protection is called during shield init
- Middleware is positioned between honeypot and ip_access
- Module-level _event_bus is set when available
- Registration is skipped when protection is disabled
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI

from araxys.core.config import (
    AccountProtectionConfig,
    AraxysConfig,
    IPControlConfig,
)


@pytest.fixture
def minimal_config() -> AraxysConfig:
    """Minimal config with no modules enabled."""
    return AraxysConfig(secret_key="test-secret-key-1234567890abcdef")


@pytest.fixture
def enabled_config() -> AraxysConfig:
    """Config with account_protection enabled and ip_control enabled."""
    return AraxysConfig(
        secret_key="test-secret-key-1234567890abcdef",
        account_protection=AccountProtectionConfig(enabled=True),
        ip_control=IPControlConfig(
            enabled=True,
            mode="block",
            blocklist=["10.0.0.0/8"],
        ),
    )


@pytest.fixture
def disabled_config() -> AraxysConfig:
    """Config with account_protection disabled."""
    return AraxysConfig(
        secret_key="test-secret-key-1234567890abcdef",
        account_protection=AccountProtectionConfig(enabled=False),
    )


class TestShieldRegistration:
    """AccountProtectionMiddleware registration via AraxysShield."""

    @pytest.fixture(autouse=True)
    def _cleanup_module_state(self) -> Any:
        """Reset module-level state after each test to avoid leaks."""
        import araxys.account_protection.middleware as _ap_mw
        import araxys.mfa.dependencies as _mfa_deps

        yield
        _ap_mw._event_bus = None
        _mfa_deps._account_protection_config = None

    async def test_registered_when_enabled(self, enabled_config: AraxysConfig) -> None:
        """Should register AccountProtectionMiddleware when protection is enabled."""
        from araxys.shield import AraxysShield

        app = FastAPI()
        AraxysShield(app, enabled_config)

        middleware_names = [m.cls.__name__ for m in app.user_middleware]
        assert "AccountProtectionMiddleware" in middleware_names

    async def test_skipped_when_disabled(self, disabled_config: AraxysConfig) -> None:
        """Should skip registration when account_protection is not enabled."""
        from araxys.shield import AraxysShield

        app = FastAPI()
        AraxysShield(app, disabled_config)

        middleware_names = [m.cls.__name__ for m in app.user_middleware]
        assert "AccountProtectionMiddleware" not in middleware_names

    async def test_skipped_when_none(self, minimal_config: AraxysConfig) -> None:
        """Should skip registration when account_protection is None."""
        assert minimal_config.account_protection is None
        from araxys.shield import AraxysShield

        app = FastAPI()
        AraxysShield(app, minimal_config)

        middleware_names = [m.cls.__name__ for m in app.user_middleware]
        assert "AccountProtectionMiddleware" not in middleware_names

    async def test_middleware_order_between_honeypot_and_ip_access(
        self, enabled_config: AraxysConfig
    ) -> None:
        """AccountProtectionMiddleware should be between honeypot and ip_access.

        Middleware order (from outermost to innermost):
        ... cors → secure_headers → telemetry → rate_limit → brute_force →
            ip_access → account_protection → honeypot → malware → ...
        Since Starlette registers in reverse, we check the stack from
        app.user_middleware (last added = first executed).
        """
        from araxys.shield import AraxysShield

        app = FastAPI()
        AraxysShield(app, enabled_config)

        names = [m.cls.__name__ for m in app.user_middleware]
        # Registration order (last = outermost):
        # sanitize, prompt_injection, malware, honeypot,
        #   account_protection,  # NEW
        # ip_access, brute_force, rate_limit, telemetry, secure_headers, cors

        assert "AccountProtectionMiddleware" in names
        ap_idx = names.index("AccountProtectionMiddleware")
        honeypot_idx = names.index("HoneypotMiddleware")
        ip_access_idx = names.index("IPAccessMiddleware")

        # Starlette's add_middleware uses insert(0, ...) so user_middleware
        # is in REVERSE registration order: [0] = outermost, [-1] = innermost.
        # Registration order: Sanitize → Honeypot → AccountProtection → IPAccess → ...
        # user_middleware order: ... → IPAccess → AccountProtection → Honeypot → Sanitize  # noqa: E501
        # So AccountProtection should have a LOWER index than Honeypot
        # (the deepest/most recently inserted) and HIGHER than IPAccess.
        assert ap_idx < honeypot_idx, (
            f"AccountProtectionMiddleware at {ap_idx} should have lower index "
            f"than HoneypotMiddleware at {honeypot_idx} "
            f"(outermost → innermost: {names})"
        )
        assert ap_idx > ip_access_idx, (
            f"AccountProtectionMiddleware at {ap_idx} should have higher index "
            f"than IPAccessMiddleware at {ip_access_idx} "
            f"(outermost → innermost: {names})"
        )

    async def test_event_bus_wired_when_available(
        self, enabled_config: AraxysConfig
    ) -> None:
        """Module-level _event_bus should be set when event bus exists."""
        # This requires event bus to be created (webhooks enabled)
        from araxys.core.config import WebhookConfig
        from araxys.shield import AraxysShield

        config = AraxysConfig(
            secret_key="test-secret-key-1234567890abcdef",
            account_protection=AccountProtectionConfig(enabled=True),
            webhooks=WebhookConfig(
                enabled=True,
                urls={"account_enumeration_detected": ["https://hooks.example.com"]},
            ),
        )
        app = FastAPI()
        shield = AraxysShield(app, config)

        # Check the middleware module has _event_bus set
        import araxys.account_protection.middleware as ap_mw

        assert ap_mw._event_bus is not None  # noqa: SLF001
        assert ap_mw._event_bus is shield.event_bus  # noqa: SLF001

    async def test_event_bus_not_set_when_no_event_bus(
        self, enabled_config: AraxysConfig
    ) -> None:
        """Module-level _event_bus should remain None when no event bus."""
        # enabled_config has no webhooks, so no event bus
        from araxys.shield import AraxysShield

        app = FastAPI()
        assert enabled_config.webhooks is None
        AraxysShield(app, enabled_config)

        import araxys.account_protection.middleware as ap_mw

        assert ap_mw._event_bus is None  # noqa: SLF001
