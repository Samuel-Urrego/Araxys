"""Tests for the RBAC (Role-Based Access Control) module."""

from __future__ import annotations

from araxys.rbac.engine import RBACEngine


class TestRBACEngine:
    """Tests for the RBACEngine core."""

    def test_direct_permission(self) -> None:
        """A directly assigned permission should be granted."""
        engine = RBACEngine()
        engine.add_role("viewer", permissions=["articles:read"])
        assert engine.has_permission(["viewer"], "articles:read")

    def test_missing_permission(self) -> None:
        """An unassigned permission should be denied."""
        engine = RBACEngine()
        engine.add_role("viewer", permissions=["articles:read"])
        assert not engine.has_permission(["viewer"], "articles:write")

    def test_wildcard_resource(self) -> None:
        """'articles:*' should grant any action on articles."""
        engine = RBACEngine()
        engine.add_role("editor", permissions=["articles:*"])
        assert engine.has_permission(["editor"], "articles:read")
        assert engine.has_permission(["editor"], "articles:write")
        assert engine.has_permission(["editor"], "articles:delete")

    def test_super_wildcard(self) -> None:
        """'*' should grant everything."""
        engine = RBACEngine()
        engine.add_role("admin", permissions=["*"])
        assert engine.has_permission(["admin"], "users:read")
        assert engine.has_permission(["admin"], "billing:admin")
        assert engine.has_permission(["admin"], "anything:at-all")

    def test_multiple_roles(self) -> None:
        """A user with multiple roles gets the union of permissions."""
        engine = RBACEngine()
        engine.add_role("viewer", permissions=["articles:read"])
        engine.add_role("commenter", permissions=["comments:write"])
        assert engine.has_permission(["viewer", "commenter"], "articles:read")
        assert engine.has_permission(["viewer", "commenter"], "comments:write")

    def test_inheritance(self) -> None:
        """A role should inherit permissions from parent roles."""
        engine = RBACEngine()
        engine.add_role("viewer", permissions=["articles:read"])
        engine.add_role("editor", permissions=["articles:write"], inherits=["viewer"])
        # editor should have both its own and inherited permissions
        assert engine.has_permission(["editor"], "articles:read")
        assert engine.has_permission(["editor"], "articles:write")

    def test_deep_inheritance(self) -> None:
        """Multi-level inheritance should work (admin → editor → viewer)."""
        engine = RBACEngine()
        engine.add_role("viewer", permissions=["articles:read"])
        engine.add_role("editor", permissions=["articles:write"], inherits=["viewer"])
        engine.add_role("admin", permissions=["*"], inherits=["editor"])
        assert engine.has_permission(["admin"], "articles:read")
        assert engine.has_permission(["admin"], "articles:write")
        assert engine.has_permission(["admin"], "users:delete")

    def test_cycle_detection(self) -> None:
        """Circular inheritance should not cause infinite recursion."""
        engine = RBACEngine()
        engine.add_role("a", permissions=["res:a"], inherits=["b"])
        engine.add_role("b", permissions=["res:b"], inherits=["a"])
        # Should not hang — cycles are detected
        perms_a = engine.get_role_permissions("a")
        # At minimum "a" has its own permission
        assert "res:a" in perms_a

    def test_init_with_roles(self) -> None:
        """RBACEngine should accept initial role definitions."""
        engine = RBACEngine(
            roles={
                "viewer": {"permissions": ["articles:read"]},
                "editor": {
                    "permissions": ["articles:write", "comments:*"],
                    "inherits": ["viewer"],
                },
            }
        )
        assert engine.has_permission(["editor"], "articles:read")
        assert engine.has_permission(["editor"], "articles:write")
        assert engine.has_permission(["editor"], "comments:delete")
        assert not engine.has_permission(["viewer"], "articles:write")

    def test_remove_role(self) -> None:
        """Removing a role should revoke its permissions."""
        engine = RBACEngine()
        engine.add_role("temp", permissions=["secret:access"])
        assert engine.has_permission(["temp"], "secret:access")
        engine.remove_role("temp")
        assert not engine.has_permission(["temp"], "secret:access")

    def test_has_any_permission(self) -> None:
        """has_any_permission should return True if any matches."""
        engine = RBACEngine()
        engine.add_role("user", permissions=["profile:read"])
        assert engine.has_any_permission(["user"], ["admin:access", "profile:read"])
        assert not engine.has_any_permission(["user"], ["admin:access", "billing:read"])

    def test_has_all_permissions(self) -> None:
        """has_all_permissions should only return True if all match."""
        engine = RBACEngine()
        engine.add_role("editor", permissions=["articles:*"])
        assert engine.has_all_permissions(
            ["editor"], ["articles:read", "articles:write"]
        )
        assert not engine.has_all_permissions(
            ["editor"], ["articles:read", "users:write"]
        )

    def test_no_role_assigned(self) -> None:
        """A user with no roles should have no permissions."""
        engine = RBACEngine()
        assert not engine.has_permission([], "anything:read")


class TestRBACDependencies:
    """Tests for FastAPI RBAC dependencies."""

    async def test_require_permission_granted(self) -> None:
        """Dependency should not raise when permission is granted."""
        from araxys.rbac.dependencies import require_permission

        engine = RBACEngine()
        engine.add_role("admin", permissions=["*"])

        dep = require_permission(engine, "users:read", get_roles=lambda: ["admin"])
        await dep()  # Should not raise

    async def test_require_permission_denied(self) -> None:
        """Dependency should raise 403 when permission is denied."""
        import pytest
        from fastapi import HTTPException

        from araxys.rbac.dependencies import require_permission

        engine = RBACEngine()
        engine.add_role("viewer", permissions=["articles:read"])

        dep = require_permission(engine, "users:read", get_roles=lambda: ["viewer"])
        with pytest.raises(HTTPException) as exc:
            await dep()
        assert exc.value.status_code == 403

    async def test_require_permission_passthrough(self) -> None:
        """Dependency with no get_roles should pass through."""
        from araxys.rbac.dependencies import require_permission

        engine = RBACEngine()
        dep = require_permission(engine, "users:read")  # no get_roles
        await dep()  # Should not raise — passthrough
