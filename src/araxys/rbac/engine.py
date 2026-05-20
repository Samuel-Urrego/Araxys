"""RBAC — Role-Based Access Control with hierarchical permissions.

Permissions follow the ``resource:action`` pattern with wildcard
support::

    "users:read"       — read users
    "users:write"      — create/update users
    "users:*"          — any action on users
    "admin:*"          — any action on admin resources
    "*"                — superuser (everything)

Roles are named collections of permissions.  Roles can inherit from
other roles, forming a hierarchy::

    viewer  → ["articles:read"]
    editor  → ["articles:*", "comments:*"], inherits=["viewer"]
    admin   → ["*"], inherits=["editor"]

Usage::

    from araxys.rbac import RBACEngine, require_permission

    engine = RBACEngine()
    engine.add_role("editor", permissions=["articles:*"], inherits=["viewer"])

    @app.get("/articles")
    async def list_articles(
        _: None = Depends(require_permission(engine, "articles:read")),
    ):
        ...
"""

from __future__ import annotations


class RBACEngine:
    """In-memory RBAC engine with hierarchical roles.

    Parameters
    ----------
    roles:
        Optional initial role definitions as ``{name: {permissions, inherits}}``.
    """

    def __init__(
        self,
        roles: dict[str, dict[str, list[str]]] | None = None,
    ) -> None:
        self._roles: dict[str, set[str]] = {}  # role → expanded permissions
        self._direct: dict[str, set[str]] = {}  # role → direct permissions
        self._inherits: dict[str, list[str]] = {}  # role → parent roles
        if roles:
            for name, defn in roles.items():
                perms = defn.get("permissions", [])
                inherits = defn.get("inherits", [])
                self.add_role(name, permissions=perms, inherits=inherits)

    # ── Role Management ──────────────────────────────────────────

    def add_role(
        self,
        name: str,
        permissions: list[str] | None = None,
        inherits: list[str] | None = None,
    ) -> None:
        """Define a role with *permissions* and optional *inherits*."""
        self._direct[name] = set(permissions or [])
        self._inherits[name] = inherits or []
        # Compute expanded permissions (resolve inheritance)
        self._roles[name] = self._expand(name)

    def remove_role(self, name: str) -> None:
        """Remove a role and invalidate dependent caches."""
        self._roles.pop(name, None)
        self._direct.pop(name, None)
        self._inherits.pop(name, None)
        # Re-expand roles that inherit from the removed one
        for other in list(self._inherits):
            if name in self._inherits[other]:
                self._inherits[other].remove(name)
            self._roles[other] = self._expand(other)

    def get_role_permissions(self, role_name: str) -> set[str]:
        """Return the expanded permission set for *role_name*."""
        return self._roles.get(role_name, set())

    # ── Permission Checking ──────────────────────────────────────

    def has_permission(
        self, role_names: list[str], permission: str
    ) -> bool:
        """Check if any given *role_names* grant *permission*.

        Parameters
        ----------
        role_names:
            The user's assigned roles (e.g. ``["editor", "viewer"]``).
        permission:
            The required permission (e.g. ``"articles:write"``).

        Returns
        -------
        bool
            ``True`` if at least one role grants the permission.
        """
        for role in role_names:
            perms = self._roles.get(role, set())
            if self._match(perms, permission):
                return True
        return False

    def has_any_permission(
        self, role_names: list[str], permissions: list[str]
    ) -> bool:
        """Check if any role grants *any* of the given *permissions*."""
        for role in role_names:
            perms = self._roles.get(role, set())
            for perm in permissions:
                if self._match(perms, perm):
                    return True
        return False

    def has_all_permissions(
        self, role_names: list[str], permissions: list[str]
    ) -> bool:
        """Check if roles grant *all* given *permissions*."""
        return all(
            self.has_permission(role_names, perm) for perm in permissions
        )

    # ── Internal ─────────────────────────────────────────────────

    def _expand(
        self, role_name: str, _visited: set[str] | None = None
    ) -> set[str]:
        """Resolve inheritance to compute the full permission set."""
        if _visited is None:
            _visited = set()
        if role_name in _visited:
            return set()  # cycle detected
        _visited.add(role_name)

        expanded: set[str] = set(self._direct.get(role_name, set()))
        for parent in self._inherits.get(role_name, []):
            expanded |= self._expand(parent, _visited.copy())
        return expanded

    @staticmethod
    def _match(granted: set[str], required: str) -> bool:
        """Check if *required* is covered by any *granted* permission.

        Supports wildcards:
        - ``"*"`` matches everything
        - ``"users:*"`` matches ``"users:read"``, ``"users:write"``, etc.
        """
        if "*" in granted:
            return True
        if required in granted:
            return True
        resource, _, _action = required.partition(":")
        wildcard = f"{resource}:*"
        return wildcard in granted
