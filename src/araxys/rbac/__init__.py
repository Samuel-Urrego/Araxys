"""RBAC — Hierarchical Role-Based Access Control.

Provides a lightweight, zero-dependency RBAC engine with:
- ``resource:action`` permission strings with wildcards
- Hierarchical role inheritance
- FastAPI dependency for endpoint protection
"""

from araxys.rbac.dependencies import (
    require_all_permissions,
    require_any_permission,
    require_permission,
)
from araxys.rbac.engine import RBACEngine

__all__ = [
    "RBACEngine",
    "require_permission",
    "require_any_permission",
    "require_all_permissions",
]
