"""Role-Based Access Control (RBAC).

Two roles exist: ``admin`` and ``user``.  Permission checks are centralised so
both the GUI (to hide/disable controls) and the service layer (to reject
unauthorised operations) share one source of truth defined in
``utils.constants.PERMISSIONS``.
"""

from __future__ import annotations

from utils.constants import PERMISSIONS, Role


def has_permission(role: str, permission: str) -> bool:
    """Return True if ``role`` is granted ``permission``."""
    role_perms = PERMISSIONS.get(role, PERMISSIONS[Role.USER.value])
    return bool(role_perms.get(permission, False))


def permitted_pages(role: str) -> dict:
    """Return a mapping of GUI pages -> whether the role can open them."""
    is_admin = role == Role.ADMIN.value
    return {
        "dashboard": True,
        "scanner": True,
        "monitoring": True,
        "connections": True,
        "alerts": True,
        "mitigation": True,
        "logs": True,
        "reports": True,
        "users": is_admin,
        "settings": is_admin,
        "help": True,
        "about": True,
    }


class PermissionError(Exception):
    """Raised when an operation is attempted without the required permission."""


def require(role: str, permission: str) -> None:
    """Raise :class:`PermissionError` if ``role`` lacks ``permission``."""
    if not has_permission(role, permission):
        raise PermissionError(
            f"Role '{role}' is not permitted to perform '{permission}'."
        )
