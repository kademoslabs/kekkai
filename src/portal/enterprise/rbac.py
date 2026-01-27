"""Role-Based Access Control (RBAC) for enterprise portal.

Security controls:
- ASVS V8.2.1: Function-level authorization
- Deterministic role mapping from SAML attributes
- No default admin accounts
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from kekkai_core import redact

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class Permission(Enum):
    """Available permissions in the system."""

    # Viewer permissions
    VIEW_FINDINGS = "view_findings"
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_REPORTS = "view_reports"

    # Analyst permissions
    CREATE_UPLOAD = "create_upload"
    UPDATE_FINDING_STATUS = "update_finding_status"
    EXPORT_FINDINGS = "export_findings"

    # Admin permissions
    MANAGE_USERS = "manage_users"
    MANAGE_INTEGRATIONS = "manage_integrations"
    VIEW_AUDIT_LOGS = "view_audit_logs"

    # Tenant Admin permissions
    MANAGE_TENANT = "manage_tenant"
    MANAGE_SAML_CONFIG = "manage_saml_config"
    ROTATE_API_KEY = "rotate_api_key"
    DELETE_TENANT = "delete_tenant"


class Role(Enum):
    """Available roles in the system."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"
    TENANT_ADMIN = "tenant_admin"


# Permission matrix: defines which roles have which permissions
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(
        {
            Permission.VIEW_FINDINGS,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_REPORTS,
        }
    ),
    Role.ANALYST: frozenset(
        {
            Permission.VIEW_FINDINGS,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_REPORTS,
            Permission.CREATE_UPLOAD,
            Permission.UPDATE_FINDING_STATUS,
            Permission.EXPORT_FINDINGS,
        }
    ),
    Role.ADMIN: frozenset(
        {
            Permission.VIEW_FINDINGS,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_REPORTS,
            Permission.CREATE_UPLOAD,
            Permission.UPDATE_FINDING_STATUS,
            Permission.EXPORT_FINDINGS,
            Permission.MANAGE_USERS,
            Permission.MANAGE_INTEGRATIONS,
            Permission.VIEW_AUDIT_LOGS,
        }
    ),
    Role.TENANT_ADMIN: frozenset(
        {
            Permission.VIEW_FINDINGS,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_REPORTS,
            Permission.CREATE_UPLOAD,
            Permission.UPDATE_FINDING_STATUS,
            Permission.EXPORT_FINDINGS,
            Permission.MANAGE_USERS,
            Permission.MANAGE_INTEGRATIONS,
            Permission.VIEW_AUDIT_LOGS,
            Permission.MANAGE_TENANT,
            Permission.MANAGE_SAML_CONFIG,
            Permission.ROTATE_API_KEY,
            Permission.DELETE_TENANT,
        }
    ),
}

# SAML attribute to role mapping
DEFAULT_ROLE_MAPPING: dict[str, Role] = {
    "viewer": Role.VIEWER,
    "analyst": Role.ANALYST,
    "admin": Role.ADMIN,
    "tenant_admin": Role.TENANT_ADMIN,
    "tenant-admin": Role.TENANT_ADMIN,
    "tenantadmin": Role.TENANT_ADMIN,
}


@dataclass(frozen=True)
class AuthorizationResult:
    """Result of an authorization check."""

    allowed: bool
    role: Role | None = None
    permission: Permission | None = None
    reason: str | None = None


@dataclass
class UserContext:
    """Context for the current user session."""

    user_id: str
    tenant_id: str
    role: Role
    email: str | None = None
    display_name: str | None = None
    session_id: str | None = None
    permissions: frozenset[Permission] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.permissions:
            object.__setattr__(self, "permissions", ROLE_PERMISSIONS.get(self.role, frozenset()))


class RBACManager:
    """Manages role-based access control decisions."""

    def __init__(
        self,
        role_mapping: dict[str, Role] | None = None,
    ) -> None:
        self._role_mapping = role_mapping or DEFAULT_ROLE_MAPPING.copy()

    def map_role_from_attribute(self, role_attribute: str) -> Role | None:
        """Map a SAML role attribute to a system role.

        Uses deterministic mapping - no user-configurable escalation.
        """
        normalized = role_attribute.lower().strip()
        return self._role_mapping.get(normalized)

    def map_role_from_attributes(self, attributes: dict[str, list[str]]) -> Role:
        """Map role from SAML attributes, defaulting to viewer."""
        role_attrs = attributes.get("role", []) + attributes.get("roles", [])
        role_attrs += attributes.get("group", []) + attributes.get("groups", [])

        for attr in role_attrs:
            mapped = self.map_role_from_attribute(attr)
            if mapped:
                return mapped

        return Role.VIEWER

    def get_permissions(self, role: Role) -> frozenset[Permission]:
        """Get all permissions for a role."""
        return ROLE_PERMISSIONS.get(role, frozenset())

    def has_permission(self, role: Role, permission: Permission) -> bool:
        """Check if a role has a specific permission."""
        return permission in ROLE_PERMISSIONS.get(role, frozenset())

    def authorize(
        self,
        user_context: UserContext,
        required_permission: Permission,
        resource_tenant_id: str | None = None,
    ) -> AuthorizationResult:
        """Authorize an action for a user.

        Args:
            user_context: Current user context with role
            required_permission: Permission needed for the action
            resource_tenant_id: Tenant owning the resource (for cross-tenant checks)

        Returns:
            AuthorizationResult indicating if access is allowed
        """
        if resource_tenant_id and resource_tenant_id != user_context.tenant_id:
            logger.warning(
                "authz.denied.cross_tenant user_id=%s tenant=%s target_tenant=%s permission=%s",
                redact(user_context.user_id),
                user_context.tenant_id,
                resource_tenant_id,
                required_permission.value,
            )
            return AuthorizationResult(
                allowed=False,
                role=user_context.role,
                permission=required_permission,
                reason="Cross-tenant access denied",
            )

        if not self.has_permission(user_context.role, required_permission):
            logger.warning(
                "authz.denied.permission user_id=%s tenant=%s role=%s permission=%s",
                redact(user_context.user_id),
                user_context.tenant_id,
                user_context.role.value,
                required_permission.value,
            )
            return AuthorizationResult(
                allowed=False,
                role=user_context.role,
                permission=required_permission,
                reason=f"Role {user_context.role.value} lacks {required_permission.value}",
            )

        logger.debug(
            "authz.allowed user_id=%s tenant=%s role=%s permission=%s",
            redact(user_context.user_id),
            user_context.tenant_id,
            user_context.role.value,
            required_permission.value,
        )
        return AuthorizationResult(
            allowed=True,
            role=user_context.role,
            permission=required_permission,
        )

    def create_user_context(
        self,
        user_id: str,
        tenant_id: str,
        role: Role,
        email: str | None = None,
        display_name: str | None = None,
        session_id: str | None = None,
    ) -> UserContext:
        """Create a user context with permissions derived from role."""
        return UserContext(
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            email=email,
            display_name=display_name,
            session_id=session_id,
            permissions=self.get_permissions(role),
        )


def require_permission(permission: Permission) -> AuthorizationResult:
    """Decorator helper to check permission before function execution.

    Usage in web handlers:
        result = require_permission(Permission.CREATE_UPLOAD)
        if not result.allowed:
            return unauthorized_response(result.reason)
    """
    return AuthorizationResult(
        allowed=False,
        permission=permission,
        reason=f"Permission {permission.value} required",
    )
