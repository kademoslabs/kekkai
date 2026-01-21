"""Unit tests for enterprise RBAC module."""

from __future__ import annotations

import pytest

from portal.enterprise.rbac import (
    ROLE_PERMISSIONS,
    Permission,
    RBACManager,
    Role,
    UserContext,
)


class TestRolePermissions:
    """Tests for role-permission mappings."""

    def test_viewer_has_read_permissions(self) -> None:
        perms = ROLE_PERMISSIONS[Role.VIEWER]
        assert Permission.VIEW_FINDINGS in perms
        assert Permission.VIEW_DASHBOARD in perms
        assert Permission.VIEW_REPORTS in perms

    def test_viewer_lacks_write_permissions(self) -> None:
        perms = ROLE_PERMISSIONS[Role.VIEWER]
        assert Permission.CREATE_UPLOAD not in perms
        assert Permission.MANAGE_USERS not in perms
        assert Permission.DELETE_TENANT not in perms

    def test_analyst_includes_viewer_permissions(self) -> None:
        viewer_perms = ROLE_PERMISSIONS[Role.VIEWER]
        analyst_perms = ROLE_PERMISSIONS[Role.ANALYST]
        assert viewer_perms.issubset(analyst_perms)

    def test_analyst_has_upload_permission(self) -> None:
        perms = ROLE_PERMISSIONS[Role.ANALYST]
        assert Permission.CREATE_UPLOAD in perms
        assert Permission.UPDATE_FINDING_STATUS in perms

    def test_admin_has_management_permissions(self) -> None:
        perms = ROLE_PERMISSIONS[Role.ADMIN]
        assert Permission.MANAGE_USERS in perms
        assert Permission.VIEW_AUDIT_LOGS in perms
        assert Permission.MANAGE_INTEGRATIONS in perms

    def test_admin_lacks_tenant_admin_permissions(self) -> None:
        perms = ROLE_PERMISSIONS[Role.ADMIN]
        assert Permission.DELETE_TENANT not in perms
        assert Permission.MANAGE_TENANT not in perms

    def test_tenant_admin_has_all_permissions(self) -> None:
        perms = ROLE_PERMISSIONS[Role.TENANT_ADMIN]
        assert Permission.DELETE_TENANT in perms
        assert Permission.MANAGE_SAML_CONFIG in perms
        assert Permission.ROTATE_API_KEY in perms


class TestRBACManager:
    """Tests for RBAC manager."""

    @pytest.fixture
    def rbac(self) -> RBACManager:
        return RBACManager()

    def test_map_role_from_attribute_viewer(self, rbac: RBACManager) -> None:
        assert rbac.map_role_from_attribute("viewer") == Role.VIEWER
        assert rbac.map_role_from_attribute("VIEWER") == Role.VIEWER

    def test_map_role_from_attribute_admin(self, rbac: RBACManager) -> None:
        assert rbac.map_role_from_attribute("admin") == Role.ADMIN

    def test_map_role_from_attribute_tenant_admin_variants(self, rbac: RBACManager) -> None:
        assert rbac.map_role_from_attribute("tenant_admin") == Role.TENANT_ADMIN
        assert rbac.map_role_from_attribute("tenant-admin") == Role.TENANT_ADMIN
        assert rbac.map_role_from_attribute("tenantadmin") == Role.TENANT_ADMIN

    def test_map_role_from_attribute_unknown_returns_none(self, rbac: RBACManager) -> None:
        assert rbac.map_role_from_attribute("superuser") is None
        assert rbac.map_role_from_attribute("root") is None

    def test_map_role_from_attributes_defaults_to_viewer(self, rbac: RBACManager) -> None:
        role = rbac.map_role_from_attributes({})
        assert role == Role.VIEWER

    def test_map_role_from_attributes_uses_role_key(self, rbac: RBACManager) -> None:
        role = rbac.map_role_from_attributes({"role": ["admin"]})
        assert role == Role.ADMIN

    def test_map_role_from_attributes_uses_group_key(self, rbac: RBACManager) -> None:
        role = rbac.map_role_from_attributes({"group": ["analyst"]})
        assert role == Role.ANALYST

    def test_has_permission_returns_true_for_valid(self, rbac: RBACManager) -> None:
        assert rbac.has_permission(Role.VIEWER, Permission.VIEW_FINDINGS) is True
        assert rbac.has_permission(Role.ADMIN, Permission.MANAGE_USERS) is True

    def test_has_permission_returns_false_for_invalid(self, rbac: RBACManager) -> None:
        assert rbac.has_permission(Role.VIEWER, Permission.CREATE_UPLOAD) is False


class TestAuthorize:
    """Tests for authorization checks."""

    @pytest.fixture
    def rbac(self) -> RBACManager:
        return RBACManager()

    @pytest.fixture
    def viewer_context(self, rbac: RBACManager) -> UserContext:
        return rbac.create_user_context(
            user_id="user1",
            tenant_id="tenant_a",
            role=Role.VIEWER,
        )

    @pytest.fixture
    def admin_context(self, rbac: RBACManager) -> UserContext:
        return rbac.create_user_context(
            user_id="admin1",
            tenant_id="tenant_a",
            role=Role.ADMIN,
        )

    def test_authorize_viewer_can_view(
        self, rbac: RBACManager, viewer_context: UserContext
    ) -> None:
        result = rbac.authorize(viewer_context, Permission.VIEW_FINDINGS)
        assert result.allowed is True
        assert result.role == Role.VIEWER

    def test_authorize_viewer_cannot_upload(
        self, rbac: RBACManager, viewer_context: UserContext
    ) -> None:
        result = rbac.authorize(viewer_context, Permission.CREATE_UPLOAD)
        assert result.allowed is False
        assert "lacks" in (result.reason or "")

    def test_authorize_admin_can_manage_users(
        self, rbac: RBACManager, admin_context: UserContext
    ) -> None:
        result = rbac.authorize(admin_context, Permission.MANAGE_USERS)
        assert result.allowed is True

    def test_authorize_cross_tenant_denied(
        self, rbac: RBACManager, admin_context: UserContext
    ) -> None:
        result = rbac.authorize(
            admin_context,
            Permission.VIEW_FINDINGS,
            resource_tenant_id="tenant_b",
        )
        assert result.allowed is False
        assert "Cross-tenant" in (result.reason or "")

    def test_authorize_same_tenant_allowed(
        self, rbac: RBACManager, admin_context: UserContext
    ) -> None:
        result = rbac.authorize(
            admin_context,
            Permission.VIEW_FINDINGS,
            resource_tenant_id="tenant_a",
        )
        assert result.allowed is True


class TestUserContext:
    """Tests for user context creation."""

    def test_user_context_has_permissions_from_role(self) -> None:
        ctx = UserContext(
            user_id="u1",
            tenant_id="t1",
            role=Role.ANALYST,
        )
        assert Permission.CREATE_UPLOAD in ctx.permissions
        assert Permission.VIEW_FINDINGS in ctx.permissions

    def test_user_context_dataclass_fields(self) -> None:
        ctx = UserContext(
            user_id="u1",
            tenant_id="t1",
            role=Role.VIEWER,
            email="user@example.com",
            display_name="Test User",
            session_id="sess123",
        )
        assert ctx.user_id == "u1"
        assert ctx.tenant_id == "t1"
        assert ctx.email == "user@example.com"
        assert ctx.display_name == "Test User"
        assert ctx.session_id == "sess123"


class TestPermissionMatrix:
    """Regression tests for the permission matrix."""

    def test_all_roles_have_permissions(self) -> None:
        for role in Role:
            assert role in ROLE_PERMISSIONS
            assert len(ROLE_PERMISSIONS[role]) > 0

    def test_role_hierarchy(self) -> None:
        """Ensure roles form a proper hierarchy."""
        viewer = ROLE_PERMISSIONS[Role.VIEWER]
        analyst = ROLE_PERMISSIONS[Role.ANALYST]
        admin = ROLE_PERMISSIONS[Role.ADMIN]
        tenant_admin = ROLE_PERMISSIONS[Role.TENANT_ADMIN]

        assert viewer.issubset(analyst)
        assert analyst.issubset(admin)
        assert admin.issubset(tenant_admin)

    def test_tenant_admin_only_permissions(self) -> None:
        """Verify tenant admin exclusive permissions."""
        tenant_only = {
            Permission.MANAGE_TENANT,
            Permission.MANAGE_SAML_CONFIG,
            Permission.ROTATE_API_KEY,
            Permission.DELETE_TENANT,
        }
        for perm in tenant_only:
            assert perm in ROLE_PERMISSIONS[Role.TENANT_ADMIN]
            assert perm not in ROLE_PERMISSIONS[Role.ADMIN]
