"""Regression tests for enterprise permission matrix.

These tests ensure the permission matrix remains stable and
any changes are intentional and reviewed.
"""

from __future__ import annotations

import pytest

from portal.enterprise.rbac import ROLE_PERMISSIONS, Permission, Role

GOLDEN_PERMISSION_MATRIX = {
    "viewer": [
        "view_findings",
        "view_dashboard",
        "view_reports",
    ],
    "analyst": [
        "view_findings",
        "view_dashboard",
        "view_reports",
        "create_upload",
        "update_finding_status",
        "export_findings",
    ],
    "admin": [
        "view_findings",
        "view_dashboard",
        "view_reports",
        "create_upload",
        "update_finding_status",
        "export_findings",
        "manage_users",
        "manage_integrations",
        "view_audit_logs",
    ],
    "tenant_admin": [
        "view_findings",
        "view_dashboard",
        "view_reports",
        "create_upload",
        "update_finding_status",
        "export_findings",
        "manage_users",
        "manage_integrations",
        "view_audit_logs",
        "manage_tenant",
        "manage_saml_config",
        "rotate_api_key",
        "delete_tenant",
    ],
}


@pytest.mark.regression
class TestPermissionMatrixGolden:
    """Golden tests for permission matrix stability."""

    def test_viewer_permissions_match_golden(self) -> None:
        """Verify viewer permissions match golden snapshot."""
        actual = sorted(p.value for p in ROLE_PERMISSIONS[Role.VIEWER])
        expected = sorted(GOLDEN_PERMISSION_MATRIX["viewer"])
        assert actual == expected, f"Viewer permissions changed: {actual}"

    def test_analyst_permissions_match_golden(self) -> None:
        """Verify analyst permissions match golden snapshot."""
        actual = sorted(p.value for p in ROLE_PERMISSIONS[Role.ANALYST])
        expected = sorted(GOLDEN_PERMISSION_MATRIX["analyst"])
        assert actual == expected, f"Analyst permissions changed: {actual}"

    def test_admin_permissions_match_golden(self) -> None:
        """Verify admin permissions match golden snapshot."""
        actual = sorted(p.value for p in ROLE_PERMISSIONS[Role.ADMIN])
        expected = sorted(GOLDEN_PERMISSION_MATRIX["admin"])
        assert actual == expected, f"Admin permissions changed: {actual}"

    def test_tenant_admin_permissions_match_golden(self) -> None:
        """Verify tenant_admin permissions match golden snapshot."""
        actual = sorted(p.value for p in ROLE_PERMISSIONS[Role.TENANT_ADMIN])
        expected = sorted(GOLDEN_PERMISSION_MATRIX["tenant_admin"])
        assert actual == expected, f"Tenant admin permissions changed: {actual}"


@pytest.mark.regression
class TestRoleHierarchyGolden:
    """Golden tests for role hierarchy stability."""

    def test_viewer_is_subset_of_analyst(self) -> None:
        """Verify viewer permissions are subset of analyst."""
        viewer = ROLE_PERMISSIONS[Role.VIEWER]
        analyst = ROLE_PERMISSIONS[Role.ANALYST]
        assert viewer.issubset(analyst), "Viewer must be subset of analyst"

    def test_analyst_is_subset_of_admin(self) -> None:
        """Verify analyst permissions are subset of admin."""
        analyst = ROLE_PERMISSIONS[Role.ANALYST]
        admin = ROLE_PERMISSIONS[Role.ADMIN]
        assert analyst.issubset(admin), "Analyst must be subset of admin"

    def test_admin_is_subset_of_tenant_admin(self) -> None:
        """Verify admin permissions are subset of tenant_admin."""
        admin = ROLE_PERMISSIONS[Role.ADMIN]
        tenant_admin = ROLE_PERMISSIONS[Role.TENANT_ADMIN]
        assert admin.issubset(tenant_admin), "Admin must be subset of tenant_admin"


@pytest.mark.regression
class TestSensitivePermissionsGolden:
    """Golden tests for sensitive permission restrictions."""

    def test_delete_tenant_only_for_tenant_admin(self) -> None:
        """Verify DELETE_TENANT is restricted to tenant_admin."""
        for role in [Role.VIEWER, Role.ANALYST, Role.ADMIN]:
            assert Permission.DELETE_TENANT not in ROLE_PERMISSIONS[role], (
                f"{role.value} should not have DELETE_TENANT"
            )
        assert Permission.DELETE_TENANT in ROLE_PERMISSIONS[Role.TENANT_ADMIN]

    def test_manage_saml_only_for_tenant_admin(self) -> None:
        """Verify MANAGE_SAML_CONFIG is restricted to tenant_admin."""
        for role in [Role.VIEWER, Role.ANALYST, Role.ADMIN]:
            assert Permission.MANAGE_SAML_CONFIG not in ROLE_PERMISSIONS[role], (
                f"{role.value} should not have MANAGE_SAML_CONFIG"
            )
        assert Permission.MANAGE_SAML_CONFIG in ROLE_PERMISSIONS[Role.TENANT_ADMIN]

    def test_manage_users_requires_admin_or_higher(self) -> None:
        """Verify MANAGE_USERS requires admin or higher."""
        for role in [Role.VIEWER, Role.ANALYST]:
            assert Permission.MANAGE_USERS not in ROLE_PERMISSIONS[role], (
                f"{role.value} should not have MANAGE_USERS"
            )
        assert Permission.MANAGE_USERS in ROLE_PERMISSIONS[Role.ADMIN]
        assert Permission.MANAGE_USERS in ROLE_PERMISSIONS[Role.TENANT_ADMIN]

    def test_view_audit_logs_requires_admin_or_higher(self) -> None:
        """Verify VIEW_AUDIT_LOGS requires admin or higher."""
        for role in [Role.VIEWER, Role.ANALYST]:
            assert Permission.VIEW_AUDIT_LOGS not in ROLE_PERMISSIONS[role], (
                f"{role.value} should not have VIEW_AUDIT_LOGS"
            )
        assert Permission.VIEW_AUDIT_LOGS in ROLE_PERMISSIONS[Role.ADMIN]


@pytest.mark.regression
class TestPermissionEnumStability:
    """Golden tests for permission enum stability."""

    EXPECTED_PERMISSIONS = [
        "view_findings",
        "view_dashboard",
        "view_reports",
        "create_upload",
        "update_finding_status",
        "export_findings",
        "manage_users",
        "manage_integrations",
        "view_audit_logs",
        "manage_tenant",
        "manage_saml_config",
        "rotate_api_key",
        "delete_tenant",
    ]

    def test_all_expected_permissions_exist(self) -> None:
        """Verify all expected permissions exist in enum."""
        actual = {p.value for p in Permission}
        expected = set(self.EXPECTED_PERMISSIONS)
        assert actual == expected, f"Permission enum changed: {actual}"

    def test_no_unexpected_permissions(self) -> None:
        """Verify no unexpected permissions were added."""
        actual = {p.value for p in Permission}
        for perm in actual:
            assert perm in self.EXPECTED_PERMISSIONS, f"Unexpected permission added: {perm}"


@pytest.mark.regression
class TestRoleEnumStability:
    """Golden tests for role enum stability."""

    EXPECTED_ROLES = ["viewer", "analyst", "admin", "tenant_admin"]

    def test_all_expected_roles_exist(self) -> None:
        """Verify all expected roles exist in enum."""
        actual = {r.value for r in Role}
        expected = set(self.EXPECTED_ROLES)
        assert actual == expected, f"Role enum changed: {actual}"
