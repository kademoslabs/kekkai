"""Integration tests for RBAC enforcement across portal operations."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from portal.enterprise.audit import AuditEventType, AuditLog
from portal.enterprise.rbac import (
    Permission,
    RBACManager,
    Role,
)
from portal.tenants import TenantStore


def make_environ(
    method: str = "GET",
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    client_ip: str = "127.0.0.1",
) -> dict[str, Any]:
    """Create a WSGI environ dict for testing."""
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "REMOTE_ADDR": client_ip,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8000",
    }
    if headers:
        for key, value in headers.items():
            wsgi_key = f"HTTP_{key.upper().replace('-', '_')}"
            environ[wsgi_key] = value
    if body:
        environ["CONTENT_LENGTH"] = len(body)
        environ["wsgi.input"] = BytesIO(body)
    else:
        environ["CONTENT_LENGTH"] = 0
        environ["wsgi.input"] = BytesIO(b"")
    return environ


@pytest.mark.integration
class TestRBACEnforcement:
    """Integration tests for RBAC enforcement."""

    @pytest.fixture
    def rbac(self) -> RBACManager:
        return RBACManager()

    @pytest.fixture
    def tenant_store(self) -> Generator[TenantStore, None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            store.create(
                tenant_id="rbac_tenant",
                name="RBAC Test Corp",
                dojo_product_id=100,
                dojo_engagement_id=1000,
            )
            yield store

    @pytest.fixture
    def audit_log(self) -> Generator[AuditLog, None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            yield AuditLog(log_path=log_path)

    def test_viewer_can_only_read(self, rbac: RBACManager) -> None:
        """NEGATIVE TEST: Viewer cannot write."""
        user = rbac.create_user_context(
            user_id="viewer@test.com",
            tenant_id="rbac_tenant",
            role=Role.VIEWER,
        )

        assert rbac.authorize(user, Permission.VIEW_FINDINGS).allowed
        assert rbac.authorize(user, Permission.VIEW_DASHBOARD).allowed
        assert rbac.authorize(user, Permission.VIEW_REPORTS).allowed

        assert not rbac.authorize(user, Permission.CREATE_UPLOAD).allowed
        assert not rbac.authorize(user, Permission.MANAGE_USERS).allowed
        assert not rbac.authorize(user, Permission.DELETE_TENANT).allowed

    def test_analyst_can_upload_but_not_manage(self, rbac: RBACManager) -> None:
        """Test analyst permissions boundary."""
        user = rbac.create_user_context(
            user_id="analyst@test.com",
            tenant_id="rbac_tenant",
            role=Role.ANALYST,
        )

        assert rbac.authorize(user, Permission.CREATE_UPLOAD).allowed
        assert rbac.authorize(user, Permission.UPDATE_FINDING_STATUS).allowed
        assert rbac.authorize(user, Permission.EXPORT_FINDINGS).allowed

        assert not rbac.authorize(user, Permission.MANAGE_USERS).allowed
        assert not rbac.authorize(user, Permission.VIEW_AUDIT_LOGS).allowed

    def test_admin_can_manage_but_not_tenant_admin(self, rbac: RBACManager) -> None:
        """Test admin permissions boundary."""
        user = rbac.create_user_context(
            user_id="admin@test.com",
            tenant_id="rbac_tenant",
            role=Role.ADMIN,
        )

        assert rbac.authorize(user, Permission.MANAGE_USERS).allowed
        assert rbac.authorize(user, Permission.VIEW_AUDIT_LOGS).allowed
        assert rbac.authorize(user, Permission.MANAGE_INTEGRATIONS).allowed

        assert not rbac.authorize(user, Permission.MANAGE_TENANT).allowed
        assert not rbac.authorize(user, Permission.DELETE_TENANT).allowed
        assert not rbac.authorize(user, Permission.MANAGE_SAML_CONFIG).allowed

    def test_tenant_admin_has_full_access(self, rbac: RBACManager) -> None:
        """Test tenant admin has all permissions."""
        user = rbac.create_user_context(
            user_id="tenant_admin@test.com",
            tenant_id="rbac_tenant",
            role=Role.TENANT_ADMIN,
        )

        for perm in Permission:
            result = rbac.authorize(user, perm)
            assert result.allowed, f"Tenant admin should have {perm.value}"


@pytest.mark.integration
class TestCrossTenantRBACEnforcement:
    """Integration tests for cross-tenant RBAC enforcement."""

    @pytest.fixture
    def rbac(self) -> RBACManager:
        return RBACManager()

    def test_cross_tenant_access_denied_for_all_roles(self, rbac: RBACManager) -> None:
        """NEGATIVE TEST: No role can access another tenant's resources."""
        for role in Role:
            user = rbac.create_user_context(
                user_id=f"{role.value}@tenant_a.com",
                tenant_id="tenant_a",
                role=role,
            )

            result = rbac.authorize(
                user,
                Permission.VIEW_FINDINGS,
                resource_tenant_id="tenant_b",
            )
            assert not result.allowed, f"{role.value} should not access tenant_b"
            assert "Cross-tenant" in (result.reason or "")

    def test_same_tenant_access_allowed(self, rbac: RBACManager) -> None:
        """Test same tenant access is allowed."""
        user = rbac.create_user_context(
            user_id="user@tenant_a.com",
            tenant_id="tenant_a",
            role=Role.ANALYST,
        )

        result = rbac.authorize(
            user,
            Permission.VIEW_FINDINGS,
            resource_tenant_id="tenant_a",
        )
        assert result.allowed


@pytest.mark.integration
class TestRBACWithAuditLogging:
    """Integration tests for RBAC with audit logging."""

    @pytest.fixture
    def rbac(self) -> RBACManager:
        return RBACManager()

    @pytest.fixture
    def audit_log(self) -> Generator[AuditLog, None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            yield AuditLog(log_path=log_path)

    def test_authz_denial_logged(self, rbac: RBACManager, audit_log: AuditLog) -> None:
        """Verify authorization denials are logged."""
        user = rbac.create_user_context(
            user_id="viewer@test.com",
            tenant_id="test_tenant",
            role=Role.VIEWER,
        )

        result = rbac.authorize(user, Permission.MANAGE_USERS)
        assert not result.allowed

        audit_log.log_authz_denied(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            permission=Permission.MANAGE_USERS.value,
            client_ip="192.168.1.100",
        )

        events = audit_log.read_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "authz.denied"
        assert events[0]["action"] == "manage_users"

    def test_cross_tenant_denial_logged(self, rbac: RBACManager, audit_log: AuditLog) -> None:
        """Verify cross-tenant denials are logged."""
        user = rbac.create_user_context(
            user_id="admin@tenant_a.com",
            tenant_id="tenant_a",
            role=Role.ADMIN,
        )

        result = rbac.authorize(
            user,
            Permission.VIEW_FINDINGS,
            resource_tenant_id="tenant_b",
        )
        assert not result.allowed

        audit_log.log_authz_denied(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            permission=Permission.VIEW_FINDINGS.value,
            resource_type="tenant",
            resource_id="tenant_b",
            cross_tenant_attempt=True,
        )

        events = audit_log.read_events()
        assert len(events) == 1
        assert events[0]["details"].get("cross_tenant_attempt") is True


@pytest.mark.integration
class TestRBACRoleMapping:
    """Integration tests for SAML to RBAC role mapping."""

    @pytest.fixture
    def rbac(self) -> RBACManager:
        return RBACManager()

    def test_standard_role_mapping(self, rbac: RBACManager) -> None:
        """Test standard SAML role attribute mapping."""
        test_cases = [
            ({"role": ["viewer"]}, Role.VIEWER),
            ({"role": ["analyst"]}, Role.ANALYST),
            ({"role": ["admin"]}, Role.ADMIN),
            ({"role": ["tenant_admin"]}, Role.TENANT_ADMIN),
            ({"roles": ["admin"]}, Role.ADMIN),
            ({"group": ["analyst"]}, Role.ANALYST),
            ({"groups": ["tenant-admin"]}, Role.TENANT_ADMIN),
        ]

        for attrs, expected_role in test_cases:
            role = rbac.map_role_from_attributes(attrs)
            assert role == expected_role, f"Failed for {attrs}"

    def test_unknown_role_defaults_to_viewer(self, rbac: RBACManager) -> None:
        """Test unknown roles default to viewer (principle of least privilege)."""
        unknown_attrs = [
            {"role": ["superuser"]},
            {"role": ["root"]},
            {"role": ["god_mode"]},
            {"role": []},
            {},
        ]

        for attrs in unknown_attrs:
            attrs_typed: dict[str, list[str]] = attrs  # type: ignore[assignment]
            role = rbac.map_role_from_attributes(attrs_typed)
            assert role == Role.VIEWER, f"Unknown role should map to viewer: {attrs}"

    def test_case_insensitive_mapping(self, rbac: RBACManager) -> None:
        """Test role mapping is case insensitive."""
        test_cases = [
            {"role": ["ADMIN"]},
            {"role": ["Admin"]},
            {"role": ["TENANT_ADMIN"]},
            {"role": ["Tenant-Admin"]},
        ]

        for attrs in test_cases:
            role = rbac.map_role_from_attributes(attrs)
            assert role in (Role.ADMIN, Role.TENANT_ADMIN)


@pytest.mark.integration
class TestAdminActionsRBAC:
    """Integration tests for admin action RBAC enforcement."""

    @pytest.fixture
    def rbac(self) -> RBACManager:
        return RBACManager()

    @pytest.fixture
    def audit_log(self) -> Generator[AuditLog, None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            yield AuditLog(log_path=log_path)

    def test_only_tenant_admin_can_modify_saml(
        self, rbac: RBACManager, audit_log: AuditLog
    ) -> None:
        """NEGATIVE TEST: Only tenant admin can modify SAML config."""
        for role in [Role.VIEWER, Role.ANALYST, Role.ADMIN]:
            user = rbac.create_user_context(
                user_id=f"{role.value}@test.com",
                tenant_id="test_tenant",
                role=role,
            )
            result = rbac.authorize(user, Permission.MANAGE_SAML_CONFIG)
            assert not result.allowed, f"{role.value} should not manage SAML"

        tenant_admin = rbac.create_user_context(
            user_id="tenant_admin@test.com",
            tenant_id="test_tenant",
            role=Role.TENANT_ADMIN,
        )
        result = rbac.authorize(tenant_admin, Permission.MANAGE_SAML_CONFIG)
        assert result.allowed

    def test_admin_action_audit_trail(self, rbac: RBACManager, audit_log: AuditLog) -> None:
        """Verify admin actions create audit trail."""
        admin = rbac.create_user_context(
            user_id="admin@test.com",
            tenant_id="test_tenant",
            role=Role.ADMIN,
        )

        result = rbac.authorize(admin, Permission.MANAGE_USERS)
        assert result.allowed

        audit_log.log_admin_action(
            event_type=AuditEventType.ADMIN_USER_CREATED,
            admin_id=admin.user_id,
            tenant_id=admin.tenant_id,
            resource_type="user",
            resource_id="new_user@test.com",
            action="create",
        )

        events = audit_log.read_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "admin.user.created"
        assert events[0]["actor_id"] == "admin@test.com"
