"""Regression tests for enterprise API contract stability."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from portal.enterprise.audit import AuditEvent, AuditEventType
from portal.enterprise.licensing import (
    EnterpriseFeature,
    EnterpriseLicense,
    LicenseStatus,
    LicenseTier,
)
from portal.enterprise.rbac import AuthorizationResult, Permission, Role, UserContext
from portal.enterprise.saml import SAMLConfig
from portal.tenants import AuthMethod, SAMLTenantConfig, Tenant


@pytest.mark.regression
class TestTenantAPIContract:
    """Regression tests for tenant data structure stability."""

    def test_tenant_serialization_contract(self) -> None:
        """Verify tenant serialization format is stable."""
        saml_cfg = SAMLTenantConfig(
            entity_id="https://idp.example.com",
            sso_url="https://idp.example.com/sso",
            certificate="CERT",
        )
        tenant = Tenant(
            id="test_tenant",
            name="Test Corp",
            api_key_hash="hash123",
            dojo_product_id=100,
            dojo_engagement_id=1000,
            enabled=True,
            max_upload_size_mb=10,
            auth_method=AuthMethod.SAML,
            saml_config=saml_cfg,
            license_token="lic_token",
            default_role="analyst",
        )

        data = tenant.to_dict()

        required_keys = {
            "id",
            "name",
            "api_key_hash",
            "dojo_product_id",
            "dojo_engagement_id",
            "enabled",
            "max_upload_size_mb",
            "auth_method",
            "saml_config",
            "license_token",
            "default_role",
        }
        assert required_keys.issubset(
            data.keys()
        ), f"Missing keys: {required_keys - set(data.keys())}"
        assert data["auth_method"] == "saml"
        assert isinstance(data["saml_config"], dict)

    def test_tenant_deserialization_contract(self) -> None:
        """Verify tenant deserialization is stable."""
        data = {
            "id": "test_id",
            "name": "Test",
            "api_key_hash": "hash",
            "dojo_product_id": 1,
            "dojo_engagement_id": 10,
            "enabled": True,
            "max_upload_size_mb": 5,
            "auth_method": "both",
            "saml_config": {
                "entity_id": "https://idp.com",
                "sso_url": "https://idp.com/sso",
                "certificate": "CERT",
            },
            "license_token": "token",
            "default_role": "admin",
        }

        tenant = Tenant.from_dict(data)
        assert tenant.id == "test_id"
        assert tenant.auth_method == AuthMethod.BOTH
        assert tenant.saml_config is not None
        assert tenant.license_token == "token"


@pytest.mark.regression
class TestAuditEventAPIContract:
    """Regression tests for audit event structure stability."""

    def test_audit_event_serialization_contract(self) -> None:
        """Verify audit event serialization format is stable."""
        event = AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            actor_id="user1",
            tenant_id="tenant_a",
            client_ip="192.168.1.1",
            details={"method": "saml"},
        )

        data = event.to_dict()

        required_keys = {
            "event_type",
            "timestamp",
            "actor_id",
            "tenant_id",
            "outcome",
            "details",
            "event_id",
        }
        assert required_keys.issubset(data.keys())
        assert data["event_type"] == "auth.login.success"
        assert "timestamp" in data

    def test_audit_event_type_values_stable(self) -> None:
        """Verify audit event type values are stable."""
        expected_types = {
            "auth.login.success",
            "auth.login.failure",
            "auth.logout",
            "auth.session.expired",
            "auth.saml.assertion",
            "auth.saml.replay_blocked",
            "authz.denied",
            "authz.cross_tenant",
            "admin.user.created",
            "admin.user.updated",
            "admin.user.deleted",
            "admin.role.changed",
            "admin.tenant.created",
            "admin.tenant.updated",
            "admin.tenant.deleted",
            "admin.api_key.rotated",
            "admin.saml_config.updated",
            "data.upload",
            "data.export",
            "data.delete",
            "system.license.check",
            "system.license.expired",
        }

        actual_types = {et.value for et in AuditEventType}
        added = actual_types - expected_types
        removed = expected_types - actual_types
        assert actual_types == expected_types, f"Audit event types changed: +{added}, -{removed}"


@pytest.mark.regression
class TestLicenseAPIContract:
    """Regression tests for license structure stability."""

    def test_license_serialization_contract(self) -> None:
        """Verify license serialization format is stable."""
        license = EnterpriseLicense(
            license_id="lic_123",
            tenant_id="tenant_a",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime(2025, 1, 1, tzinfo=UTC),
            expires_at=datetime(2026, 1, 1, tzinfo=UTC),
            features=frozenset({EnterpriseFeature.SSO_SAML}),
            max_users=100,
            max_projects=50,
        )

        data = license.to_dict()

        required_keys = {
            "license_id",
            "tenant_id",
            "tier",
            "issued_at",
            "expires_at",
            "features",
            "max_users",
            "max_projects",
        }
        assert required_keys.issubset(data.keys())
        assert data["tier"] == "enterprise"
        assert isinstance(data["features"], list)

    def test_license_tier_values_stable(self) -> None:
        """Verify license tier values are stable."""
        expected_tiers = {"community", "professional", "enterprise"}
        actual_tiers = {t.value for t in LicenseTier}
        assert actual_tiers == expected_tiers

    def test_license_status_values_stable(self) -> None:
        """Verify license status values are stable."""
        expected_statuses = {"valid", "expired", "grace_period", "invalid", "missing"}
        actual_statuses = {s.value for s in LicenseStatus}
        assert actual_statuses == expected_statuses


@pytest.mark.regression
class TestSAMLConfigAPIContract:
    """Regression tests for SAML config structure stability."""

    def test_saml_config_serialization_contract(self) -> None:
        """Verify SAML config serialization format is stable."""
        config = SAMLConfig(
            entity_id="https://idp.example.com",
            sso_url="https://idp.example.com/sso",
            slo_url="https://idp.example.com/slo",
            certificate="CERT",
            session_lifetime=7200,
        )

        data = config.to_dict()

        required_keys = {
            "entity_id",
            "sso_url",
            "slo_url",
            "name_id_format",
            "session_lifetime",
            "want_assertions_signed",
        }
        assert required_keys.issubset(data.keys())

    def test_saml_tenant_config_serialization_contract(self) -> None:
        """Verify SAML tenant config serialization is stable."""
        config = SAMLTenantConfig(
            entity_id="https://idp.corp.com",
            sso_url="https://idp.corp.com/sso",
            certificate="CERT",
            role_attribute="memberOf",
            default_role="analyst",
        )

        data = config.to_dict()

        required_keys = {
            "entity_id",
            "sso_url",
            "certificate",
            "name_id_format",
            "session_lifetime",
            "role_attribute",
            "default_role",
        }
        assert required_keys.issubset(data.keys())


@pytest.mark.regression
class TestRBACAPIContract:
    """Regression tests for RBAC structure stability."""

    def test_user_context_structure(self) -> None:
        """Verify user context structure is stable."""
        ctx = UserContext(
            user_id="user1",
            tenant_id="tenant_a",
            role=Role.ANALYST,
            email="user@example.com",
            display_name="User One",
            session_id="sess_123",
        )

        assert hasattr(ctx, "user_id")
        assert hasattr(ctx, "tenant_id")
        assert hasattr(ctx, "role")
        assert hasattr(ctx, "email")
        assert hasattr(ctx, "display_name")
        assert hasattr(ctx, "session_id")
        assert hasattr(ctx, "permissions")

    def test_authorization_result_structure(self) -> None:
        """Verify authorization result structure is stable."""
        result = AuthorizationResult(
            allowed=True,
            role=Role.ADMIN,
            permission=Permission.MANAGE_USERS,
            reason=None,
        )

        assert hasattr(result, "allowed")
        assert hasattr(result, "role")
        assert hasattr(result, "permission")
        assert hasattr(result, "reason")


@pytest.mark.regression
class TestEnterpriseFeatureAPIContract:
    """Regression tests for enterprise feature values."""

    def test_enterprise_feature_values_stable(self) -> None:
        """Verify enterprise feature enum values are stable."""
        expected_features = {
            "sso_saml",
            "rbac",
            "audit_logging",
            "custom_branding",
            "api_rate_limit_increase",
            "priority_support",
            "sla_guarantee",
            "multi_region",
            "advanced_reports",
        }
        actual_features = {f.value for f in EnterpriseFeature}
        diff = actual_features.symmetric_difference(expected_features)
        assert actual_features == expected_features, f"Enterprise features changed: {diff}"
