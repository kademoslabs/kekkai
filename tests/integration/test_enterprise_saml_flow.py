"""Integration tests for SAML SSO flow."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from portal.enterprise.audit import AuditLog
from portal.enterprise.rbac import Permission, RBACManager, Role
from portal.enterprise.saml import (
    SAMLConfig,
    SAMLProcessor,
    create_mock_saml_response,
)
from portal.tenants import AuthMethod, SAMLTenantConfig, TenantStore


@pytest.mark.integration
class TestSAMLLoginFlow:
    """Integration tests for complete SAML login flow."""

    @pytest.fixture
    def saml_config(self) -> SAMLConfig:
        return SAMLConfig(
            entity_id="https://idp.example.com",
            sso_url="https://idp.example.com/sso",
            certificate=None,
            want_assertions_signed=False,
            session_lifetime=3600,
        )

    @pytest.fixture
    def processor(self, saml_config: SAMLConfig) -> SAMLProcessor:
        return SAMLProcessor(
            sp_entity_id="https://kekkai.example.com",
            sp_acs_url="https://kekkai.example.com/saml/acs",
            idp_config=saml_config,
        )

    @pytest.fixture
    def rbac(self) -> RBACManager:
        return RBACManager()

    @pytest.fixture
    def tenant_store(self) -> Generator[TenantStore, None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            saml_cfg = SAMLTenantConfig(
                entity_id="https://idp.example.com",
                sso_url="https://idp.example.com/sso",
                certificate="CERT",
            )
            store.create(
                tenant_id="enterprise_tenant",
                name="Enterprise Corp",
                dojo_product_id=100,
                dojo_engagement_id=1000,
                auth_method=AuthMethod.SAML,
                saml_config=saml_cfg,
            )
            yield store

    def test_complete_saml_flow(
        self,
        processor: SAMLProcessor,
        rbac: RBACManager,
        tenant_store: TenantStore,
    ) -> None:
        """Test complete SAML SSO flow from request to session."""
        login_url, request_id = processor.create_authn_request(relay_state="/dashboard")
        assert "SAMLRequest=" in login_url

        saml_response = create_mock_saml_response(
            assertion_id="_assertion_flow_test",
            issuer="https://idp.example.com",
            subject="admin@enterprise.com",
            audience="https://kekkai.example.com",
            attributes={
                "role": ["admin"],
                "displayName": ["Enterprise Admin"],
                "email": ["admin@enterprise.com"],
            },
        )

        assertion = processor.process_response(saml_response, validate_signature=False)

        assert assertion.subject_name_id == "admin@enterprise.com"
        assert assertion.display_name == "Enterprise Admin"
        assert "admin" in assertion.roles

        role = rbac.map_role_from_attributes(assertion.attributes)
        assert role == Role.ADMIN

        user_context = rbac.create_user_context(
            user_id=assertion.subject_name_id,
            tenant_id="enterprise_tenant",
            role=role,
            email=assertion.email,
            display_name=assertion.display_name,
            session_id=assertion.session_index,
        )

        assert rbac.authorize(user_context, Permission.MANAGE_USERS).allowed
        assert rbac.authorize(user_context, Permission.VIEW_AUDIT_LOGS).allowed

    def test_saml_flow_with_viewer_role(
        self,
        processor: SAMLProcessor,
        rbac: RBACManager,
    ) -> None:
        """Test SAML flow defaults to viewer for unknown roles."""
        saml_response = create_mock_saml_response(
            assertion_id="_assertion_viewer_test",
            issuer="https://idp.example.com",
            subject="viewer@enterprise.com",
            audience="https://kekkai.example.com",
            attributes={"role": ["readonly"]},
        )

        assertion = processor.process_response(saml_response, validate_signature=False)

        role = rbac.map_role_from_attributes(assertion.attributes)
        assert role == Role.VIEWER

        user_context = rbac.create_user_context(
            user_id=assertion.subject_name_id,
            tenant_id="enterprise_tenant",
            role=role,
        )

        assert rbac.authorize(user_context, Permission.VIEW_FINDINGS).allowed
        assert not rbac.authorize(user_context, Permission.CREATE_UPLOAD).allowed

    def test_saml_session_token_roundtrip(
        self,
        processor: SAMLProcessor,
    ) -> None:
        """Test session token creation and verification."""
        saml_response = create_mock_saml_response(
            assertion_id="_assertion_session_test",
            issuer="https://idp.example.com",
            subject="user@enterprise.com",
            audience="https://kekkai.example.com",
        )

        assertion = processor.process_response(saml_response, validate_signature=False)

        secret = "enterprise_session_secret_key"
        token = processor.create_session_token(
            assertion=assertion,
            tenant_id="enterprise_tenant",
            secret_key=secret,
        )

        payload = processor.verify_session_token(token, secret)
        assert payload is not None
        assert payload["sub"] == "user@enterprise.com"
        assert payload["tid"] == "enterprise_tenant"


@pytest.mark.integration
class TestSAMLWithAudit:
    """Integration tests for SAML with audit logging."""

    @pytest.fixture
    def audit_log(self) -> Generator[AuditLog, None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            yield AuditLog(log_path=log_path)

    @pytest.fixture
    def processor(self) -> SAMLProcessor:
        config = SAMLConfig(
            entity_id="https://idp.example.com",
            sso_url="https://idp.example.com/sso",
            want_assertions_signed=False,
        )
        return SAMLProcessor(
            sp_entity_id="https://kekkai.example.com",
            sp_acs_url="https://kekkai.example.com/saml/acs",
            idp_config=config,
        )

    def test_saml_login_creates_audit_event(
        self,
        processor: SAMLProcessor,
        audit_log: AuditLog,
    ) -> None:
        """Verify SAML login creates audit trail."""
        saml_response = create_mock_saml_response(
            assertion_id="_audit_test_assertion",
            issuer="https://idp.example.com",
            subject="audited@enterprise.com",
            audience="https://kekkai.example.com",
        )

        assertion = processor.process_response(saml_response, validate_signature=False)

        audit_log.log_auth_success(
            user_id=assertion.subject_name_id,
            tenant_id="enterprise_tenant",
            auth_method="saml",
            assertion_id=assertion.assertion_id,
        )

        events = audit_log.read_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "auth.login.success"
        assert events[0]["details"]["auth_method"] == "saml"

    def test_saml_replay_creates_audit_event(
        self,
        processor: SAMLProcessor,
        audit_log: AuditLog,
    ) -> None:
        """Verify SAML replay attempt creates audit trail."""
        saml_response = create_mock_saml_response(
            assertion_id="_replay_audit_test",
            issuer="https://idp.example.com",
            subject="replayer@enterprise.com",
            audience="https://kekkai.example.com",
        )

        processor.process_response(saml_response, validate_signature=False)

        try:
            processor.process_response(saml_response, validate_signature=False)
        except Exception:
            audit_log.log_saml_replay_blocked(
                assertion_id="_replay_audit_test",
                client_ip="192.168.1.100",
            )

        events = audit_log.read_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "auth.saml.replay_blocked"


@pytest.mark.integration
class TestEnterpriseTenantSAML:
    """Integration tests for enterprise tenant SAML configuration."""

    def test_tenant_with_saml_config(self) -> None:
        """Verify tenant can store and retrieve SAML configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            saml_cfg = SAMLTenantConfig(
                entity_id="https://idp.corp.com",
                sso_url="https://idp.corp.com/sso",
                certificate="MIICert...",
                session_lifetime=7200,
                role_attribute="memberOf",
                default_role="analyst",
            )

            tenant, api_key = store.create(
                tenant_id="corp_tenant",
                name="Corporation Inc",
                dojo_product_id=200,
                dojo_engagement_id=2000,
                auth_method=AuthMethod.BOTH,
                saml_config=saml_cfg,
            )

            assert tenant.is_enterprise()
            assert tenant.auth_method == AuthMethod.BOTH
            assert tenant.saml_config is not None
            assert tenant.saml_config.entity_id == "https://idp.corp.com"
            assert tenant.saml_config.session_lifetime == 7200

            store2 = TenantStore(store_path)
            loaded = store2.get_by_id("corp_tenant")
            assert loaded is not None
            assert loaded.saml_config is not None
            assert loaded.saml_config.role_attribute == "memberOf"

    def test_update_saml_config(self) -> None:
        """Verify SAML configuration can be updated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            store.create(
                tenant_id="update_tenant",
                name="Update Corp",
                dojo_product_id=300,
                dojo_engagement_id=3000,
            )

            new_saml = SAMLTenantConfig(
                entity_id="https://new-idp.com",
                sso_url="https://new-idp.com/sso",
                certificate="NewCert",
            )

            updated = store.update_saml_config("update_tenant", new_saml)
            assert updated is not None
            assert updated.auth_method == AuthMethod.SAML
            assert updated.saml_config is not None
            assert updated.saml_config.entity_id == "https://new-idp.com"
