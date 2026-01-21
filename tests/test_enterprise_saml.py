"""Unit tests for enterprise SAML module."""

from __future__ import annotations

import base64
import time
from datetime import UTC, datetime, timedelta

import pytest

from portal.enterprise.saml import (
    AssertionIDStore,
    SAMLAssertion,
    SAMLConfig,
    SAMLProcessor,
    SAMLReplayError,
    SAMLValidationError,
    create_mock_saml_response,
)


class TestSAMLConfig:
    """Tests for SAML configuration."""

    def test_config_to_dict(self) -> None:
        config = SAMLConfig(
            entity_id="https://idp.example.com",
            sso_url="https://idp.example.com/sso",
            certificate="CERT_DATA",
        )
        data = config.to_dict()
        assert data["entity_id"] == "https://idp.example.com"
        assert data["sso_url"] == "https://idp.example.com/sso"

    def test_config_from_dict(self) -> None:
        data = {
            "entity_id": "https://idp.example.com",
            "sso_url": "https://idp.example.com/sso",
            "certificate": "CERT",
            "session_lifetime": 7200,
        }
        config = SAMLConfig.from_dict(data)
        assert config.entity_id == "https://idp.example.com"
        assert config.session_lifetime == 7200

    def test_config_defaults(self) -> None:
        config = SAMLConfig(
            entity_id="https://idp.example.com",
            sso_url="https://idp.example.com/sso",
        )
        assert config.want_assertions_signed is True
        assert config.allow_clock_skew == 300


class TestAssertionIDStore:
    """Tests for SAML assertion ID replay protection."""

    def test_check_and_mark_new_id_returns_true(self) -> None:
        store = AssertionIDStore()
        assert store.check_and_mark("_assertion_123") is True

    def test_check_and_mark_duplicate_returns_false(self) -> None:
        store = AssertionIDStore()
        store.check_and_mark("_assertion_123")
        assert store.check_and_mark("_assertion_123") is False

    def test_is_used_detects_used_ids(self) -> None:
        store = AssertionIDStore()
        store.check_and_mark("_id_1")
        assert store.is_used("_id_1") is True
        assert store.is_used("_id_2") is False

    def test_expired_ids_are_cleaned(self) -> None:
        store = AssertionIDStore(ttl=1)
        store.check_and_mark("_old_id")
        store._used_ids["_old_id"] = time.time() - 100
        store._last_cleanup = time.time() - 120
        store.check_and_mark("_new_id")
        assert store.is_used("_old_id") is False


class TestSAMLAssertion:
    """Tests for parsed SAML assertion."""

    def test_email_from_nameid(self) -> None:
        assertion = SAMLAssertion(
            assertion_id="_123",
            issuer="https://idp.example.com",
            subject_name_id="user@example.com",
            subject_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index="_sess",
            authn_instant=datetime.now(UTC),
            not_before=None,
            not_on_or_after=None,
        )
        assert assertion.email == "user@example.com"

    def test_email_from_attributes(self) -> None:
        assertion = SAMLAssertion(
            assertion_id="_123",
            issuer="https://idp.example.com",
            subject_name_id="user123",
            subject_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            session_index="_sess",
            authn_instant=datetime.now(UTC),
            not_before=None,
            not_on_or_after=None,
            attributes={"email": ["user@example.com"]},
        )
        assert assertion.email == "user@example.com"

    def test_display_name_from_attributes(self) -> None:
        assertion = SAMLAssertion(
            assertion_id="_123",
            issuer="https://idp.example.com",
            subject_name_id="user@example.com",
            subject_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index="_sess",
            authn_instant=datetime.now(UTC),
            not_before=None,
            not_on_or_after=None,
            attributes={"displayName": ["John Doe"]},
        )
        assert assertion.display_name == "John Doe"

    def test_roles_from_multiple_attributes(self) -> None:
        assertion = SAMLAssertion(
            assertion_id="_123",
            issuer="https://idp.example.com",
            subject_name_id="user@example.com",
            subject_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index="_sess",
            authn_instant=datetime.now(UTC),
            not_before=None,
            not_on_or_after=None,
            attributes={"role": ["admin"], "groups": ["developers"]},
        )
        roles = assertion.roles
        assert "admin" in roles
        assert "developers" in roles


class TestSAMLProcessor:
    """Tests for SAML processor."""

    @pytest.fixture
    def processor(self) -> SAMLProcessor:
        config = SAMLConfig(
            entity_id="https://idp.example.com",
            sso_url="https://idp.example.com/sso",
            certificate=None,
            want_assertions_signed=False,
        )
        return SAMLProcessor(
            sp_entity_id="https://sp.example.com",
            sp_acs_url="https://sp.example.com/saml/acs",
            idp_config=config,
        )

    def test_create_authn_request(self, processor: SAMLProcessor) -> None:
        url, request_id = processor.create_authn_request()
        assert url.startswith("https://idp.example.com/sso")
        assert "SAMLRequest=" in url
        assert request_id.startswith("_kek_")

    def test_create_authn_request_with_relay_state(self, processor: SAMLProcessor) -> None:
        url, _ = processor.create_authn_request(relay_state="/dashboard")
        assert "RelayState=" in url

    def test_process_valid_response(self, processor: SAMLProcessor) -> None:
        response = create_mock_saml_response(
            assertion_id="_test_assertion_1",
            issuer="https://idp.example.com",
            subject="user@example.com",
            audience="https://sp.example.com",
            attributes={"role": ["admin"]},
        )

        assertion = processor.process_response(response, validate_signature=False)

        assert assertion.assertion_id == "_test_assertion_1"
        assert assertion.subject_name_id == "user@example.com"
        assert "admin" in assertion.roles

    def test_process_response_rejects_replay(self, processor: SAMLProcessor) -> None:
        response = create_mock_saml_response(
            assertion_id="_replay_test_id",
            issuer="https://idp.example.com",
            subject="user@example.com",
            audience="https://sp.example.com",
        )

        processor.process_response(response, validate_signature=False)

        with pytest.raises(SAMLReplayError):
            processor.process_response(response, validate_signature=False)

    def test_process_response_rejects_expired(self, processor: SAMLProcessor) -> None:
        past = datetime.now(UTC) - timedelta(hours=2)
        response = create_mock_saml_response(
            assertion_id="_expired_test",
            issuer="https://idp.example.com",
            subject="user@example.com",
            audience="https://sp.example.com",
            not_before=past - timedelta(hours=1),
            not_on_or_after=past,
        )

        with pytest.raises(SAMLValidationError, match="expired"):
            processor.process_response(response, validate_signature=False)

    def test_process_response_rejects_future(self, processor: SAMLProcessor) -> None:
        future = datetime.now(UTC) + timedelta(hours=2)
        response = create_mock_saml_response(
            assertion_id="_future_test",
            issuer="https://idp.example.com",
            subject="user@example.com",
            audience="https://sp.example.com",
            not_before=future,
            not_on_or_after=future + timedelta(hours=1),
        )

        with pytest.raises(SAMLValidationError, match="not yet valid"):
            processor.process_response(response, validate_signature=False)

    def test_process_invalid_base64(self, processor: SAMLProcessor) -> None:
        with pytest.raises(SAMLValidationError, match="Base64"):
            processor.process_response("not-valid-base64!!!")

    def test_process_invalid_xml(self, processor: SAMLProcessor) -> None:
        invalid_xml = base64.b64encode(b"<not-xml").decode()
        with pytest.raises(SAMLValidationError, match="XML"):
            processor.process_response(invalid_xml)


class TestSessionTokens:
    """Tests for session token creation and verification."""

    @pytest.fixture
    def processor(self) -> SAMLProcessor:
        return SAMLProcessor(
            sp_entity_id="https://sp.example.com",
            sp_acs_url="https://sp.example.com/saml/acs",
        )

    @pytest.fixture
    def assertion(self) -> SAMLAssertion:
        return SAMLAssertion(
            assertion_id="_test_123",
            issuer="https://idp.example.com",
            subject_name_id="user@example.com",
            subject_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index="_session_abc",
            authn_instant=datetime.now(UTC),
            not_before=None,
            not_on_or_after=None,
        )

    def test_create_session_token(self, processor: SAMLProcessor, assertion: SAMLAssertion) -> None:
        token = processor.create_session_token(
            assertion=assertion,
            tenant_id="tenant_a",
            secret_key="test_secret_key",
        )
        assert "." in token
        parts = token.split(".")
        assert len(parts) == 2

    def test_verify_valid_token(self, processor: SAMLProcessor, assertion: SAMLAssertion) -> None:
        secret = "test_secret_key"
        token = processor.create_session_token(
            assertion=assertion,
            tenant_id="tenant_a",
            secret_key=secret,
        )

        payload = processor.verify_session_token(token, secret)
        assert payload is not None
        assert payload["sub"] == "user@example.com"
        assert payload["tid"] == "tenant_a"

    def test_verify_invalid_signature(
        self, processor: SAMLProcessor, assertion: SAMLAssertion
    ) -> None:
        token = processor.create_session_token(
            assertion=assertion,
            tenant_id="tenant_a",
            secret_key="correct_key",
        )

        payload = processor.verify_session_token(token, "wrong_key")
        assert payload is None

    def test_verify_expired_token(self, processor: SAMLProcessor, assertion: SAMLAssertion) -> None:
        secret = "test_key"
        token = processor.create_session_token(
            assertion=assertion,
            tenant_id="tenant_a",
            secret_key=secret,
        )

        parts = token.split(".")
        import base64
        import json

        payload_b64 = parts[0]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        payload["exp"] = int(time.time()) - 3600

        new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        import hashlib
        import hmac

        new_sig = hmac.new(secret.encode(), new_payload.encode(), hashlib.sha256).hexdigest()
        expired_token = f"{new_payload}.{new_sig}"

        result = processor.verify_session_token(expired_token, secret)
        assert result is None

    def test_verify_malformed_token(self, processor: SAMLProcessor) -> None:
        assert processor.verify_session_token("invalid", "key") is None
        assert processor.verify_session_token("a.b.c", "key") is None
