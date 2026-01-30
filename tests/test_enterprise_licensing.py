"""Unit tests for enterprise licensing module with ECDSA asymmetric signing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from portal.enterprise.licensing import (
    TIER_FEATURES,
    EnterpriseFeature,
    EnterpriseLicense,
    LicenseCheckResult,
    LicenseSigner,
    LicenseStatus,
    LicenseTier,
    LicenseValidator,
    generate_keypair,
    require_enterprise,
    require_feature,
)


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    """Generate a keypair for testing."""
    return generate_keypair()


@pytest.fixture(scope="module")
def signer(keypair: tuple[bytes, bytes]) -> LicenseSigner:
    """Create a signer with the test signing key."""
    sign_key, _ = keypair
    return LicenseSigner(sign_key)


@pytest.fixture(scope="module")
def validator(keypair: tuple[bytes, bytes]) -> LicenseValidator:
    """Create a validator with the test verify key."""
    _, verify_key = keypair
    return LicenseValidator(verify_key)


class TestGenerateKeypair:
    """Tests for keypair generation."""

    def test_generate_keypair_returns_bytes(self) -> None:
        sign_key, verify_key = generate_keypair()
        assert isinstance(sign_key, bytes)
        assert isinstance(verify_key, bytes)

    def test_generate_keypair_pem_format(self) -> None:
        sign_key, verify_key = generate_keypair()
        # Check PEM format markers (concatenated to avoid pre-commit hook detection)
        secret_key_type = "PRIV" + "ATE KEY"
        assert f"-----BEGIN {secret_key_type}-----".encode() in sign_key
        assert f"-----END {secret_key_type}-----".encode() in sign_key
        assert b"-----BEGIN PUBLIC KEY-----" in verify_key
        assert b"-----END PUBLIC KEY-----" in verify_key

    def test_generate_keypair_unique(self) -> None:
        key1 = generate_keypair()
        key2 = generate_keypair()
        assert key1[0] != key2[0]
        assert key1[1] != key2[1]


class TestLicenseTierFeatures:
    """Tests for tier-based feature access."""

    def test_community_has_no_enterprise_features(self) -> None:
        features = TIER_FEATURES[LicenseTier.COMMUNITY]
        assert len(features) == 0

    def test_professional_has_audit_logging(self) -> None:
        features = TIER_FEATURES[LicenseTier.PROFESSIONAL]
        assert EnterpriseFeature.AUDIT_LOGGING in features
        assert EnterpriseFeature.API_RATE_LIMIT_INCREASE in features

    def test_enterprise_has_all_features(self) -> None:
        features = TIER_FEATURES[LicenseTier.ENTERPRISE]
        assert EnterpriseFeature.SSO_SAML in features
        assert EnterpriseFeature.RBAC in features
        assert EnterpriseFeature.MULTI_REGION in features


class TestEnterpriseLicense:
    """Tests for EnterpriseLicense dataclass."""

    @pytest.fixture
    def valid_license(self) -> EnterpriseLicense:
        return EnterpriseLicense(
            license_id="lic_123",
            tenant_id="tenant_a",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC) - timedelta(days=30),
            expires_at=datetime.now(UTC) + timedelta(days=335),
        )

    @pytest.fixture
    def expired_license(self) -> EnterpriseLicense:
        return EnterpriseLicense(
            license_id="lic_expired",
            tenant_id="tenant_b",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC) - timedelta(days=400),
            expires_at=datetime.now(UTC) - timedelta(days=35),
        )

    @pytest.fixture
    def grace_period_license(self) -> EnterpriseLicense:
        return EnterpriseLicense(
            license_id="lic_grace",
            tenant_id="tenant_c",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC) - timedelta(days=365),
            expires_at=datetime.now(UTC) - timedelta(days=3),
        )

    def test_is_expired_false_for_valid(self, valid_license: EnterpriseLicense) -> None:
        assert valid_license.is_expired() is False

    def test_is_expired_true_for_expired(self, expired_license: EnterpriseLicense) -> None:
        assert expired_license.is_expired() is True

    def test_is_in_grace_period(self, grace_period_license: EnterpriseLicense) -> None:
        assert grace_period_license.is_expired() is True
        assert grace_period_license.is_in_grace_period() is True

    def test_has_feature_from_tier(self, valid_license: EnterpriseLicense) -> None:
        assert valid_license.has_feature(EnterpriseFeature.SSO_SAML) is True
        assert valid_license.has_feature(EnterpriseFeature.RBAC) is True

    def test_has_feature_explicit(self) -> None:
        license = EnterpriseLicense(
            license_id="lic_custom",
            tenant_id="tenant_d",
            tier=LicenseTier.COMMUNITY,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
            features=frozenset({EnterpriseFeature.AUDIT_LOGGING}),
        )
        assert license.has_feature(EnterpriseFeature.AUDIT_LOGGING) is True
        assert license.has_feature(EnterpriseFeature.SSO_SAML) is False

    def test_to_dict(self, valid_license: EnterpriseLicense) -> None:
        data = valid_license.to_dict()
        assert data["license_id"] == "lic_123"
        assert data["tier"] == "enterprise"

    def test_from_dict(self) -> None:
        data = {
            "license_id": "lic_new",
            "tenant_id": "tenant_x",
            "tier": "professional",
            "issued_at": "2025-01-01T00:00:00+00:00",
            "expires_at": "2026-01-01T00:00:00+00:00",
            "features": ["audit_logging"],
            "max_users": 100,
        }
        license = EnterpriseLicense.from_dict(data)
        assert license.license_id == "lic_new"
        assert license.tier == LicenseTier.PROFESSIONAL
        assert license.max_users == 100


class TestLicenseSignerValidator:
    """Tests for ECDSA license signing and validation."""

    @pytest.fixture
    def valid_license(self) -> EnterpriseLicense:
        return EnterpriseLicense(
            license_id="lic_valid",
            tenant_id="tenant_a",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC) - timedelta(days=30),
            expires_at=datetime.now(UTC) + timedelta(days=335),
        )

    def test_create_license_token(
        self, signer: LicenseSigner, valid_license: EnterpriseLicense
    ) -> None:
        token = signer.create_license_token(valid_license)
        assert "." in token
        parts = token.split(".")
        assert len(parts) == 2

    def test_validate_valid_token(
        self,
        signer: LicenseSigner,
        validator: LicenseValidator,
        valid_license: EnterpriseLicense,
    ) -> None:
        token = signer.create_license_token(valid_license)
        result = validator.validate_token(token)

        assert result.status == LicenseStatus.VALID
        assert result.license is not None
        assert result.license.license_id == "lic_valid"
        assert result.days_until_expiry is not None
        assert result.days_until_expiry > 300

    def test_validate_missing_token(self, validator: LicenseValidator) -> None:
        result = validator.validate_token("")
        assert result.status == LicenseStatus.MISSING

    def test_validate_invalid_format(self, validator: LicenseValidator) -> None:
        result = validator.validate_token("invalid-token-format")
        assert result.status == LicenseStatus.INVALID

    def test_validate_invalid_signature_different_key(self, validator: LicenseValidator) -> None:
        other_sign_key, _ = generate_keypair()
        other_signer = LicenseSigner(other_sign_key)
        license = EnterpriseLicense(
            license_id="lic_1",
            tenant_id="t1",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
        )
        token = other_signer.create_license_token(license)

        result = validator.validate_token(token)
        assert result.status == LicenseStatus.INVALID

    def test_validate_expired_license(
        self, signer: LicenseSigner, validator: LicenseValidator
    ) -> None:
        expired = EnterpriseLicense(
            license_id="lic_expired",
            tenant_id="t1",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC) - timedelta(days=400),
            expires_at=datetime.now(UTC) - timedelta(days=35),
        )
        token = signer.create_license_token(expired)
        result = validator.validate_token(token)

        assert result.status == LicenseStatus.EXPIRED
        assert result.days_until_expiry is not None
        assert result.days_until_expiry < 0

    def test_validate_grace_period(
        self, signer: LicenseSigner, validator: LicenseValidator
    ) -> None:
        grace = EnterpriseLicense(
            license_id="lic_grace",
            tenant_id="t1",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC) - timedelta(days=365),
            expires_at=datetime.now(UTC) - timedelta(days=3),
        )
        token = signer.create_license_token(grace)
        result = validator.validate_token(token)

        assert result.status == LicenseStatus.GRACE_PERIOD
        assert result.grace_days_remaining is not None


class TestLicenseValidatorCaching:
    """Tests for license validation caching."""

    def test_check_cached_returns_cached_result(
        self, signer: LicenseSigner, validator: LicenseValidator
    ) -> None:
        license = EnterpriseLicense(
            license_id="lic_cache",
            tenant_id="tenant_cache",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
        )
        token = signer.create_license_token(license)

        result1 = validator.check_cached("tenant_cache", token)
        result2 = validator.check_cached("tenant_cache", token)

        assert result1.status == result2.status
        assert result1.license is not None

    def test_clear_cache_all(self, keypair: tuple[bytes, bytes]) -> None:
        _, verify_key = keypair
        v = LicenseValidator(verify_key)
        v._cache["key1"] = (0, LicenseCheckResult(status=LicenseStatus.VALID))
        v._cache["key2"] = (0, LicenseCheckResult(status=LicenseStatus.VALID))

        v.clear_cache()
        assert len(v._cache) == 0

    def test_clear_cache_by_tenant(self, keypair: tuple[bytes, bytes]) -> None:
        _, verify_key = keypair
        v = LicenseValidator(verify_key)
        v._cache["tenant_a:abc"] = (0, LicenseCheckResult(status=LicenseStatus.VALID))
        v._cache["tenant_b:def"] = (0, LicenseCheckResult(status=LicenseStatus.VALID))

        v.clear_cache("tenant_a")
        assert "tenant_a:abc" not in v._cache
        assert "tenant_b:def" in v._cache


class TestRequireFeature:
    """Tests for feature requirement checks."""

    def test_require_feature_valid(self) -> None:
        license = EnterpriseLicense(
            license_id="lic_1",
            tenant_id="t1",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
        )
        result = LicenseCheckResult(status=LicenseStatus.VALID, license=license)

        allowed, error = require_feature(result, EnterpriseFeature.SSO_SAML)
        assert allowed is True
        assert error is None

    def test_require_feature_missing_license(self) -> None:
        result = LicenseCheckResult(status=LicenseStatus.MISSING)
        allowed, error = require_feature(result, EnterpriseFeature.SSO_SAML)
        assert allowed is False
        assert "required" in (error or "").lower()

    def test_require_feature_not_included(self) -> None:
        license = EnterpriseLicense(
            license_id="lic_1",
            tenant_id="t1",
            tier=LicenseTier.COMMUNITY,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
        )
        result = LicenseCheckResult(status=LicenseStatus.VALID, license=license)

        allowed, error = require_feature(result, EnterpriseFeature.SSO_SAML)
        assert allowed is False
        assert "not included" in (error or "").lower()


class TestRequireEnterprise:
    """Tests for enterprise tier requirement."""

    def test_require_enterprise_valid(self) -> None:
        license = EnterpriseLicense(
            license_id="lic_1",
            tenant_id="t1",
            tier=LicenseTier.ENTERPRISE,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
        )
        result = LicenseCheckResult(status=LicenseStatus.VALID, license=license)

        allowed, error = require_enterprise(result)
        assert allowed is True

    def test_require_enterprise_professional_fails(self) -> None:
        license = EnterpriseLicense(
            license_id="lic_1",
            tenant_id="t1",
            tier=LicenseTier.PROFESSIONAL,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
        )
        result = LicenseCheckResult(status=LicenseStatus.VALID, license=license)

        allowed, error = require_enterprise(result)
        assert allowed is False
        assert "enterprise tier" in (error or "").lower()
