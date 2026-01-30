"""Enterprise license validation and feature gating.

Security controls:
- Server-side license enforcement
- Asymmetric (ECDSA P-256) signed license tokens to prevent tampering
- Grace period handling for expiration
- Private key for signing (admin only), public key for validation (distributed)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

GRACE_PERIOD_DAYS = 7
LICENSE_CHECK_INTERVAL = 3600


class LicenseStatus(Enum):
    """License validation status."""

    VALID = "valid"
    EXPIRED = "expired"
    GRACE_PERIOD = "grace_period"
    INVALID = "invalid"
    MISSING = "missing"


class LicenseTier(Enum):
    """License tier levels."""

    COMMUNITY = "community"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class EnterpriseFeature(Enum):
    """Features available in enterprise tier."""

    SSO_SAML = "sso_saml"
    RBAC = "rbac"
    AUDIT_LOGGING = "audit_logging"
    CUSTOM_BRANDING = "custom_branding"
    API_RATE_LIMIT_INCREASE = "api_rate_limit_increase"
    PRIORITY_SUPPORT = "priority_support"
    SLA_GUARANTEE = "sla_guarantee"
    MULTI_REGION = "multi_region"
    ADVANCED_REPORTS = "advanced_reports"


TIER_FEATURES: dict[LicenseTier, frozenset[EnterpriseFeature]] = {
    LicenseTier.COMMUNITY: frozenset(),
    LicenseTier.PROFESSIONAL: frozenset(
        {
            EnterpriseFeature.AUDIT_LOGGING,
            EnterpriseFeature.API_RATE_LIMIT_INCREASE,
        }
    ),
    LicenseTier.ENTERPRISE: frozenset(
        {
            EnterpriseFeature.SSO_SAML,
            EnterpriseFeature.RBAC,
            EnterpriseFeature.AUDIT_LOGGING,
            EnterpriseFeature.CUSTOM_BRANDING,
            EnterpriseFeature.API_RATE_LIMIT_INCREASE,
            EnterpriseFeature.PRIORITY_SUPPORT,
            EnterpriseFeature.SLA_GUARANTEE,
            EnterpriseFeature.MULTI_REGION,
            EnterpriseFeature.ADVANCED_REPORTS,
        }
    ),
}


@dataclass(frozen=True)
class EnterpriseLicense:
    """Represents an enterprise license."""

    license_id: str
    tenant_id: str
    tier: LicenseTier
    issued_at: datetime
    expires_at: datetime
    features: frozenset[EnterpriseFeature] = field(default_factory=frozenset)
    max_users: int = 0
    max_projects: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if license is expired (without grace period)."""
        return datetime.now(UTC) > self.expires_at

    def is_in_grace_period(self) -> bool:
        """Check if license is in grace period."""
        now = datetime.now(UTC)
        if now <= self.expires_at:
            return False
        grace_end = self.expires_at + timedelta(days=GRACE_PERIOD_DAYS)
        return now <= grace_end

    def has_feature(self, feature: EnterpriseFeature) -> bool:
        """Check if license includes a specific feature."""
        tier_features = TIER_FEATURES.get(self.tier, frozenset())
        return feature in self.features or feature in tier_features

    def to_dict(self) -> dict[str, Any]:
        return {
            "license_id": self.license_id,
            "tenant_id": self.tenant_id,
            "tier": self.tier.value,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "features": [f.value for f in self.features],
            "max_users": self.max_users,
            "max_projects": self.max_projects,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnterpriseLicense:
        features = frozenset(EnterpriseFeature(f) for f in data.get("features", []))
        return cls(
            license_id=str(data["license_id"]),
            tenant_id=str(data["tenant_id"]),
            tier=LicenseTier(data["tier"]),
            issued_at=datetime.fromisoformat(str(data["issued_at"])),
            expires_at=datetime.fromisoformat(str(data["expires_at"])),
            features=features,
            max_users=int(data.get("max_users", 0)),
            max_projects=int(data.get("max_projects", 0)),
            metadata=data.get("metadata", {}),
        )


@dataclass
class LicenseCheckResult:
    """Result of a license check."""

    status: LicenseStatus
    license: EnterpriseLicense | None = None
    message: str | None = None
    days_until_expiry: int | None = None
    grace_days_remaining: int | None = None


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new ECDSA P-256 keypair for license signing.

    Returns:
        Tuple of (private_key_pem, public_key_pem) as bytes.
        Keep private_key_pem SECRET - only used for signing licenses.
        Distribute public_key_pem with the application for verification.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


class LicenseSigner:
    """Signs enterprise licenses using ECDSA private key.

    This class should only be used server-side by administrators
    to generate license tokens. Never distribute the private key.
    """

    _private_key: ec.EllipticCurvePrivateKey

    def __init__(self, private_key_pem: bytes) -> None:
        loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(loaded_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Expected ECDSA private key")
        self._private_key = loaded_key

    def create_license_token(self, license: EnterpriseLicense) -> str:
        """Create a signed license token using ECDSA.

        The token format is: base64(payload).base64(signature)
        """
        payload = license.to_dict()
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")

        signature = self._private_key.sign(
            payload_b64.encode(),
            ec.ECDSA(hashes.SHA256()),
        )
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{payload_b64}.{signature_b64}"


class LicenseValidator:
    """Validates enterprise licenses using ECDSA public key.

    This class can be safely distributed with the application.
    It only requires the public key for verification.
    """

    _public_key: ec.EllipticCurvePublicKey

    def __init__(self, public_key_pem: bytes) -> None:
        loaded_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(loaded_key, ec.EllipticCurvePublicKey):
            raise ValueError("Expected ECDSA public key")
        self._public_key = loaded_key
        self._cache: dict[str, tuple[float, LicenseCheckResult]] = {}

    @classmethod
    def from_public_key_string(cls, public_key_str: str) -> LicenseValidator:
        """Create validator from PEM string (convenience method)."""
        return cls(public_key_str.encode())

    def validate_token(self, token: str) -> LicenseCheckResult:
        """Validate a license token and return the license if valid.

        Args:
            token: The signed license token

        Returns:
            LicenseCheckResult with status and license details
        """
        if not token:
            return LicenseCheckResult(
                status=LicenseStatus.MISSING,
                message="No license token provided",
            )

        parts = token.split(".")
        if len(parts) != 2:
            logger.warning("license.invalid_format")
            return LicenseCheckResult(
                status=LicenseStatus.INVALID,
                message="Invalid license token format",
            )

        payload_b64, signature_b64 = parts

        try:
            sig_padding = 4 - len(signature_b64) % 4
            if sig_padding != 4:
                signature_b64 += "=" * sig_padding
            signature = base64.urlsafe_b64decode(signature_b64)

            self._public_key.verify(
                signature,
                payload_b64.encode(),
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature:
            logger.warning("license.invalid_signature")
            return LicenseCheckResult(
                status=LicenseStatus.INVALID,
                message="Invalid license signature",
            )
        except Exception as e:
            logger.warning("license.signature_error: %s", e)
            return LicenseCheckResult(
                status=LicenseStatus.INVALID,
                message="Failed to verify license signature",
            )

        try:
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            payload = json.loads(payload_json)
            license = EnterpriseLicense.from_dict(payload)
        except (ValueError, json.JSONDecodeError, KeyError) as e:
            logger.warning("license.decode_error: %s", e)
            return LicenseCheckResult(
                status=LicenseStatus.INVALID,
                message="Failed to decode license",
            )

        now = datetime.now(UTC)
        days_until_expiry = (license.expires_at - now).days

        if license.is_expired():
            if license.is_in_grace_period():
                grace_end = license.expires_at + timedelta(days=GRACE_PERIOD_DAYS)
                grace_days = (grace_end - now).days
                logger.warning(
                    "license.grace_period license_id=%s days_remaining=%d",
                    license.license_id,
                    grace_days,
                )
                return LicenseCheckResult(
                    status=LicenseStatus.GRACE_PERIOD,
                    license=license,
                    message=f"License expired, {grace_days} days of grace period remaining",
                    days_until_expiry=days_until_expiry,
                    grace_days_remaining=grace_days,
                )
            else:
                logger.warning("license.expired license_id=%s", license.license_id)
                return LicenseCheckResult(
                    status=LicenseStatus.EXPIRED,
                    license=license,
                    message="License has expired",
                    days_until_expiry=days_until_expiry,
                )

        logger.debug(
            "license.valid license_id=%s tier=%s expires_in=%d",
            license.license_id,
            license.tier.value,
            days_until_expiry,
        )
        return LicenseCheckResult(
            status=LicenseStatus.VALID,
            license=license,
            days_until_expiry=days_until_expiry,
        )

    def check_cached(self, tenant_id: str, token: str) -> LicenseCheckResult:
        """Check license with caching to reduce validation overhead."""
        cache_key = f"{tenant_id}:{hashlib.sha256(token.encode()).hexdigest()[:16]}"
        now = time.time()

        if cache_key in self._cache:
            cached_time, cached_result = self._cache[cache_key]
            if now - cached_time < LICENSE_CHECK_INTERVAL:
                return cached_result

        result = self.validate_token(token)
        self._cache[cache_key] = (now, result)
        return result

    def clear_cache(self, tenant_id: str | None = None) -> None:
        """Clear license validation cache."""
        if tenant_id:
            self._cache = {
                k: v for k, v in self._cache.items() if not k.startswith(f"{tenant_id}:")
            }
        else:
            self._cache.clear()


def require_feature(
    license_result: LicenseCheckResult,
    feature: EnterpriseFeature,
) -> tuple[bool, str | None]:
    """Check if a license allows access to a feature.

    Returns:
        Tuple of (allowed, error_message)
    """
    if license_result.status == LicenseStatus.MISSING:
        return False, "Enterprise license required"

    if license_result.status == LicenseStatus.INVALID:
        return False, "Invalid license"

    if license_result.status == LicenseStatus.EXPIRED:
        return False, "License has expired"

    if not license_result.license:
        return False, "No license data"

    if not license_result.license.has_feature(feature):
        return False, f"Feature {feature.value} not included in license"

    return True, None


def require_enterprise(
    license_result: LicenseCheckResult,
) -> tuple[bool, str | None]:
    """Check if license is enterprise tier.

    Returns:
        Tuple of (allowed, error_message)
    """
    if license_result.status not in (LicenseStatus.VALID, LicenseStatus.GRACE_PERIOD):
        return False, "Enterprise license required"

    if not license_result.license:
        return False, "No license data"

    if license_result.license.tier != LicenseTier.ENTERPRISE:
        return False, "Enterprise tier license required"

    return True, None
