"""Tenant management for multi-tenant portal.

Security controls:
- ASVS V8.4.1: Cross-tenant controls via tenant_id boundary
- ASVS V8.2.2: Data-specific authorization via product/engagement mapping
- ASVS V6.8.2: SAML configuration for enterprise tenants
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import string
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

API_KEY_LENGTH = 32
API_KEY_PREFIX = "kek_"


class AuthMethod(Enum):
    """Authentication methods for tenants."""

    API_KEY = "api_key"
    SAML = "saml"
    BOTH = "both"


@dataclass(frozen=True)
class SAMLTenantConfig:
    """SAML configuration for a tenant."""

    entity_id: str
    sso_url: str
    certificate: str
    slo_url: str | None = None
    certificate_fingerprint: str | None = None
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    session_lifetime: int = 28800
    role_attribute: str = "role"
    default_role: str = "viewer"

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "sso_url": self.sso_url,
            "certificate": self.certificate,
            "slo_url": self.slo_url,
            "certificate_fingerprint": self.certificate_fingerprint,
            "name_id_format": self.name_id_format,
            "session_lifetime": self.session_lifetime,
            "role_attribute": self.role_attribute,
            "default_role": self.default_role,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SAMLTenantConfig:
        return cls(
            entity_id=str(data["entity_id"]),
            sso_url=str(data["sso_url"]),
            certificate=str(data["certificate"]),
            slo_url=data.get("slo_url"),
            certificate_fingerprint=data.get("certificate_fingerprint"),
            name_id_format=data.get(
                "name_id_format",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            ),
            session_lifetime=int(data.get("session_lifetime", 28800)),
            role_attribute=str(data.get("role_attribute", "role")),
            default_role=str(data.get("default_role", "viewer")),
        )


@dataclass(frozen=True)
class Tenant:
    """Represents a portal tenant with DefectDojo product mapping."""

    id: str
    name: str
    api_key_hash: str
    dojo_product_id: int
    dojo_engagement_id: int
    enabled: bool = True
    max_upload_size_mb: int = 10
    auth_method: AuthMethod = AuthMethod.API_KEY
    saml_config: SAMLTenantConfig | None = None
    license_token: str | None = None
    default_role: str = "viewer"

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["auth_method"] = self.auth_method.value
        if self.saml_config:
            result["saml_config"] = self.saml_config.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Tenant:
        dojo_product = data["dojo_product_id"]
        dojo_engagement = data["dojo_engagement_id"]
        max_size = data.get("max_upload_size_mb", 10)

        auth_method_str = data.get("auth_method", "api_key")
        auth_method = AuthMethod(str(auth_method_str))

        saml_config = None
        saml_data = data.get("saml_config")
        if saml_data and isinstance(saml_data, dict):
            saml_config = SAMLTenantConfig.from_dict(saml_data)

        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            api_key_hash=str(data["api_key_hash"]),
            dojo_product_id=int(str(dojo_product)),
            dojo_engagement_id=int(str(dojo_engagement)),
            enabled=bool(data.get("enabled", True)),
            max_upload_size_mb=int(str(max_size)),
            auth_method=auth_method,
            saml_config=saml_config,
            license_token=data.get("license_token"),  # type: ignore[arg-type]
            default_role=str(data.get("default_role", "viewer")),
        )

    def is_enterprise(self) -> bool:
        """Check if tenant has enterprise features enabled."""
        return self.auth_method in (AuthMethod.SAML, AuthMethod.BOTH)


def generate_api_key() -> str:
    """Generate a secure random API key with prefix."""
    alphabet = string.ascii_letters + string.digits
    key = "".join(secrets.choice(alphabet) for _ in range(API_KEY_LENGTH))
    return f"{API_KEY_PREFIX}{key}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA-256 for secure storage."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    """Verify an API key against its hash using constant-time comparison."""
    computed_hash = hash_api_key(api_key)
    return hmac.compare_digest(computed_hash, api_key_hash)


class TenantStore:
    """File-based tenant storage for MVP.

    Easily swappable for database storage in production.
    """

    def __init__(self, store_path: Path) -> None:
        self._store_path = store_path
        self._tenants: dict[str, Tenant] = {}
        self._load()

    def _load(self) -> None:
        """Load tenants from storage file."""
        if not self._store_path.exists():
            self._tenants = {}
            return

        try:
            data = json.loads(self._store_path.read_text())
            self._tenants = {
                tid: Tenant.from_dict(tdata) for tid, tdata in data.get("tenants", {}).items()
            }
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Failed to load tenant store: %s", exc)
            self._tenants = {}

    def _save(self) -> None:
        """Persist tenants to storage file."""
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"tenants": {tid: t.to_dict() for tid, t in self._tenants.items()}}
        self._store_path.write_text(json.dumps(data, indent=2))

    def get_by_id(self, tenant_id: str) -> Tenant | None:
        """Get tenant by ID."""
        return self._tenants.get(tenant_id)

    def get_by_api_key(self, api_key: str) -> Tenant | None:
        """Find tenant by API key (constant-time for each tenant)."""
        for tenant in self._tenants.values():
            if verify_api_key(api_key, tenant.api_key_hash):
                return tenant
        return None

    def create(
        self,
        tenant_id: str,
        name: str,
        dojo_product_id: int,
        dojo_engagement_id: int,
        max_upload_size_mb: int = 10,
        auth_method: AuthMethod = AuthMethod.API_KEY,
        saml_config: SAMLTenantConfig | None = None,
        license_token: str | None = None,
        default_role: str = "viewer",
    ) -> tuple[Tenant, str]:
        """Create a new tenant and return (tenant, api_key).

        The plaintext API key is only returned once during creation.
        """
        if tenant_id in self._tenants:
            raise ValueError(f"Tenant {tenant_id} already exists")

        api_key = generate_api_key()
        tenant = Tenant(
            id=tenant_id,
            name=name,
            api_key_hash=hash_api_key(api_key),
            dojo_product_id=dojo_product_id,
            dojo_engagement_id=dojo_engagement_id,
            enabled=True,
            max_upload_size_mb=max_upload_size_mb,
            auth_method=auth_method,
            saml_config=saml_config,
            license_token=license_token,
            default_role=default_role,
        )
        self._tenants[tenant_id] = tenant
        self._save()

        logger.info("Created tenant: %s", tenant_id)
        return tenant, api_key

    def update(self, tenant: Tenant) -> None:
        """Update an existing tenant."""
        if tenant.id not in self._tenants:
            raise ValueError(f"Tenant {tenant.id} does not exist")
        self._tenants[tenant.id] = tenant
        self._save()
        logger.info("Updated tenant: %s", tenant.id)

    def delete(self, tenant_id: str) -> bool:
        """Delete a tenant by ID."""
        if tenant_id not in self._tenants:
            return False
        del self._tenants[tenant_id]
        self._save()
        logger.info("Deleted tenant: %s", tenant_id)
        return True

    def list_all(self) -> list[Tenant]:
        """List all tenants."""
        return list(self._tenants.values())

    def rotate_api_key(self, tenant_id: str) -> str | None:
        """Generate a new API key for a tenant."""
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return None

        new_api_key = generate_api_key()
        updated = Tenant(
            id=tenant.id,
            name=tenant.name,
            api_key_hash=hash_api_key(new_api_key),
            dojo_product_id=tenant.dojo_product_id,
            dojo_engagement_id=tenant.dojo_engagement_id,
            enabled=tenant.enabled,
            max_upload_size_mb=tenant.max_upload_size_mb,
            auth_method=tenant.auth_method,
            saml_config=tenant.saml_config,
            license_token=tenant.license_token,
            default_role=tenant.default_role,
        )
        self._tenants[tenant_id] = updated
        self._save()

        logger.info("Rotated API key for tenant: %s", tenant_id)
        return new_api_key

    def update_saml_config(
        self,
        tenant_id: str,
        saml_config: SAMLTenantConfig,
        auth_method: AuthMethod = AuthMethod.SAML,
    ) -> Tenant | None:
        """Update SAML configuration for a tenant."""
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return None

        updated = Tenant(
            id=tenant.id,
            name=tenant.name,
            api_key_hash=tenant.api_key_hash,
            dojo_product_id=tenant.dojo_product_id,
            dojo_engagement_id=tenant.dojo_engagement_id,
            enabled=tenant.enabled,
            max_upload_size_mb=tenant.max_upload_size_mb,
            auth_method=auth_method,
            saml_config=saml_config,
            license_token=tenant.license_token,
            default_role=tenant.default_role,
        )
        self._tenants[tenant_id] = updated
        self._save()

        logger.info("Updated SAML config for tenant: %s", tenant_id)
        return updated

    def update_license(self, tenant_id: str, license_token: str) -> Tenant | None:
        """Update license token for a tenant."""
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return None

        updated = Tenant(
            id=tenant.id,
            name=tenant.name,
            api_key_hash=tenant.api_key_hash,
            dojo_product_id=tenant.dojo_product_id,
            dojo_engagement_id=tenant.dojo_engagement_id,
            enabled=tenant.enabled,
            max_upload_size_mb=tenant.max_upload_size_mb,
            auth_method=tenant.auth_method,
            saml_config=tenant.saml_config,
            license_token=license_token,
            default_role=tenant.default_role,
        )
        self._tenants[tenant_id] = updated
        self._save()

        logger.info("Updated license for tenant: %s", tenant_id)
        return updated
