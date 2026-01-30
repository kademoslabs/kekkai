"""Enterprise features for Kekkai Portal.

Provides:
- RBAC (Role-Based Access Control)
- SAML 2.0 SSO integration
- Audit logging
- Enterprise license gating (ECDSA asymmetric signing)
"""

from __future__ import annotations

from .audit import AuditEvent, AuditEventType, AuditLog
from .licensing import (
    EnterpriseLicense,
    LicenseCheckResult,
    LicenseSigner,
    LicenseStatus,
    LicenseValidator,
    generate_keypair,
)
from .rbac import AuthorizationResult, Permission, RBACManager, Role
from .saml import SAMLAssertion, SAMLConfig, SAMLError, SAMLProcessor

ENTERPRISE_AVAILABLE = True

__all__ = [
    "ENTERPRISE_AVAILABLE",
    "AuditEvent",
    "AuditEventType",
    "AuditLog",
    "AuthorizationResult",
    "EnterpriseLicense",
    "LicenseCheckResult",
    "LicenseSigner",
    "LicenseStatus",
    "LicenseValidator",
    "Permission",
    "RBACManager",
    "Role",
    "SAMLAssertion",
    "SAMLConfig",
    "SAMLError",
    "SAMLProcessor",
    "generate_keypair",
]
