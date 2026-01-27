"""Enterprise features for Kekkai Portal.

Provides:
- RBAC (Role-Based Access Control)
- SAML 2.0 SSO integration
- Audit logging
- Enterprise license gating
"""

from __future__ import annotations

from .audit import AuditEvent, AuditEventType, AuditLog
from .licensing import EnterpriseLicense, LicenseStatus, LicenseValidator
from .rbac import AuthorizationResult, Permission, RBACManager, Role
from .saml import SAMLAssertion, SAMLConfig, SAMLError, SAMLProcessor

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLog",
    "AuthorizationResult",
    "EnterpriseLicense",
    "LicenseStatus",
    "LicenseValidator",
    "Permission",
    "RBACManager",
    "Role",
    "SAMLAssertion",
    "SAMLConfig",
    "SAMLError",
    "SAMLProcessor",
]
