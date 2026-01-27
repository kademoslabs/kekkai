"""Authentication middleware for portal API.

Security controls:
- ASVS V16.3.2: Log failed authorization attempts
- Constant-time API key comparison to prevent timing attacks
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kekkai_core import redact

from .tenants import Tenant, TenantStore

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

BEARER_PATTERN = re.compile(r"^Bearer\s+(\S+)$", re.IGNORECASE)


@dataclass(frozen=True)
class AuthResult:
    """Result of authentication attempt."""

    authenticated: bool
    tenant: Tenant | None = None
    error: str | None = None


def authenticate_request(
    headers: Mapping[str, str],
    tenant_store: TenantStore,
    client_ip: str = "unknown",
) -> AuthResult:
    """Authenticate a request using Bearer token.

    Args:
        headers: Request headers (case-insensitive lookup)
        tenant_store: Tenant storage for API key verification
        client_ip: Client IP for logging failed attempts

    Returns:
        AuthResult with tenant if authenticated, error otherwise
    """
    auth_header = _get_header(headers, "Authorization")
    if not auth_header:
        _log_auth_failure(client_ip, "missing_header")
        return AuthResult(authenticated=False, error="Missing Authorization header")

    match = BEARER_PATTERN.match(auth_header)
    if not match:
        _log_auth_failure(client_ip, "invalid_format")
        return AuthResult(authenticated=False, error="Invalid Authorization format")

    api_key = match.group(1)
    if not api_key:
        _log_auth_failure(client_ip, "empty_token")
        return AuthResult(authenticated=False, error="Empty API token")

    tenant = tenant_store.get_by_api_key(api_key)
    if not tenant:
        _log_auth_failure(client_ip, "invalid_token", api_key_prefix=api_key[:8])
        return AuthResult(authenticated=False, error="Invalid API key")

    if not tenant.enabled:
        _log_auth_failure(client_ip, "tenant_disabled", tenant_id=tenant.id)
        return AuthResult(authenticated=False, error="Tenant is disabled")

    logger.info(
        "auth.success client_ip=%s tenant_id=%s",
        redact(client_ip),
        tenant.id,
    )
    return AuthResult(authenticated=True, tenant=tenant)


def _get_header(headers: Mapping[str, str], name: str) -> str | None:
    """Get header value with case-insensitive lookup."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _log_auth_failure(
    client_ip: str,
    reason: str,
    tenant_id: str | None = None,
    api_key_prefix: str | None = None,
) -> None:
    """Log authentication failure for security monitoring (ASVS V16.3.2)."""
    parts = [f"auth.failure reason={reason}", f"client_ip={redact(client_ip)}"]
    if tenant_id:
        parts.append(f"tenant_id={tenant_id}")
    if api_key_prefix:
        parts.append(f"api_key_prefix={api_key_prefix}...")
    logger.warning(" ".join(parts))
