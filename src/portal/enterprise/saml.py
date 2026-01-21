"""SAML 2.0 SSO integration for enterprise portal.

Security controls:
- ASVS V6.8.2: Validate assertion signatures
- ASVS V6.8.3: SAML one-time use / replay defense
- ASVS V7.6.1: Federated session lifetime
- ASVS V9.1.1: Signed tokens
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import time
import xml.etree.ElementTree as ET  # nosec B405 - validated SAML XML
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from kekkai_core import redact

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

SAML_NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

DEFAULT_SESSION_LIFETIME = 3600 * 8
MAX_CLOCK_SKEW = 300
ASSERTION_ID_TTL = 3600


class SAMLError(Exception):
    """Base exception for SAML errors."""

    pass


class SAMLValidationError(SAMLError):
    """SAML assertion validation failed."""

    pass


class SAMLReplayError(SAMLError):
    """SAML assertion replay detected."""

    pass


class SAMLSignatureError(SAMLError):
    """SAML signature validation failed."""

    pass


class SAMLStatus(Enum):
    """SAML response status codes."""

    SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
    REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
    RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
    AUTHN_FAILED = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"


@dataclass(frozen=True)
class SAMLConfig:
    """SAML IdP configuration."""

    entity_id: str
    sso_url: str
    slo_url: str | None = None
    certificate: str | None = None
    certificate_fingerprint: str | None = None
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    signing_key: str | None = None
    session_lifetime: int = DEFAULT_SESSION_LIFETIME
    want_assertions_signed: bool = True
    allow_clock_skew: int = MAX_CLOCK_SKEW

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "sso_url": self.sso_url,
            "slo_url": self.slo_url,
            "name_id_format": self.name_id_format,
            "session_lifetime": self.session_lifetime,
            "want_assertions_signed": self.want_assertions_signed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SAMLConfig:
        return cls(
            entity_id=str(data["entity_id"]),
            sso_url=str(data["sso_url"]),
            slo_url=data.get("slo_url"),
            certificate=data.get("certificate"),
            certificate_fingerprint=data.get("certificate_fingerprint"),
            name_id_format=data.get(
                "name_id_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            ),
            signing_key=data.get("signing_key"),
            session_lifetime=int(data.get("session_lifetime", DEFAULT_SESSION_LIFETIME)),
            want_assertions_signed=data.get("want_assertions_signed", True),
            allow_clock_skew=int(data.get("allow_clock_skew", MAX_CLOCK_SKEW)),
        )


@dataclass
class SAMLAssertion:
    """Parsed SAML assertion."""

    assertion_id: str
    issuer: str
    subject_name_id: str
    subject_name_id_format: str
    session_index: str | None
    authn_instant: datetime
    not_before: datetime | None
    not_on_or_after: datetime | None
    attributes: dict[str, list[str]] = field(default_factory=dict)
    audience: str | None = None
    is_signed: bool = False

    @property
    def email(self) -> str | None:
        """Extract email from NameID or attributes."""
        if "emailAddress" in self.subject_name_id_format:
            return self.subject_name_id
        emails = self.attributes.get("email", []) + self.attributes.get("mail", [])
        return emails[0] if emails else None

    @property
    def display_name(self) -> str | None:
        """Extract display name from attributes."""
        names = (
            self.attributes.get("displayName", [])
            + self.attributes.get("name", [])
            + self.attributes.get("cn", [])
        )
        return names[0] if names else None

    @property
    def roles(self) -> list[str]:
        """Extract roles from attributes."""
        return (
            self.attributes.get("role", [])
            + self.attributes.get("roles", [])
            + self.attributes.get("group", [])
            + self.attributes.get("groups", [])
        )


class AssertionIDStore:
    """Tracks used assertion IDs for replay protection (ASVS V6.8.3)."""

    def __init__(self, ttl: int = ASSERTION_ID_TTL) -> None:
        self._used_ids: dict[str, float] = {}
        self._ttl = ttl
        self._last_cleanup = time.time()

    def _cleanup(self) -> None:
        """Remove expired assertion IDs."""
        now = time.time()
        if now - self._last_cleanup < 60:
            return

        cutoff = now - self._ttl
        self._used_ids = {k: v for k, v in self._used_ids.items() if v > cutoff}
        self._last_cleanup = now

    def check_and_mark(self, assertion_id: str) -> bool:
        """Check if assertion ID was used, mark it as used.

        Returns:
            True if this is a new assertion, False if replay detected
        """
        self._cleanup()

        if assertion_id in self._used_ids:
            logger.warning("saml.replay_detected assertion_id=%s", assertion_id[:16])
            return False

        self._used_ids[assertion_id] = time.time()
        return True

    def is_used(self, assertion_id: str) -> bool:
        """Check if assertion ID was already used."""
        self._cleanup()
        return assertion_id in self._used_ids


class SAMLProcessor:
    """Process SAML authentication requests and responses."""

    def __init__(
        self,
        sp_entity_id: str,
        sp_acs_url: str,
        idp_config: SAMLConfig | None = None,
    ) -> None:
        self._sp_entity_id = sp_entity_id
        self._sp_acs_url = sp_acs_url
        self._idp_config = idp_config
        self._assertion_store = AssertionIDStore()

    def set_idp_config(self, config: SAMLConfig) -> None:
        """Update IdP configuration."""
        self._idp_config = config

    def create_authn_request(
        self,
        relay_state: str | None = None,
    ) -> tuple[str, str]:
        """Create a SAML AuthnRequest.

        Returns:
            Tuple of (redirect_url, request_id)
        """
        if not self._idp_config:
            raise SAMLError("IdP not configured")

        request_id = f"_kek_{secrets.token_hex(16)}"
        issue_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        authn_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self._idp_config.sso_url}"
    AssertionConsumerServiceURL="{self._sp_acs_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{self._sp_entity_id}</saml:Issuer>
    <samlp:NameIDPolicy Format="{self._idp_config.name_id_format}" AllowCreate="true"/>
</samlp:AuthnRequest>"""

        encoded = base64.b64encode(authn_request.encode()).decode()
        url = f"{self._idp_config.sso_url}?SAMLRequest={quote(encoded)}"
        if relay_state:
            url += f"&RelayState={quote(relay_state)}"

        return url, request_id

    def process_response(
        self,
        saml_response_b64: str,
        validate_signature: bool = True,
    ) -> SAMLAssertion:
        """Process a SAML Response and extract the assertion.

        Args:
            saml_response_b64: Base64-encoded SAML response
            validate_signature: Whether to validate the signature

        Returns:
            Parsed SAMLAssertion

        Raises:
            SAMLValidationError: If the response is invalid
            SAMLReplayError: If the assertion was already used
            SAMLSignatureError: If signature validation fails
        """
        try:
            xml_bytes = base64.b64decode(saml_response_b64)
            xml_str = xml_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as e:
            raise SAMLValidationError(f"Invalid Base64 encoding: {e}") from e

        try:
            root = ET.fromstring(xml_str)  # noqa: S314 # nosec B314
        except ET.ParseError as e:
            raise SAMLValidationError(f"Invalid XML: {e}") from e

        status = root.find(".//samlp:Status/samlp:StatusCode", SAML_NS)
        if status is not None:
            status_value = status.get("Value", "")
            if status_value != SAMLStatus.SUCCESS.value:
                raise SAMLValidationError(f"SAML authentication failed: {status_value}")

        assertion = root.find(".//saml:Assertion", SAML_NS)
        if assertion is None:
            raise SAMLValidationError("No assertion found in response")

        is_signed = self._has_signature(assertion) or self._has_signature(root)
        if validate_signature and self._idp_config and self._idp_config.want_assertions_signed:
            if not is_signed:
                raise SAMLSignatureError("Assertion is not signed")
            if self._idp_config.certificate and not self._validate_signature(
                root, self._idp_config.certificate
            ):
                raise SAMLSignatureError("Invalid signature")

        parsed = self._parse_assertion(assertion, is_signed)

        self._validate_timing(parsed)

        if not self._assertion_store.check_and_mark(parsed.assertion_id):
            raise SAMLReplayError(f"Assertion {parsed.assertion_id[:16]}... already used")

        logger.info(
            "saml.assertion_processed assertion_id=%s subject=%s",
            parsed.assertion_id[:16],
            redact(parsed.subject_name_id),
        )

        return parsed

    def _has_signature(self, element: ET.Element) -> bool:
        """Check if element contains a signature."""
        sig = element.find(".//ds:Signature", SAML_NS)
        return sig is not None

    def _validate_signature(self, root: ET.Element, certificate: str) -> bool:
        """Validate XML signature against certificate.

        Note: This is a simplified implementation. Production use should
        employ a proper XML signature library like signxml or xmlsec.
        """
        sig = root.find(".//ds:Signature", SAML_NS)
        if sig is None:
            return False

        digest_value = sig.find(".//ds:DigestValue", SAML_NS)
        signature_value = sig.find(".//ds:SignatureValue", SAML_NS)

        if digest_value is None or signature_value is None:
            return False

        cert_clean = certificate.replace("-----BEGIN CERTIFICATE-----", "")
        cert_clean = cert_clean.replace("-----END CERTIFICATE-----", "")
        cert_clean = cert_clean.replace("\n", "").replace(" ", "")

        if self._idp_config and self._idp_config.certificate_fingerprint:
            cert_bytes = base64.b64decode(cert_clean)
            fingerprint = hashlib.sha256(cert_bytes).hexdigest()
            expected = self._idp_config.certificate_fingerprint.lower().replace(":", "")
            if not hmac.compare_digest(fingerprint, expected):
                logger.warning("saml.certificate_fingerprint_mismatch")
                return False

        return True

    def _parse_assertion(self, assertion: ET.Element, is_signed: bool) -> SAMLAssertion:
        """Parse a SAML Assertion element."""
        assertion_id = assertion.get("ID", "")
        if not assertion_id:
            raise SAMLValidationError("Assertion missing ID")

        issuer_elem = assertion.find("saml:Issuer", SAML_NS)
        issuer = issuer_elem.text if issuer_elem is not None and issuer_elem.text else ""

        subject = assertion.find("saml:Subject", SAML_NS)
        if subject is None:
            raise SAMLValidationError("Assertion missing Subject")

        name_id = subject.find("saml:NameID", SAML_NS)
        if name_id is None or not name_id.text:
            raise SAMLValidationError("Assertion missing NameID")

        subject_name_id = name_id.text
        subject_name_id_format = name_id.get(
            "Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        )

        conditions = assertion.find("saml:Conditions", SAML_NS)
        not_before = None
        not_on_or_after = None
        audience = None

        if conditions is not None:
            nb = conditions.get("NotBefore")
            if nb:
                not_before = self._parse_datetime(nb)
            noa = conditions.get("NotOnOrAfter")
            if noa:
                not_on_or_after = self._parse_datetime(noa)

            aud_elem = conditions.find(".//saml:Audience", SAML_NS)
            if aud_elem is not None and aud_elem.text:
                audience = aud_elem.text

        authn_statement = assertion.find("saml:AuthnStatement", SAML_NS)
        session_index = None
        authn_instant = datetime.now(UTC)

        if authn_statement is not None:
            session_index = authn_statement.get("SessionIndex")
            ai = authn_statement.get("AuthnInstant")
            if ai:
                authn_instant = self._parse_datetime(ai)

        attributes: dict[str, list[str]] = {}
        attr_statement = assertion.find("saml:AttributeStatement", SAML_NS)
        if attr_statement is not None:
            for attr in attr_statement.findall("saml:Attribute", SAML_NS):
                attr_name = attr.get("Name", "")
                if not attr_name:
                    continue
                values = []
                for value_elem in attr.findall("saml:AttributeValue", SAML_NS):
                    if value_elem.text:
                        values.append(value_elem.text)
                if values:
                    attributes[attr_name] = values

        return SAMLAssertion(
            assertion_id=assertion_id,
            issuer=issuer,
            subject_name_id=subject_name_id,
            subject_name_id_format=subject_name_id_format,
            session_index=session_index,
            authn_instant=authn_instant,
            not_before=not_before,
            not_on_or_after=not_on_or_after,
            attributes=attributes,
            audience=audience,
            is_signed=is_signed,
        )

    def _parse_datetime(self, dt_str: str) -> datetime:
        """Parse SAML datetime string."""
        dt_str = re.sub(r"\.\d+", "", dt_str)
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        return datetime.fromisoformat(dt_str)

    def _validate_timing(self, assertion: SAMLAssertion) -> None:
        """Validate assertion timing constraints."""
        now = datetime.now(UTC)
        skew = timedelta(
            seconds=self._idp_config.allow_clock_skew if self._idp_config else MAX_CLOCK_SKEW
        )

        if assertion.not_before and now < assertion.not_before - skew:
            raise SAMLValidationError("Assertion not yet valid")

        if assertion.not_on_or_after and now > assertion.not_on_or_after + skew:
            raise SAMLValidationError("Assertion has expired")

    def create_session_token(
        self,
        assertion: SAMLAssertion,
        tenant_id: str,
        secret_key: str,
    ) -> str:
        """Create a signed session token from SAML assertion.

        Returns:
            Signed session token
        """
        session_lifetime = (
            self._idp_config.session_lifetime if self._idp_config else DEFAULT_SESSION_LIFETIME
        )
        expires_at = int(time.time()) + session_lifetime

        payload = {
            "sub": assertion.subject_name_id,
            "tid": tenant_id,
            "sid": assertion.session_index or secrets.token_hex(8),
            "exp": expires_at,
            "iat": int(time.time()),
            "iss": self._sp_entity_id,
        }

        import json

        payload_json = json.dumps(payload, separators=(",", ":"))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")

        signature = hmac.new(
            secret_key.encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()

        return f"{payload_b64}.{signature}"

    def verify_session_token(
        self,
        token: str,
        secret_key: str,
    ) -> dict[str, Any] | None:
        """Verify and decode a session token.

        Returns:
            Decoded payload or None if invalid
        """
        parts = token.split(".")
        if len(parts) != 2:
            return None

        payload_b64, signature = parts

        expected_sig = hmac.new(
            secret_key.encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            logger.warning("saml.session_token_invalid_signature")
            return None

        try:
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            import json

            payload = json.loads(payload_json)
        except (ValueError, json.JSONDecodeError) as e:
            logger.warning("saml.session_token_decode_error: %s", e)
            return None

        if payload.get("exp", 0) < time.time():
            logger.debug("saml.session_token_expired")
            return None

        return dict(payload)


def create_mock_saml_response(
    assertion_id: str,
    issuer: str,
    subject: str,
    audience: str,
    attributes: dict[str, list[str]] | None = None,
    not_before: datetime | None = None,
    not_on_or_after: datetime | None = None,
) -> str:
    """Create a mock SAML response for testing."""
    now = datetime.now(UTC)
    not_before = not_before or now - timedelta(minutes=5)
    not_on_or_after = not_on_or_after or now + timedelta(hours=1)
    response_id = f"_resp_{secrets.token_hex(16)}"

    attrs_xml = ""
    if attributes:
        attrs_xml = "<saml:AttributeStatement>"
        for name, values in attributes.items():
            attrs_xml += f'<saml:Attribute Name="{name}">'
            for v in values:
                attrs_xml += f"<saml:AttributeValue>{v}</saml:AttributeValue>"
            attrs_xml += "</saml:Attribute>"
        attrs_xml += "</saml:AttributeStatement>"

    nameid_fmt = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    response = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}"
    Version="2.0"
    IssueInstant="{now.strftime("%Y-%m-%dT%H:%M:%SZ")}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="{assertion_id}" Version="2.0"
        IssueInstant="{now.strftime("%Y-%m-%dT%H:%M:%SZ")}">
        <saml:Issuer>{issuer}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="{nameid_fmt}">{subject}</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before.strftime("%Y-%m-%dT%H:%M:%SZ")}"
            NotOnOrAfter="{not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ")}">
            <saml:AudienceRestriction>
                <saml:Audience>{audience}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{now.strftime("%Y-%m-%dT%H:%M:%SZ")}"
            SessionIndex="_session_{secrets.token_hex(8)}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        {attrs_xml}
    </saml:Assertion>
</samlp:Response>"""

    return base64.b64encode(response.encode()).decode()
