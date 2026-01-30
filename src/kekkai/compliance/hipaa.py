"""HIPAA Security Rule safeguard mapping for security findings.

Maps findings to HIPAA Security Rule safeguards based on CWE IDs and rule patterns.
Reference: https://www.hhs.gov/hipaa/for-professionals/security/index.html

Note: HIPAA mappings are advisory and apply primarily to healthcare-related
applications handling Protected Health Information (PHI).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .mappings import FrameworkControl

if TYPE_CHECKING:
    from kekkai.scanners.base import Finding


@dataclass(frozen=True)
class HIPAASafeguard:
    """HIPAA Security Rule safeguard definition."""

    id: str
    title: str
    description: str
    category: str  # Administrative, Physical, Technical
    implementation: str  # Required, Addressable
    cwes: frozenset[int]
    rule_patterns: tuple[str, ...]


# HIPAA Security Rule safeguards relevant to application security
HIPAA_SAFEGUARDS: dict[str, HIPAASafeguard] = {
    # Technical Safeguards
    "164.312(a)(1)": HIPAASafeguard(
        id="164.312(a)(1)",
        title="Access Control",
        description=(
            "Implement technical policies and procedures for electronic "
            "information systems that maintain ePHI"
        ),
        category="Technical",
        implementation="Required",
        cwes=frozenset({264, 284, 285, 287, 306, 639, 862, 863}),
        rule_patterns=("access-control", "authorization", "authentication"),
    ),
    "164.312(a)(2)(i)": HIPAASafeguard(
        id="164.312(a)(2)(i)",
        title="Unique User Identification",
        description="Assign a unique name and/or number for identifying and tracking user identity",
        category="Technical",
        implementation="Required",
        cwes=frozenset({287, 288, 521}),
        rule_patterns=("user-identification", "identity", "authentication"),
    ),
    "164.312(a)(2)(ii)": HIPAASafeguard(
        id="164.312(a)(2)(ii)",
        title="Emergency Access Procedure",
        description="Establish procedures for obtaining necessary ePHI during an emergency",
        category="Technical",
        implementation="Required",
        cwes=frozenset({269}),
        rule_patterns=("emergency-access", "break-glass"),
    ),
    "164.312(a)(2)(iii)": HIPAASafeguard(
        id="164.312(a)(2)(iii)",
        title="Automatic Logoff",
        description=(
            "Implement electronic procedures that terminate an electronic session after inactivity"
        ),
        category="Technical",
        implementation="Addressable",
        cwes=frozenset({613}),
        rule_patterns=("session", "timeout", "logoff", "idle"),
    ),
    "164.312(a)(2)(iv)": HIPAASafeguard(
        id="164.312(a)(2)(iv)",
        title="Encryption and Decryption",
        description="Implement a mechanism to encrypt and decrypt ePHI",
        category="Technical",
        implementation="Addressable",
        cwes=frozenset({311, 312, 319, 326, 327, 328}),
        rule_patterns=("encryption", "crypto", "decrypt"),
    ),
    "164.312(b)": HIPAASafeguard(
        id="164.312(b)",
        title="Audit Controls",
        description=(
            "Implement hardware, software, and/or procedures to record and examine activity"
        ),
        category="Technical",
        implementation="Required",
        cwes=frozenset({117, 223, 532, 778}),
        rule_patterns=("audit", "logging", "monitoring", "log-injection"),
    ),
    "164.312(c)(1)": HIPAASafeguard(
        id="164.312(c)(1)",
        title="Integrity",
        description=(
            "Implement policies and procedures to protect ePHI from "
            "improper alteration or destruction"
        ),
        category="Technical",
        implementation="Required",
        cwes=frozenset({345, 353, 494, 502}),
        rule_patterns=("integrity", "tampering", "modification"),
    ),
    "164.312(c)(2)": HIPAASafeguard(
        id="164.312(c)(2)",
        title="Mechanism to Authenticate ePHI",
        description="Implement electronic mechanisms to corroborate that ePHI has not been altered",
        category="Technical",
        implementation="Addressable",
        cwes=frozenset({345, 347, 354}),
        rule_patterns=("authentication", "signature", "hash", "checksum"),
    ),
    "164.312(d)": HIPAASafeguard(
        id="164.312(d)",
        title="Person or Entity Authentication",
        description=(
            "Implement procedures to verify that a person or entity seeking "
            "access is the one claimed"
        ),
        category="Technical",
        implementation="Required",
        cwes=frozenset({287, 290, 294, 295, 302, 306, 307}),
        rule_patterns=("authentication", "verify", "identity", "credential"),
    ),
    "164.312(e)(1)": HIPAASafeguard(
        id="164.312(e)(1)",
        title="Transmission Security",
        description=(
            "Implement technical security measures to guard against unauthorized access to ePHI"
        ),
        category="Technical",
        implementation="Required",
        cwes=frozenset({319, 523, 757}),
        rule_patterns=("transmission", "tls", "ssl", "transport"),
    ),
    "164.312(e)(2)(i)": HIPAASafeguard(
        id="164.312(e)(2)(i)",
        title="Integrity Controls",
        description=(
            "Implement security measures to ensure electronically transmitted "
            "ePHI is not improperly modified"
        ),
        category="Technical",
        implementation="Addressable",
        cwes=frozenset({319, 345}),
        rule_patterns=("integrity", "transmission", "modification"),
    ),
    "164.312(e)(2)(ii)": HIPAASafeguard(
        id="164.312(e)(2)(ii)",
        title="Encryption",
        description="Implement mechanism to encrypt ePHI whenever deemed appropriate",
        category="Technical",
        implementation="Addressable",
        cwes=frozenset({311, 319, 326, 327}),
        rule_patterns=("encryption", "tls", "ssl"),
    ),
    # Administrative Safeguards (security-relevant)
    "164.308(a)(1)(ii)(A)": HIPAASafeguard(
        id="164.308(a)(1)(ii)(A)",
        title="Risk Analysis",
        description=(
            "Conduct an accurate and thorough assessment of potential risks and vulnerabilities"
        ),
        category="Administrative",
        implementation="Required",
        cwes=frozenset({937, 1035, 1104}),
        rule_patterns=("vulnerability", "risk", "cve-", "scan"),
    ),
    "164.308(a)(5)(ii)(B)": HIPAASafeguard(
        id="164.308(a)(5)(ii)(B)",
        title="Protection from Malicious Software",
        description="Procedures for guarding against, detecting, and reporting malicious software",
        category="Administrative",
        implementation="Addressable",
        cwes=frozenset({94, 502, 829}),
        rule_patterns=("malware", "malicious", "injection"),
    ),
}


def _extract_cwe_id(cwe_str: str | None) -> int | None:
    """Extract numeric CWE ID from string."""
    if not cwe_str:
        return None
    cwe_str = cwe_str.upper().replace("CWE-", "").replace("CWE", "")
    try:
        return int(cwe_str.strip())
    except ValueError:
        return None


def map_to_hipaa(finding: Finding) -> list[FrameworkControl]:
    """Map a finding to HIPAA Security Rule safeguards."""
    controls: list[FrameworkControl] = []

    cwe_id = _extract_cwe_id(finding.cwe)
    rule_id_lower = (finding.rule_id or "").lower()
    title_lower = finding.title.lower()

    for safeguard in HIPAA_SAFEGUARDS.values():
        matched = False

        # Match by CWE
        if cwe_id and cwe_id in safeguard.cwes:
            matched = True

        # Match by rule pattern
        if not matched:
            for pattern in safeguard.rule_patterns:
                if pattern in rule_id_lower or pattern in title_lower:
                    matched = True
                    break

        # CVEs map to 164.308(a)(1)(ii)(A) (risk analysis)
        if not matched and safeguard.id == "164.308(a)(1)(ii)(A)" and finding.cve:
            matched = True

        if matched:
            controls.append(
                FrameworkControl(
                    framework="HIPAA",
                    control_id=safeguard.id,
                    title=safeguard.title,
                    description=safeguard.description,
                    requirement_level=safeguard.implementation.lower(),
                )
            )

    return controls
