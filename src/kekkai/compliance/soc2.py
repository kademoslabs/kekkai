"""SOC 2 Type II criteria mapping for security findings.

Maps findings to SOC 2 Trust Services Criteria based on CWE IDs and rule patterns.
Reference: https://www.aicpa.org/resources/landing/trust-services-criteria
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .mappings import FrameworkControl

if TYPE_CHECKING:
    from kekkai.scanners.base import Finding


@dataclass(frozen=True)
class SOC2Criterion:
    """SOC 2 Trust Services Criterion definition."""

    id: str
    title: str
    description: str
    category: str  # Security, Availability, Processing Integrity, Confidentiality, Privacy
    cwes: frozenset[int]
    rule_patterns: tuple[str, ...]


# SOC 2 Trust Services Criteria relevant to application security
SOC2_CRITERIA: dict[str, SOC2Criterion] = {
    # Security (Common Criteria)
    "CC6.1": SOC2Criterion(
        id="CC6.1",
        title="Logical and Physical Access Controls",
        description=(
            "The entity implements logical access security software, "
            "infrastructure, and architectures to protect against threats"
        ),
        category="Security",
        cwes=frozenset({264, 284, 285, 287, 306, 639, 862, 863}),
        rule_patterns=("access-control", "authorization", "authentication", "idor"),
    ),
    "CC6.2": SOC2Criterion(
        id="CC6.2",
        title="User Registration and Authorization",
        description="Prior to issuing system credentials, users are registered and authorized",
        category="Security",
        cwes=frozenset({287, 288, 302, 307, 521}),
        rule_patterns=("registration", "user-management", "credential"),
    ),
    "CC6.3": SOC2Criterion(
        id="CC6.3",
        title="Credential Lifecycle Management",
        description="The entity authorizes, modifies, or removes access based on roles",
        category="Security",
        cwes=frozenset({255, 259, 269, 522, 613, 640, 798}),
        rule_patterns=("credential", "password", "session", "privilege"),
    ),
    "CC6.6": SOC2Criterion(
        id="CC6.6",
        title="Security Events Detection",
        description="The entity implements controls to prevent, detect, and act on security events",
        category="Security",
        cwes=frozenset({117, 223, 532, 778}),
        rule_patterns=("logging", "monitoring", "detection", "audit"),
    ),
    "CC6.7": SOC2Criterion(
        id="CC6.7",
        title="Transmission Protection",
        description=(
            "The entity restricts transmission of confidential information "
            "over communication channels"
        ),
        category="Security",
        cwes=frozenset({319, 523, 757}),
        rule_patterns=("tls", "ssl", "encryption", "transmission"),
    ),
    "CC6.8": SOC2Criterion(
        id="CC6.8",
        title="Malicious Software Prevention",
        description="The entity implements controls to prevent or detect malicious software",
        category="Security",
        cwes=frozenset({94, 502, 829}),
        rule_patterns=("malware", "injection", "deserialization"),
    ),
    "CC7.1": SOC2Criterion(
        id="CC7.1",
        title="Vulnerability Management",
        description=(
            "The entity uses detection and monitoring procedures to identify vulnerabilities"
        ),
        category="Security",
        cwes=frozenset({937, 1035, 1104}),
        rule_patterns=("vulnerability", "cve-", "outdated", "component"),
    ),
    "CC7.2": SOC2Criterion(
        id="CC7.2",
        title="Security Incident Response",
        description=(
            "The entity monitors system components for anomalies indicative of malicious acts"
        ),
        category="Security",
        cwes=frozenset({778, 779}),
        rule_patterns=("incident", "response", "anomaly"),
    ),
    "CC8.1": SOC2Criterion(
        id="CC8.1",
        title="Change Management",
        description="The entity authorizes, designs, develops, configures, and implements changes",
        category="Security",
        cwes=frozenset({489, 540}),
        rule_patterns=("change-management", "deployment", "debug"),
    ),
    # Confidentiality
    "C1.1": SOC2Criterion(
        id="C1.1",
        title="Confidential Information Identification",
        description="The entity identifies and maintains confidential information",
        category="Confidentiality",
        cwes=frozenset({200, 201, 312, 319, 359}),
        rule_patterns=("sensitive-data", "pii", "secret", "confidential"),
    ),
    "C1.2": SOC2Criterion(
        id="C1.2",
        title="Confidential Information Disposal",
        description="The entity disposes of confidential information to meet objectives",
        category="Confidentiality",
        cwes=frozenset({226, 312, 459}),
        rule_patterns=("disposal", "cleanup", "retention"),
    ),
    # Processing Integrity
    "PI1.2": SOC2Criterion(
        id="PI1.2",
        title="Input Validation",
        description="The entity implements policies to verify input is complete and accurate",
        category="Processing Integrity",
        cwes=frozenset({20, 74, 77, 78, 79, 89, 91, 94}),
        rule_patterns=("validation", "input", "injection", "xss", "sqli"),
    ),
    "PI1.4": SOC2Criterion(
        id="PI1.4",
        title="Output Validation",
        description="The entity implements policies to verify output is complete and accurate",
        category="Processing Integrity",
        cwes=frozenset({79, 116}),
        rule_patterns=("output", "encoding", "xss"),
    ),
    # Availability
    "A1.2": SOC2Criterion(
        id="A1.2",
        title="System Recovery",
        description="The entity implements policies to support system recovery",
        category="Availability",
        cwes=frozenset({400, 770}),  # resource exhaustion
        rule_patterns=("dos", "resource", "availability", "recovery"),
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


def map_to_soc2(finding: Finding) -> list[FrameworkControl]:
    """Map a finding to SOC 2 criteria."""
    controls: list[FrameworkControl] = []

    cwe_id = _extract_cwe_id(finding.cwe)
    rule_id_lower = (finding.rule_id or "").lower()
    title_lower = finding.title.lower()

    for criterion in SOC2_CRITERIA.values():
        matched = False

        # Match by CWE
        if cwe_id and cwe_id in criterion.cwes:
            matched = True

        # Match by rule pattern
        if not matched:
            for pattern in criterion.rule_patterns:
                if pattern in rule_id_lower or pattern in title_lower:
                    matched = True
                    break

        # CVEs map to CC7.1 (vulnerability management)
        if not matched and criterion.id == "CC7.1" and finding.cve:
            matched = True

        if matched:
            controls.append(
                FrameworkControl(
                    framework="SOC2",
                    control_id=criterion.id,
                    title=criterion.title,
                    description=criterion.description,
                    requirement_level="required",
                )
            )

    return controls
