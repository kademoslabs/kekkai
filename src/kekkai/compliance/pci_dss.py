"""PCI-DSS v4.0 control mapping for security findings.

Maps findings to PCI-DSS requirements based on CWE IDs and rule patterns.
Reference: https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .mappings import FrameworkControl

if TYPE_CHECKING:
    from kekkai.scanners.base import Finding


@dataclass(frozen=True)
class PCIDSSControl:
    """PCI-DSS v4.0 control definition."""

    id: str
    title: str
    description: str
    cwes: frozenset[int]
    rule_patterns: tuple[str, ...]


# PCI-DSS v4.0 Requirements relevant to application security
PCI_DSS_CONTROLS: dict[str, PCIDSSControl] = {
    "1.4": PCIDSSControl(
        id="1.4",
        title="Network connections between trusted and untrusted networks are controlled",
        description=(
            "System components that store, process, or transmit CHD are not "
            "directly accessible from untrusted networks"
        ),
        cwes=frozenset({918, 441}),  # SSRF, open redirect
        rule_patterns=("ssrf", "network", "firewall"),
    ),
    "2.2.6": PCIDSSControl(
        id="2.2.6",
        title="System security parameters prevent misuse",
        description="Common security parameter settings are correctly configured",
        cwes=frozenset({16, 260, 315, 520, 756}),
        rule_patterns=("misconfiguration", "config", "security-parameter", "hardcoded"),
    ),
    "3.5": PCIDSSControl(
        id="3.5",
        title="Primary account number (PAN) is secured wherever stored",
        description="PAN is rendered unreadable using strong cryptography",
        cwes=frozenset({311, 312, 319, 327, 328}),
        rule_patterns=("encryption", "crypto", "storage", "pan", "card"),
    ),
    "4.2": PCIDSSControl(
        id="4.2",
        title="PAN is protected during transmission",
        description=(
            "Strong cryptography protects PAN during transmission over open, public networks"
        ),
        cwes=frozenset({319, 523, 757}),
        rule_patterns=("tls", "ssl", "transmission", "transport"),
    ),
    "5.2": PCIDSSControl(
        id="5.2",
        title="Malicious software is prevented or detected and addressed",
        description="Anti-malware solutions detect and address malicious software",
        cwes=frozenset({94, 502, 829}),  # code injection, deserialization, untrusted code
        rule_patterns=("malware", "code-injection", "deserialization"),
    ),
    "6.2.4": PCIDSSControl(
        id="6.2.4",
        title="Software engineering techniques prevent or mitigate common attacks",
        description=(
            "Injection attacks, buffer overflows, insecure cryptographic "
            "storage, etc. are prevented"
        ),
        cwes=frozenset({20, 74, 77, 78, 79, 89, 90, 91, 94, 120, 134, 190}),
        rule_patterns=("injection", "sqli", "xss", "buffer", "overflow"),
    ),
    "6.3.1": PCIDSSControl(
        id="6.3.1",
        title="Security vulnerabilities are identified and managed",
        description=(
            "A process is defined for identifying security vulnerabilities "
            "using reputable external sources"
        ),
        cwes=frozenset({937, 1035, 1104}),
        rule_patterns=("cve-", "vulnerability", "outdated", "component"),
    ),
    "6.3.2": PCIDSSControl(
        id="6.3.2",
        title="An inventory of custom and third-party software is maintained",
        description="Software inventory including components and dependencies",
        cwes=frozenset({1104}),
        rule_patterns=("dependency", "component", "sbom"),
    ),
    "6.5.1": PCIDSSControl(
        id="6.5.1",
        title="Changes to production systems follow change control procedures",
        description="Development and test environments are separate from production",
        cwes=frozenset({489, 540}),  # debug code, sensitive info exposure
        rule_patterns=("debug", "development", "test-code"),
    ),
    "6.5.2": PCIDSSControl(
        id="6.5.2",
        title="Live PANs are not used in pre-production environments",
        description="Test data does not contain live PAN or sensitive auth data",
        cwes=frozenset({200, 312}),
        rule_patterns=("test-data", "sensitive-data", "pii"),
    ),
    "6.5.4": PCIDSSControl(
        id="6.5.4",
        title="Roles and functions are separated between production and pre-production",
        description="Separation of duties between environments",
        cwes=frozenset({269, 284}),
        rule_patterns=("privilege", "separation", "access-control"),
    ),
    "7.2": PCIDSSControl(
        id="7.2",
        title="Access to system components and data is appropriately defined",
        description="Role-based access control limits access based on need-to-know",
        cwes=frozenset({264, 284, 285, 639, 862, 863}),
        rule_patterns=("access-control", "authorization", "rbac", "idor"),
    ),
    "8.3": PCIDSSControl(
        id="8.3",
        title="Strong authentication for users and administrators",
        description="MFA and strong password requirements",
        cwes=frozenset({255, 259, 287, 307, 521, 640, 798}),
        rule_patterns=("authentication", "password", "credential", "mfa", "hardcoded-password"),
    ),
    "8.6": PCIDSSControl(
        id="8.6",
        title="Use of application and system accounts is strictly managed",
        description="Shared and service accounts are managed securely",
        cwes=frozenset({250, 269, 522}),
        rule_patterns=("service-account", "shared-credential", "privilege"),
    ),
    "10.3": PCIDSSControl(
        id="10.3",
        title="Audit logs are protected from destruction and unauthorized modifications",
        description="Audit trail records cannot be altered",
        cwes=frozenset({117, 532, 778}),
        rule_patterns=("logging", "audit", "log-injection", "log-tampering"),
    ),
    "11.3.1": PCIDSSControl(
        id="11.3.1",
        title="External and internal vulnerabilities are managed",
        description="Vulnerability scans performed at least quarterly",
        cwes=frozenset({937}),
        rule_patterns=("vulnerability", "scan"),
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


def map_to_pci_dss(finding: Finding) -> list[FrameworkControl]:
    """Map a finding to PCI-DSS v4.0 controls."""
    controls: list[FrameworkControl] = []

    cwe_id = _extract_cwe_id(finding.cwe)
    rule_id_lower = (finding.rule_id or "").lower()
    title_lower = finding.title.lower()

    for control in PCI_DSS_CONTROLS.values():
        matched = False

        # Match by CWE
        if cwe_id and cwe_id in control.cwes:
            matched = True

        # Match by rule pattern
        if not matched:
            for pattern in control.rule_patterns:
                if pattern in rule_id_lower or pattern in title_lower:
                    matched = True
                    break

        # Special case: CVEs map to 6.3.1 (vulnerability management)
        if not matched and control.id == "6.3.1" and finding.cve:
            matched = True

        if matched:
            controls.append(
                FrameworkControl(
                    framework="PCI-DSS",
                    control_id=control.id,
                    title=control.title,
                    description=control.description,
                    requirement_level="required",
                )
            )

    return controls
