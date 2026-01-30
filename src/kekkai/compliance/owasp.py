"""OWASP Top 10 2025 mapping for security findings.

Maps findings to OWASP Top 10 2025 categories based on CWE IDs and rule patterns.
Reference: https://owasp.org/Top10/2025/

Changes from 2021:
- A01:2025 Broken Access Control (now includes SSRF)
- A02:2025 Security Misconfiguration (moved up from #5)
- A03:2025 Software Supply Chain Failures (NEW - replaces Vulnerable Components)
- A04:2025 Cryptographic Failures (moved down from #2)
- A05:2025 Injection (moved down from #3)
- A06:2025 Insecure Design (moved down from #4)
- A07:2025 Authentication Failures (renamed)
- A08:2025 Software or Data Integrity Failures (stable)
- A09:2025 Security Logging and Alerting Failures (minor rename)
- A10:2025 Mishandling of Exceptional Conditions (NEW)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .mappings import FrameworkControl

if TYPE_CHECKING:
    from kekkai.scanners.base import Finding


@dataclass(frozen=True)
class OWASPCategory:
    """OWASP Top 10 category definition."""

    id: str
    name: str
    description: str
    cwes: frozenset[int]
    rule_patterns: tuple[str, ...]


# OWASP Top 10 2025 Categories with CWE mappings
OWASP_TOP_10: dict[str, OWASPCategory] = {
    "A01": OWASPCategory(
        id="A01:2025",
        name="Broken Access Control",
        description=(
            "Restrictions on authenticated users are not properly enforced. "
            "Now includes SSRF vulnerabilities."
        ),
        cwes=frozenset(
            {
                22,
                23,
                35,
                59,  # Path traversal
                200,
                201,
                219,  # Information exposure
                264,
                275,
                276,
                284,
                285,  # Permissions
                352,  # CSRF
                359,
                377,
                402,
                425,
                441,
                497,
                538,
                540,
                548,
                552,
                566,
                601,  # Open redirect
                639,
                651,
                668,
                706,
                862,
                863,  # Missing authorization
                913,
                918,  # SSRF (moved from A10:2021)
                922,
                1275,
            }
        ),
        rule_patterns=(
            "access-control",
            "authorization",
            "idor",
            "path-traversal",
            "directory-traversal",
            "ssrf",
            "server-side-request",
            "open-redirect",
        ),
    ),
    "A02": OWASPCategory(
        id="A02:2025",
        name="Security Misconfiguration",
        description=(
            "Missing security hardening or improperly configured permissions. "
            "Moved up from #5 in 2021."
        ),
        cwes=frozenset(
            {
                2,
                11,
                13,
                15,
                16,
                260,
                315,
                520,
                526,
                537,
                541,
                547,
                611,  # XXE
                614,
                756,
                776,
                942,
                1004,
                1032,
                1174,
            }
        ),
        rule_patterns=(
            "misconfiguration",
            "config",
            "default",
            "debug",
            "verbose",
            "hardcoded",
            "xxe",
        ),
    ),
    "A03": OWASPCategory(
        id="A03:2025",
        name="Software Supply Chain Failures",
        description=(
            "Vulnerabilities in software dependencies, build systems, and "
            "distribution infrastructure. Replaces Vulnerable Components from 2021."
        ),
        cwes=frozenset(
            {
                426,  # Untrusted search path
                494,  # Download without integrity check
                506,  # Embedded malicious code
                829,  # Inclusion of untrusted functionality
                937,  # Using components with known vulnerabilities
                1035,  # Reliance on reverse DNS
                1104,  # Use of unmaintained third-party components
            }
        ),
        rule_patterns=(
            "supply-chain",
            "dependency",
            "component",
            "outdated",
            "cve-",
            "vulnerability",
            "sbom",
            "third-party",
        ),
    ),
    "A04": OWASPCategory(
        id="A04:2025",
        name="Cryptographic Failures",
        description=(
            "Failures related to cryptography leading to sensitive data exposure. "
            "Moved down from #2 in 2021."
        ),
        cwes=frozenset(
            {
                261,
                296,
                310,
                319,  # Cleartext transmission
                320,
                321,
                322,
                323,
                324,
                325,
                326,
                327,
                328,
                329,  # Weak crypto
                330,
                331,
                335,
                336,
                337,
                338,
                339,
                340,
                347,
                523,
                720,
                757,
                759,
                760,
                780,
                818,
                916,
            }
        ),
        rule_patterns=(
            "crypto",
            "encryption",
            "hash",
            "ssl",
            "tls",
            "certificate",
            "weak-crypto",
            "cleartext",
        ),
    ),
    "A05": OWASPCategory(
        id="A05:2025",
        name="Injection",
        description=(
            "User-supplied data is not validated, filtered, or sanitized. "
            "Moved down from #3 in 2021."
        ),
        cwes=frozenset(
            {
                20,  # Improper input validation
                74,
                75,
                77,
                78,
                79,
                80,
                83,
                87,
                88,
                89,  # SQL injection
                90,
                91,
                93,
                94,
                95,
                96,
                97,
                98,
                99,
                100,
                113,
                116,
                138,
                184,
                470,
                471,
                564,
                610,
                643,
                644,
                652,
                917,
            }
        ),
        rule_patterns=(
            "injection",
            "sqli",
            "xss",
            "command-injection",
            "os-command",
            "ldap",
            "xpath",
            "nosql",
            "template-injection",
        ),
    ),
    "A06": OWASPCategory(
        id="A06:2025",
        name="Insecure Design",
        description=("Missing or ineffective control design. Moved down from #4 in 2021."),
        cwes=frozenset(
            {
                73,
                183,
                209,
                213,
                235,
                256,
                257,
                266,
                269,
                280,
                311,
                312,
                313,
                316,
                419,
                430,
                434,
                444,
                451,
                472,
                501,
                522,
                525,
                539,
                579,
                598,
                602,
                642,
                646,
                650,
                653,
                656,
                657,
                799,
                807,
                840,
                841,
                927,
                1021,
                1173,
            }
        ),
        rule_patterns=(
            "insecure-design",
            "business-logic",
            "threat-model",
            "race-condition",
        ),
    ),
    "A07": OWASPCategory(
        id="A07:2025",
        name="Authentication Failures",
        description=(
            "Functions related to authentication and session management "
            "are incorrectly implemented. Renamed from 'Identification and "
            "Authentication Failures'."
        ),
        cwes=frozenset(
            {
                255,
                259,
                287,
                288,
                290,
                294,
                295,
                297,
                300,
                302,
                304,
                306,
                307,
                346,
                384,
                521,  # Weak password
                613,  # Session expiration
                620,
                640,
                798,  # Hardcoded credentials
                940,
                1216,
            }
        ),
        rule_patterns=(
            "authentication",
            "auth",
            "session",
            "password",
            "credential",
            "login",
            "jwt",
            "mfa",
            "2fa",
        ),
    ),
    "A08": OWASPCategory(
        id="A08:2025",
        name="Software or Data Integrity Failures",
        description=("Code and infrastructure that does not protect against integrity violations."),
        cwes=frozenset(
            {
                345,  # Insufficient verification
                353,
                426,
                494,
                502,  # Deserialization
                565,
                784,
                829,
                830,
                913,
                915,
            }
        ),
        rule_patterns=(
            "deserialization",
            "integrity",
            "signature",
            "ci-cd",
            "update",
            "tampering",
        ),
    ),
    "A09": OWASPCategory(
        id="A09:2025",
        name="Security Logging and Alerting Failures",
        description=(
            "Insufficient logging, detection, monitoring, and active response. "
            "Minor rename to include 'Alerting'."
        ),
        cwes=frozenset(
            {
                117,  # Log injection
                223,  # Omission of security info
                532,  # Info exposure through logs
                778,
                779,  # Insufficient logging
            }
        ),
        rule_patterns=(
            "logging",
            "monitoring",
            "audit",
            "log-injection",
            "alerting",
        ),
    ),
    "A10": OWASPCategory(
        id="A10:2025",
        name="Mishandling of Exceptional Conditions",
        description=(
            "Improper handling of errors, exceptions, and unexpected inputs. NEW category in 2025."
        ),
        cwes=frozenset(
            {
                248,  # Uncaught exception
                252,
                253,  # Unchecked return value
                390,
                391,  # Detection of error condition
                392,  # Missing report of error
                397,  # Throwing generic exception
                754,  # Improper check for unusual conditions
                755,  # Improper handling of exceptional conditions
                756,  # Missing custom error page
                757,  # Selection of insecure algorithm during negotiation
            }
        ),
        rule_patterns=(
            "exception",
            "error-handling",
            "uncaught",
            "unhandled",
            "edge-case",
            "boundary",
            "overflow",
        ),
    ),
}


def _extract_cwe_id(cwe_str: str | None) -> int | None:
    """Extract numeric CWE ID from string like 'CWE-79'."""
    if not cwe_str:
        return None
    cwe_str = cwe_str.upper().replace("CWE-", "").replace("CWE", "")
    try:
        return int(cwe_str.strip())
    except ValueError:
        return None


def map_to_owasp(finding: Finding) -> list[FrameworkControl]:
    """Map a finding to OWASP Top 10 2025 categories."""
    controls: list[FrameworkControl] = []

    # Extract CWE ID
    cwe_id = _extract_cwe_id(finding.cwe)

    # Check rule_id patterns
    rule_id_lower = (finding.rule_id or "").lower()
    title_lower = finding.title.lower()

    for category in OWASP_TOP_10.values():
        matched = False

        # Match by CWE
        if cwe_id and cwe_id in category.cwes:
            matched = True

        # Match by rule pattern
        if not matched:
            for pattern in category.rule_patterns:
                if pattern in rule_id_lower or pattern in title_lower:
                    matched = True
                    break

        # Match CVEs to A03 (Software Supply Chain Failures)
        if not matched and category.id == "A03:2025" and finding.cve:
            matched = True

        if matched:
            controls.append(
                FrameworkControl(
                    framework="OWASP",
                    control_id=category.id,
                    title=category.name,
                    description=category.description,
                    requirement_level="required",
                )
            )

    return controls
