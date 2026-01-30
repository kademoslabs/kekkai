"""Compliance framework mapping for security findings.

Maps security findings to compliance framework controls for audit reporting.

Supported frameworks:
- PCI-DSS v4.0 (Payment Card Industry)
- SOC 2 Type II (Service Organization Controls)
- OWASP Top 10 2025 (Web Application Security)
- OWASP Agentic AI Top 10 (Autonomous AI Agent Security)
- HIPAA (Health Insurance Portability and Accountability)

Security considerations:
- Mappings are advisory, not compliance certifications
- Always include disclaimer in generated reports
- Raw finding data shown, no compliance assessments

ASVS Requirements:
- V5.3.1: Output encoding for reports
- V8.1.1: Reports stored in user-specified paths only
"""

from __future__ import annotations

from .hipaa import HIPAA_SAFEGUARDS, HIPAASafeguard, map_to_hipaa
from .mappings import (
    ComplianceMapping,
    ComplianceMappingResult,
    FrameworkControl,
    map_finding_to_frameworks,
    map_findings_to_all_frameworks,
)
from .owasp import OWASP_TOP_10, OWASPCategory, map_to_owasp
from .owasp_agentic import (
    OWASP_AGENTIC_TOP_10,
    OWASPAgenticCategory,
    map_to_owasp_agentic,
)
from .pci_dss import PCI_DSS_CONTROLS, PCIDSSControl, map_to_pci_dss
from .soc2 import SOC2_CRITERIA, SOC2Criterion, map_to_soc2

__all__ = [
    # Core mapping
    "ComplianceMapping",
    "ComplianceMappingResult",
    "FrameworkControl",
    "map_finding_to_frameworks",
    "map_findings_to_all_frameworks",
    # PCI-DSS
    "PCIDSSControl",
    "PCI_DSS_CONTROLS",
    "map_to_pci_dss",
    # SOC 2
    "SOC2Criterion",
    "SOC2_CRITERIA",
    "map_to_soc2",
    # OWASP Top 10 2025
    "OWASPCategory",
    "OWASP_TOP_10",
    "map_to_owasp",
    # OWASP Agentic AI Top 10
    "OWASPAgenticCategory",
    "OWASP_AGENTIC_TOP_10",
    "map_to_owasp_agentic",
    # HIPAA
    "HIPAASafeguard",
    "HIPAA_SAFEGUARDS",
    "map_to_hipaa",
]
