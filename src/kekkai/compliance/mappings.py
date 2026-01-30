"""Core compliance mapping engine.

Maps security findings to compliance framework controls using CWE IDs,
rule patterns, and severity levels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from kekkai.scanners.base import Finding


@dataclass(frozen=True)
class FrameworkControl:
    """A single compliance framework control."""

    framework: str
    control_id: str
    title: str
    description: str
    requirement_level: str = "required"  # required, recommended, optional


@dataclass
class ComplianceMapping:
    """Mapping of a finding to compliance controls."""

    finding_hash: str
    finding_title: str
    finding_severity: str
    controls: list[FrameworkControl] = field(default_factory=list)

    def add_control(self, control: FrameworkControl) -> None:
        """Add a control to this mapping."""
        self.controls.append(control)

    def has_framework(self, framework: str) -> bool:
        """Check if any control from a framework is mapped."""
        return any(c.framework == framework for c in self.controls)


@dataclass
class ComplianceMappingResult:
    """Result of mapping findings to all frameworks."""

    mappings: list[ComplianceMapping] = field(default_factory=list)
    framework_summary: dict[str, int] = field(default_factory=dict)
    unmapped_count: int = 0
    total_findings: int = 0

    def get_controls_by_framework(self, framework: str) -> list[FrameworkControl]:
        """Get all unique controls for a framework."""
        seen: set[str] = set()
        result: list[FrameworkControl] = []
        for mapping in self.mappings:
            for control in mapping.controls:
                if control.framework == framework and control.control_id not in seen:
                    seen.add(control.control_id)
                    result.append(control)
        return sorted(result, key=lambda c: c.control_id)

    def get_findings_for_control(self, framework: str, control_id: str) -> list[ComplianceMapping]:
        """Get all findings mapped to a specific control."""
        return [
            m
            for m in self.mappings
            if any(c.framework == framework and c.control_id == control_id for c in m.controls)
        ]


def map_finding_to_frameworks(finding: Finding) -> ComplianceMapping:
    """Map a single finding to all applicable compliance frameworks."""
    from .hipaa import map_to_hipaa
    from .owasp import map_to_owasp
    from .owasp_agentic import map_to_owasp_agentic
    from .pci_dss import map_to_pci_dss
    from .soc2 import map_to_soc2

    mapping = ComplianceMapping(
        finding_hash=finding.dedupe_hash(),
        finding_title=finding.title,
        finding_severity=finding.severity.value,
    )

    # Map to each framework
    for control in map_to_pci_dss(finding):
        mapping.add_control(control)

    for control in map_to_soc2(finding):
        mapping.add_control(control)

    for control in map_to_owasp(finding):
        mapping.add_control(control)

    for control in map_to_owasp_agentic(finding):
        mapping.add_control(control)

    for control in map_to_hipaa(finding):
        mapping.add_control(control)

    return mapping


def map_findings_to_all_frameworks(
    findings: Sequence[Finding],
) -> ComplianceMappingResult:
    """Map all findings to compliance frameworks."""
    result = ComplianceMappingResult(total_findings=len(findings))

    framework_counts: dict[str, set[str]] = {
        "PCI-DSS": set(),
        "SOC2": set(),
        "OWASP": set(),
        "OWASP-Agentic": set(),
        "HIPAA": set(),
    }

    for finding in findings:
        mapping = map_finding_to_frameworks(finding)
        result.mappings.append(mapping)

        if not mapping.controls:
            result.unmapped_count += 1
        else:
            for control in mapping.controls:
                if control.framework in framework_counts:
                    framework_counts[control.framework].add(control.control_id)

    result.framework_summary = {k: len(v) for k, v in framework_counts.items()}

    return result
