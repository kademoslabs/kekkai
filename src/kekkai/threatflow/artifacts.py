"""Artifact generation for ThreatFlow threat models.

Generates structured Markdown artifacts:
- THREATS.md: Identified threats with STRIDE categorization
- DATAFLOWS.md: Data flow diagram description
- DATAFLOW.mmd: Mermaid.js DFD syntax (Milestone 3)
- ASSUMPTIONS.md: Analysis assumptions and limitations

ASVS V15.3.1: Output only the required subset of data.
ASVS V5.3.3: Output encoding for Mermaid format.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class ThreatEntry:
    """A single threat entry."""

    id: str
    title: str
    category: str
    affected_component: str
    description: str
    risk_level: str
    mitigation: str
    owasp_category: str | None = None

    def to_markdown(self) -> str:
        """Convert to Markdown format."""
        owasp = f"\n- **OWASP**: {self.owasp_category}" if self.owasp_category else ""
        return f"""### {self.id}: {self.title}
- **Category**: {self.category}
- **Affected Component**: {self.affected_component}
- **Risk Level**: {self.risk_level}{owasp}

**Description**: {self.description}

**Mitigation**: {self.mitigation}
"""

    def to_dict(self) -> dict[str, str | None]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "affected_component": self.affected_component,
            "description": self.description,
            "risk_level": self.risk_level,
            "mitigation": self.mitigation,
            "owasp_category": self.owasp_category,
        }


@dataclass
class DataFlowEntry:
    """A data flow entry."""

    source: str
    destination: str
    data_type: str
    trust_boundary_crossed: bool = False
    notes: str | None = None

    def to_markdown(self) -> str:
        """Convert to Markdown format."""
        boundary = " [CROSSES TRUST BOUNDARY]" if self.trust_boundary_crossed else ""
        notes = f" - {self.notes}" if self.notes else ""
        return f"- {self.source} -> {self.destination}: {self.data_type}{boundary}{notes}"


@dataclass
class ThreatModelArtifacts:
    """Container for all threat model artifacts."""

    threats: list[ThreatEntry] = field(default_factory=list)
    dataflows: list[DataFlowEntry] = field(default_factory=list)
    external_entities: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    data_stores: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    scope_notes: list[str] = field(default_factory=list)
    environment_notes: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    repo_name: str = ""
    analysis_timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    model_used: str = "unknown"
    files_analyzed: int = 0
    languages_detected: list[str] = field(default_factory=list)

    def threat_count_by_risk(self) -> dict[str, int]:
        """Count threats by risk level."""
        counts: dict[str, int] = {}
        for threat in self.threats:
            level = threat.risk_level.lower()
            counts[level] = counts.get(level, 0) + 1
        return counts

    def threat_count_by_stride(self) -> dict[str, int]:
        """Count threats by STRIDE category."""
        counts: dict[str, int] = {}
        for threat in self.threats:
            cat = threat.category
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "threats": [t.to_dict() for t in self.threats],
            "dataflows": [
                {
                    "source": df.source,
                    "destination": df.destination,
                    "data_type": df.data_type,
                    "trust_boundary_crossed": df.trust_boundary_crossed,
                }
                for df in self.dataflows
            ],
            "external_entities": self.external_entities,
            "processes": self.processes,
            "data_stores": self.data_stores,
            "trust_boundaries": self.trust_boundaries,
            "assumptions": self.assumptions,
            "limitations": self.limitations,
            "metadata": {
                "repo_name": self.repo_name,
                "analysis_timestamp": self.analysis_timestamp,
                "model_used": self.model_used,
                "files_analyzed": self.files_analyzed,
                "languages_detected": self.languages_detected,
            },
        }


@dataclass
class ArtifactGenerator:
    """Generates threat model artifact files."""

    output_dir: Path
    repo_name: str = ""

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)

    def generate_threats_md(self, artifacts: ThreatModelArtifacts) -> str:
        """Generate THREATS.md content."""
        lines = [
            "# Threat Model: Identified Threats",
            "",
            f"> Generated: {artifacts.analysis_timestamp}",
            f"> Repository: {artifacts.repo_name or 'Unknown'}",
            f"> Model: {artifacts.model_used}",
            "",
            "## Summary",
            "",
        ]

        # Add risk summary
        risk_counts = artifacts.threat_count_by_risk()
        lines.append("| Risk Level | Count |")
        lines.append("|------------|-------|")
        for level in ["critical", "high", "medium", "low"]:
            count = risk_counts.get(level, 0)
            lines.append(f"| {level.capitalize()} | {count} |")
        lines.append(f"| **Total** | **{len(artifacts.threats)}** |")
        lines.append("")

        # Add STRIDE summary
        lines.append("### By STRIDE Category")
        lines.append("")
        stride_counts = artifacts.threat_count_by_stride()
        for cat, count in sorted(stride_counts.items()):
            lines.append(f"- {cat}: {count}")
        lines.append("")

        # Add detailed threats
        lines.append("## Detailed Threats")
        lines.append("")

        for threat in artifacts.threats:
            lines.append(threat.to_markdown())
            lines.append("")

        return "\n".join(lines)

    def generate_dataflows_md(self, artifacts: ThreatModelArtifacts) -> str:
        """Generate DATAFLOWS.md content."""
        lines = [
            "# Threat Model: Data Flow Diagram",
            "",
            f"> Generated: {artifacts.analysis_timestamp}",
            f"> Repository: {artifacts.repo_name or 'Unknown'}",
            "",
            "## External Entities",
            "",
        ]

        for entity in artifacts.external_entities:
            lines.append(f"- {entity}")
        lines.append("")

        lines.append("## Processes")
        lines.append("")
        for process in artifacts.processes:
            lines.append(f"- {process}")
        lines.append("")

        lines.append("## Data Stores")
        lines.append("")
        for store in artifacts.data_stores:
            lines.append(f"- {store}")
        lines.append("")

        lines.append("## Data Flows")
        lines.append("")
        for flow in artifacts.dataflows:
            lines.append(flow.to_markdown())
        lines.append("")

        lines.append("## Trust Boundaries")
        lines.append("")
        for boundary in artifacts.trust_boundaries:
            lines.append(f"- {boundary}")
        lines.append("")

        return "\n".join(lines)

    def generate_assumptions_md(self, artifacts: ThreatModelArtifacts) -> str:
        """Generate ASSUMPTIONS.md content."""
        lines = [
            "# Threat Model: Assumptions and Limitations",
            "",
            f"> Generated: {artifacts.analysis_timestamp}",
            f"> Repository: {artifacts.repo_name or 'Unknown'}",
            "",
            "## Scope",
            "",
        ]

        for note in artifacts.scope_notes:
            lines.append(f"- {note}")
        if not artifacts.scope_notes:
            lines.append("- This analysis covers the provided repository code")
        lines.append("")

        lines.append("## Environment Assumptions")
        lines.append("")
        for note in artifacts.environment_notes:
            lines.append(f"- {note}")
        if not artifacts.environment_notes:
            lines.append("- Standard deployment environment assumed")
        lines.append("")

        lines.append("## Analysis Assumptions")
        lines.append("")
        for assumption in artifacts.assumptions:
            lines.append(f"- {assumption}")
        if not artifacts.assumptions:
            lines.append("- All third-party dependencies are from trusted sources")
        lines.append("")

        lines.append("## Limitations")
        lines.append("")
        for limitation in artifacts.limitations:
            lines.append(f"- {limitation}")

        # Always add standard limitations
        lines.extend(
            [
                "- This is an automated first-pass analysis",
                "- Human review and validation is required",
                "- Runtime behavior was not analyzed",
                "- Configuration and deployment specifics may vary",
            ]
        )
        lines.append("")

        lines.append("## Metadata")
        lines.append("")
        lines.append(f"- Files analyzed: {artifacts.files_analyzed}")
        lines.append(f"- Languages: {', '.join(artifacts.languages_detected) or 'Unknown'}")
        lines.append(f"- Model: {artifacts.model_used}")
        lines.append("")

        return "\n".join(lines)

    def write_artifacts(self, artifacts: ThreatModelArtifacts) -> list[Path]:
        """Write all artifact files and return paths."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []

        # Write THREATS.md
        threats_path = self.output_dir / "THREATS.md"
        threats_path.write_text(self.generate_threats_md(artifacts), encoding="utf-8")
        written.append(threats_path)

        # Write DATAFLOWS.md
        dataflows_path = self.output_dir / "DATAFLOWS.md"
        dataflows_path.write_text(self.generate_dataflows_md(artifacts), encoding="utf-8")
        written.append(dataflows_path)

        # Write ASSUMPTIONS.md
        assumptions_path = self.output_dir / "ASSUMPTIONS.md"
        assumptions_path.write_text(self.generate_assumptions_md(artifacts), encoding="utf-8")
        written.append(assumptions_path)

        # Write JSON summary
        json_path = self.output_dir / "threat-model.json"
        json_path.write_text(
            json.dumps(artifacts.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        written.append(json_path)

        # Write Mermaid DFD (Milestone 3)
        mermaid_path = self.output_dir / "DATAFLOW.mmd"
        mermaid_path.write_text(self.generate_dataflow_mmd(artifacts), encoding="utf-8")
        written.append(mermaid_path)

        return written

    def generate_dataflow_mmd(self, artifacts: ThreatModelArtifacts) -> str:
        """Generate Mermaid.js DFD syntax from artifacts.

        Security: All labels are HTML-encoded and special characters sanitized
        to prevent XSS when rendered in browsers.

        Args:
            artifacts: ThreatModelArtifacts containing DFD components

        Returns:
            Mermaid flowchart syntax string
        """
        from .mermaid import MermaidDFDGenerator

        generator = MermaidDFDGenerator.from_artifacts(artifacts)
        return generator.generate()

    def parse_llm_threats(self, llm_output: str) -> list[ThreatEntry]:
        """Parse LLM output into structured ThreatEntry objects.

        Attempts to extract threats from various Markdown formats.
        """
        threats: list[ThreatEntry] = []

        # Split by threat headers first
        threat_blocks = re.split(r"(?=###?\s*T\d{3})", llm_output)

        # Pattern for individual threat fields
        for block in threat_blocks:
            if not block.strip():
                continue

            # Extract threat ID and title
            header_match = re.search(r"###?\s*(?P<id>T\d{3}):?\s*(?P<title>[^\n]+)", block)
            if not header_match:
                continue

            # Extract fields
            category_match = re.search(
                r"(?:\*\*Category\*\*|Category)[:\s]*(?P<value>[^\n*]+)", block, re.IGNORECASE
            )
            component_match = re.search(
                r"(?:\*\*Affected[^*]*\*\*|Affected[^:]*)[:\s]*(?P<value>[^\n*]+)",
                block,
                re.IGNORECASE,
            )
            desc_match = re.search(
                r"(?:\*\*Description\*\*|Description)[:\s]*(?P<value>[^\n]+)", block, re.IGNORECASE
            )
            risk_match = re.search(
                r"(?:\*\*Risk[^*]*\*\*|Risk[^:]*)[:\s]*(?P<value>[^\n*]+)", block, re.IGNORECASE
            )
            mitigation_match = re.search(
                r"(?:\*\*Mitigation\*\*|Mitigation)[:\s]*(?P<value>[^\n]+)", block, re.IGNORECASE
            )

            threats.append(
                ThreatEntry(
                    id=header_match.group("id").strip(),
                    title=header_match.group("title").strip(),
                    category=category_match.group("value").strip() if category_match else "Unknown",
                    affected_component=(
                        component_match.group("value").strip() if component_match else "Unknown"
                    ),
                    description=desc_match.group("value").strip() if desc_match else "",
                    risk_level=risk_match.group("value").strip() if risk_match else "Unknown",
                    mitigation=mitigation_match.group("value").strip() if mitigation_match else "",
                )
            )

        return threats

    def parse_llm_dataflows(
        self, llm_output: str
    ) -> tuple[
        list[str],  # external_entities
        list[str],  # processes
        list[str],  # data_stores
        list[DataFlowEntry],  # dataflows
        list[str],  # trust_boundaries
    ]:
        """Parse LLM output into structured dataflow components."""
        external_entities: list[str] = []
        processes: list[str] = []
        data_stores: list[str] = []
        dataflows: list[DataFlowEntry] = []
        trust_boundaries: list[str] = []

        # Current section being parsed
        current_section = ""

        for line in llm_output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Detect section headers
            lower_line = line.lower()
            if "external" in lower_line and ("entities" in lower_line or "##" in line):
                current_section = "external"
                continue
            elif "process" in lower_line and "##" in line:
                current_section = "processes"
                continue
            elif "data stor" in lower_line and "##" in line:
                current_section = "stores"
                continue
            elif "data flow" in lower_line and "##" in line:
                current_section = "flows"
                continue
            elif "trust" in lower_line and "boundar" in lower_line:
                current_section = "boundaries"
                continue

            # Parse list items
            if line.startswith("-"):
                item = line[1:].strip()
                item = re.sub(r"^\*\*([^*]+)\*\*:?", r"\1:", item)  # Remove bold

                if current_section == "external":
                    external_entities.append(item)
                elif current_section == "processes":
                    processes.append(item)
                elif current_section == "stores":
                    data_stores.append(item)
                elif current_section == "boundaries":
                    trust_boundaries.append(item)
                elif current_section == "flows":
                    # Parse flow format: Source -> Destination: Data Type
                    flow_match = re.match(
                        r"([^->]+)\s*->\s*([^:]+):\s*(.+)",
                        item,
                    )
                    if flow_match:
                        dataflows.append(
                            DataFlowEntry(
                                source=flow_match.group(1).strip(),
                                destination=flow_match.group(2).strip(),
                                data_type=flow_match.group(3).strip(),
                                trust_boundary_crossed="boundary" in item.lower()
                                or "trust" in item.lower(),
                            )
                        )

        return external_entities, processes, data_stores, dataflows, trust_boundaries
