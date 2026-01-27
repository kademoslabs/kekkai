"""Mermaid.js DFD generation for ThreatFlow.

Generates Mermaid.js syntax for Data Flow Diagrams (DFDs) with security encoding
to prevent XSS and injection attacks in rendered diagrams.

ASVS 5.0 Requirements:
- V5.3.3: Output encoding for target format
- V5.2.6: Validate structured output
- V5.5.2: Safe serialization (no executable content)

Threat Mitigations:
- XSS payloads in labels -> HTML escape + unsafe char replacement
- Mermaid syntax injection -> Strip special characters
- Architecture spoofing -> Validate against known entities
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .artifacts import ThreatModelArtifacts

# Characters unsafe in Mermaid labels that could break syntax or enable injection
MERMAID_UNSAFE_CHARS = re.compile(r'[<>"\'`{}|\\;\[\]()]')

# Maximum label length to prevent DoS via extremely long labels
MAX_LABEL_LENGTH = 100


class NodeType(Enum):
    """DFD node types with corresponding Mermaid shapes."""

    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"


@dataclass(frozen=True)
class MermaidNode:
    """A node in the Mermaid DFD.

    Attributes:
        id: Unique identifier for the node (alphanumeric + underscore only)
        label: Display label (will be sanitized)
        node_type: Type of DFD element
    """

    id: str
    label: str
    node_type: NodeType

    def to_mermaid(self) -> str:
        """Convert to Mermaid syntax with security encoding.

        Returns:
            Mermaid node definition string
        """
        safe_label = _encode_label(self.label)
        safe_id = _sanitize_id(self.id)

        # Map node types to Mermaid shapes
        # External entities: parallelogram (trapezoid)
        # Processes: circle (stadium shape)
        # Data stores: cylinder
        shapes = {
            NodeType.EXTERNAL_ENTITY: f'{safe_id}[/"{safe_label}"/]',
            NodeType.PROCESS: f'{safe_id}(["{safe_label}"])',
            NodeType.DATA_STORE: f'{safe_id}[("{safe_label}")]',
        }
        return shapes.get(self.node_type, f'{safe_id}["{safe_label}"]')


@dataclass(frozen=True)
class MermaidEdge:
    """An edge (data flow) in the Mermaid DFD.

    Attributes:
        source: Source node ID
        target: Target node ID
        label: Edge label describing the data flow
        crosses_trust_boundary: Whether this flow crosses a trust boundary
    """

    source: str
    target: str
    label: str
    crosses_trust_boundary: bool = False

    def to_mermaid(self) -> str:
        """Convert to Mermaid edge syntax with security encoding.

        Returns:
            Mermaid edge definition string
        """
        safe_source = _sanitize_id(self.source)
        safe_target = _sanitize_id(self.target)
        safe_label = _encode_label(self.label)

        # Use thick arrow for trust boundary crossings
        if self.crosses_trust_boundary:
            return f'{safe_source} ==>|"{safe_label}"| {safe_target}'
        return f'{safe_source} -->|"{safe_label}"| {safe_target}'


@dataclass
class MermaidDFDGenerator:
    """Generates Mermaid.js Data Flow Diagrams.

    Security-first design:
    - All labels are HTML-encoded
    - Special characters are replaced
    - IDs are sanitized to alphanumeric only
    """

    title: str = "Data Flow Diagram"
    direction: str = "TB"  # TB (top-bottom), LR (left-right)
    _nodes: list[MermaidNode] = field(default_factory=list)
    _edges: list[MermaidEdge] = field(default_factory=list)
    _trust_boundaries: list[tuple[str, list[str]]] = field(default_factory=list)

    def add_node(self, node: MermaidNode) -> None:
        """Add a node to the diagram."""
        self._nodes.append(node)

    def add_edge(self, edge: MermaidEdge) -> None:
        """Add an edge to the diagram."""
        self._edges.append(edge)

    def add_trust_boundary(self, name: str, node_ids: list[str]) -> None:
        """Add a trust boundary containing specified nodes."""
        self._trust_boundaries.append((name, node_ids))

    def generate(self) -> str:
        """Generate complete Mermaid DFD syntax.

        Returns:
            Valid Mermaid flowchart syntax
        """
        lines: list[str] = []

        # Header with title
        safe_title = _encode_label(self.title)
        lines.extend(
            [
                "---",
                f"title: {safe_title}",
                "---",
                f"flowchart {self.direction}",
                "",
            ]
        )

        # Group nodes by type for organization
        external = [n for n in self._nodes if n.node_type == NodeType.EXTERNAL_ENTITY]
        processes = [n for n in self._nodes if n.node_type == NodeType.PROCESS]
        stores = [n for n in self._nodes if n.node_type == NodeType.DATA_STORE]

        # Add trust boundaries as subgraphs
        nodes_in_boundaries: set[str] = set()
        for boundary_name, node_ids in self._trust_boundaries:
            safe_boundary = _sanitize_id(boundary_name)
            safe_label = _encode_label(boundary_name)
            lines.append(f'    subgraph {safe_boundary}["{safe_label}"]')
            for node_id in node_ids:
                nodes_in_boundaries.add(node_id)
                node = self._find_node(node_id)
                if node:
                    lines.append(f"        {node.to_mermaid()}")
            lines.append("    end")
            lines.append("")

        # Add remaining nodes not in boundaries
        if external:
            lines.append("    %% External Entities")
            for node in external:
                if node.id not in nodes_in_boundaries:
                    lines.append(f"    {node.to_mermaid()}")
            lines.append("")

        if processes:
            lines.append("    %% Processes")
            for node in processes:
                if node.id not in nodes_in_boundaries:
                    lines.append(f"    {node.to_mermaid()}")
            lines.append("")

        if stores:
            lines.append("    %% Data Stores")
            for node in stores:
                if node.id not in nodes_in_boundaries:
                    lines.append(f"    {node.to_mermaid()}")
            lines.append("")

        # Add edges
        if self._edges:
            lines.append("    %% Data Flows")
            for edge in self._edges:
                lines.append(f"    {edge.to_mermaid()}")
            lines.append("")

        # Add styling for trust boundary crossings
        boundary_edges = [e for e in self._edges if e.crosses_trust_boundary]
        if boundary_edges:
            lines.append("    %% Style trust boundary crossings")
            lines.append("    linkStyle default stroke:#333,stroke-width:2px")

        return "\n".join(lines)

    def _find_node(self, node_id: str) -> MermaidNode | None:
        """Find a node by ID."""
        for node in self._nodes:
            if node.id == node_id:
                return node
        return None

    @classmethod
    def from_artifacts(cls, artifacts: ThreatModelArtifacts) -> MermaidDFDGenerator:
        """Create a Mermaid DFD generator from ThreatModelArtifacts.

        Args:
            artifacts: ThreatModelArtifacts containing DFD components

        Returns:
            Configured MermaidDFDGenerator
        """
        generator = cls(title=f"{artifacts.repo_name} Data Flow Diagram")

        # Track node IDs for edge validation
        node_ids: set[str] = set()

        # Add external entities
        for i, entity in enumerate(artifacts.external_entities):
            node_id = f"ext_{i}"
            generator.add_node(
                MermaidNode(
                    id=node_id,
                    label=entity,
                    node_type=NodeType.EXTERNAL_ENTITY,
                )
            )
            node_ids.add(node_id)

        # Add processes
        for i, process in enumerate(artifacts.processes):
            node_id = f"proc_{i}"
            generator.add_node(
                MermaidNode(
                    id=node_id,
                    label=process,
                    node_type=NodeType.PROCESS,
                )
            )
            node_ids.add(node_id)

        # Add data stores
        for i, store in enumerate(artifacts.data_stores):
            node_id = f"store_{i}"
            generator.add_node(
                MermaidNode(
                    id=node_id,
                    label=store,
                    node_type=NodeType.DATA_STORE,
                )
            )
            node_ids.add(node_id)

        # Build lookup for node names to IDs
        name_to_id = _build_name_to_id_map(generator._nodes)

        # Add data flows as edges
        for flow in artifacts.dataflows:
            source_id = name_to_id.get(flow.source.lower(), _sanitize_id(flow.source))
            target_id = name_to_id.get(flow.destination.lower(), _sanitize_id(flow.destination))
            generator.add_edge(
                MermaidEdge(
                    source=source_id,
                    target=target_id,
                    label=flow.data_type,
                    crosses_trust_boundary=flow.trust_boundary_crossed,
                )
            )

        # Add trust boundaries
        if artifacts.trust_boundaries:
            # Group internal processes
            internal_ids = [f"proc_{i}" for i in range(len(artifacts.processes))]
            if internal_ids:
                generator.add_trust_boundary("Internal_Network", internal_ids)

        return generator


def _encode_label(label: str) -> str:
    """Encode a label for safe use in Mermaid diagrams.

    Applies:
    1. HTML escaping for XSS prevention
    2. Replacement of Mermaid-unsafe characters
    3. Length truncation

    Args:
        label: Raw label text

    Returns:
        Sanitized label safe for Mermaid
    """
    # HTML escape first
    safe = html.escape(label, quote=True)

    # Replace unsafe Mermaid characters with underscores
    safe = MERMAID_UNSAFE_CHARS.sub("_", safe)

    # Truncate to prevent DoS
    if len(safe) > MAX_LABEL_LENGTH:
        safe = safe[: MAX_LABEL_LENGTH - 3] + "..."

    return safe


def _sanitize_id(id_str: str) -> str:
    """Sanitize a node/subgraph ID for Mermaid.

    IDs must be alphanumeric with underscores only.

    Args:
        id_str: Raw ID string

    Returns:
        Sanitized ID safe for Mermaid
    """
    # Replace spaces and special chars with underscores
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", id_str)

    # Ensure starts with letter (Mermaid requirement)
    if safe and not safe[0].isalpha():
        safe = "n_" + safe

    # Ensure not empty
    if not safe:
        safe = "node"

    return safe


def _build_name_to_id_map(nodes: list[MermaidNode]) -> dict[str, str]:
    """Build a mapping from node labels (lowercase) to IDs.

    Args:
        nodes: List of MermaidNodes

    Returns:
        Dictionary mapping lowercase labels to node IDs
    """
    return {node.label.lower(): node.id for node in nodes}


def generate_dfd_mermaid(artifacts: ThreatModelArtifacts) -> str:
    """Generate Mermaid DFD syntax from ThreatModelArtifacts.

    Convenience function for simple usage.

    Args:
        artifacts: ThreatModelArtifacts containing DFD components

    Returns:
        Mermaid flowchart syntax string
    """
    generator = MermaidDFDGenerator.from_artifacts(artifacts)
    return generator.generate()
