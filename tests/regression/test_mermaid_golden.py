"""Regression tests for Mermaid DFD output stability."""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.threatflow import (
    ArtifactGenerator,
    DataFlowEntry,
    ThreatModelArtifacts,
    generate_dfd_mermaid,
)

pytestmark = pytest.mark.regression


class TestMermaidOutputFormat:
    """Golden tests for Mermaid output format stability."""

    def test_mermaid_header_format_stable(self) -> None:
        """Test Mermaid header format is stable."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User"],
            processes=["App"],
            data_stores=["DB"],
            repo_name="test-repo",
        )

        content = generate_dfd_mermaid(artifacts)
        lines = content.split("\n")

        # YAML frontmatter format
        assert lines[0] == "---"
        assert lines[1].startswith("title:")
        assert lines[2] == "---"
        assert "flowchart TB" in lines[3]

    def test_node_shape_format_stable(self) -> None:
        """Test node shape formats are stable."""
        artifacts = ThreatModelArtifacts(
            external_entities=["ExternalEntity"],
            processes=["ProcessNode"],
            data_stores=["DataStore"],
            repo_name="test",
        )

        content = generate_dfd_mermaid(artifacts)

        # External entity uses parallelogram [/"label"/]
        assert '[/"ExternalEntity"/]' in content

        # Process uses stadium (["label"])
        assert '(["ProcessNode"])' in content

        # Data store uses cylinder [("label")]
        assert '[("DataStore")]' in content

    def test_edge_format_stable(self) -> None:
        """Test edge format is stable."""
        artifacts = ThreatModelArtifacts(
            external_entities=["Source"],
            processes=["Target"],
            dataflows=[
                DataFlowEntry(
                    source="Source",
                    destination="Target",
                    data_type="DataFlow",
                    trust_boundary_crossed=False,
                ),
            ],
            repo_name="test",
        )

        content = generate_dfd_mermaid(artifacts)

        # Regular edge format
        assert '-->|"DataFlow"|' in content

    def test_trust_boundary_edge_format_stable(self) -> None:
        """Test trust boundary edge format is stable."""
        artifacts = ThreatModelArtifacts(
            external_entities=["External"],
            processes=["Internal"],
            dataflows=[
                DataFlowEntry(
                    source="External",
                    destination="Internal",
                    data_type="Request",
                    trust_boundary_crossed=True,
                ),
            ],
            repo_name="test",
        )

        content = generate_dfd_mermaid(artifacts)

        # Trust boundary crossing uses thick arrow ==>
        assert '==>|"Request"|' in content

    def test_comment_format_stable(self) -> None:
        """Test comment format is stable."""
        artifacts = ThreatModelArtifacts(
            external_entities=["E"],
            processes=["P"],
            data_stores=["S"],
            repo_name="test",
        )

        content = generate_dfd_mermaid(artifacts)

        # Section comments use Mermaid %% format
        assert "%% External Entities" in content
        assert "%% Processes" in content
        assert "%% Data Stores" in content


class TestDataflowsMdUnchanged:
    """Tests to ensure DATAFLOWS.md format is unchanged."""

    def test_dataflows_md_structure_unchanged(self, tmp_path: Path) -> None:
        """Test DATAFLOWS.md maintains its original structure."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User", "External API"],
            processes=["Application", "Auth Service"],
            data_stores=["Database", "Cache"],
            dataflows=[
                DataFlowEntry(
                    source="User",
                    destination="Application",
                    data_type="HTTP Request",
                    trust_boundary_crossed=True,
                ),
            ],
            trust_boundaries=["Internet -> DMZ"],
            repo_name="test-repo",
        )

        generator = ArtifactGenerator(output_dir=tmp_path, repo_name="test-repo")
        content = generator.generate_dataflows_md(artifacts)

        # Original structure must be preserved
        assert "# Threat Model: Data Flow Diagram" in content
        assert "## External Entities" in content
        assert "## Processes" in content
        assert "## Data Stores" in content
        assert "## Data Flows" in content
        assert "## Trust Boundaries" in content

        # Entities listed correctly
        assert "- User" in content
        assert "- External API" in content
        assert "- Application" in content
        assert "- Database" in content

    def test_dataflows_md_format_unchanged(self, tmp_path: Path) -> None:
        """Test DATAFLOWS.md list format unchanged."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User"],
            processes=["App"],
            dataflows=[
                DataFlowEntry(
                    source="User",
                    destination="App",
                    data_type="Request",
                    trust_boundary_crossed=True,
                ),
            ],
            repo_name="test",
        )

        generator = ArtifactGenerator(output_dir=tmp_path, repo_name="test")
        content = generator.generate_dataflows_md(artifacts)

        # Dataflow format unchanged
        assert "- User -> App: Request" in content
        assert "[CROSSES TRUST BOUNDARY]" in content


class TestWriteArtifactsRegressions:
    """Regression tests for write_artifacts behavior."""

    def test_write_artifacts_file_list_extended(self, tmp_path: Path) -> None:
        """Test write_artifacts returns extended file list including .mmd."""
        artifacts = ThreatModelArtifacts(
            external_entities=["E"],
            processes=["P"],
            repo_name="test",
        )

        generator = ArtifactGenerator(output_dir=tmp_path, repo_name="test")
        written = generator.write_artifacts(artifacts)

        # Should include all original files plus DATAFLOW.mmd
        filenames = [p.name for p in written]
        assert "THREATS.md" in filenames
        assert "DATAFLOWS.md" in filenames
        assert "ASSUMPTIONS.md" in filenames
        assert "threat-model.json" in filenames
        assert "DATAFLOW.mmd" in filenames

    def test_existing_artifact_content_unchanged(self, tmp_path: Path) -> None:
        """Test existing artifacts maintain their content format."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User"],
            processes=["App"],
            data_stores=["DB"],
            repo_name="test",
            model_used="mock",
            files_analyzed=5,
            languages_detected=["python"],
        )

        generator = ArtifactGenerator(output_dir=tmp_path, repo_name="test")
        generator.write_artifacts(artifacts)

        # THREATS.md format unchanged
        threats_content = (tmp_path / "THREATS.md").read_text()
        assert "# Threat Model: Identified Threats" in threats_content
        assert "## Summary" in threats_content

        # ASSUMPTIONS.md format unchanged
        assumptions_content = (tmp_path / "ASSUMPTIONS.md").read_text()
        assert "# Threat Model: Assumptions and Limitations" in assumptions_content
        assert "## Metadata" in assumptions_content


class TestMermaidGoldenSamples:
    """Golden sample tests for Mermaid output."""

    def test_minimal_dfd_golden(self) -> None:
        """Test minimal DFD produces expected output."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User"],
            processes=["Server"],
            data_stores=["Database"],
            dataflows=[
                DataFlowEntry(source="User", destination="Server", data_type="Request"),
                DataFlowEntry(source="Server", destination="Database", data_type="Query"),
            ],
            repo_name="minimal-app",
        )

        content = generate_dfd_mermaid(artifacts)

        # Verify structure
        assert "title: minimal-app Data Flow Diagram" in content
        assert "flowchart TB" in content

        # All elements present
        assert "User" in content
        assert "Server" in content
        assert "Database" in content
        assert "Request" in content
        assert "Query" in content

    def test_complex_dfd_golden(self) -> None:
        """Test complex DFD maintains structure."""
        artifacts = ThreatModelArtifacts(
            external_entities=["Web Client", "Mobile Client", "Third Party API"],
            processes=[
                "Load Balancer",
                "API Gateway",
                "Auth Service",
                "Business Logic",
                "Notification Service",
            ],
            data_stores=["User DB", "Session Cache", "Message Queue"],
            dataflows=[
                DataFlowEntry(
                    source="Web Client",
                    destination="Load Balancer",
                    data_type="HTTPS",
                    trust_boundary_crossed=True,
                ),
                DataFlowEntry(
                    source="Load Balancer",
                    destination="API Gateway",
                    data_type="HTTP",
                ),
                DataFlowEntry(
                    source="API Gateway",
                    destination="Auth Service",
                    data_type="JWT Token",
                ),
                DataFlowEntry(
                    source="Business Logic",
                    destination="User DB",
                    data_type="SQL",
                ),
            ],
            trust_boundaries=["Internet", "DMZ", "Internal"],
            repo_name="complex-system",
        )

        content = generate_dfd_mermaid(artifacts)

        # All external entities
        assert "Web Client" in content
        assert "Mobile Client" in content
        assert "Third Party API" in content

        # All processes
        assert "Load Balancer" in content
        assert "API Gateway" in content
        assert "Auth Service" in content

        # All data stores
        assert "User DB" in content
        assert "Session Cache" in content

        # Trust boundary crossing
        assert "==>" in content  # Thick arrow for boundary crossing

        # Subgraph for trust boundary
        assert "subgraph" in content
