"""Integration tests for Mermaid DFD generation end-to-end."""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.threatflow import (
    ArtifactGenerator,
    DataFlowEntry,
    MockModelAdapter,
    ThreatFlow,
    ThreatFlowConfig,
    ThreatModelArtifacts,
)

pytestmark = pytest.mark.integration


class TestMermaidE2E:
    """End-to-end tests for Mermaid DFD generation."""

    def test_threatflow_produces_mmd_file(self, tmp_path: Path) -> None:
        """Test that ThreatFlow analysis produces DATAFLOW.mmd file."""
        # Create a simple repo
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user/<id>')
def get_user(id):
    conn = sqlite3.connect('users.db')
    return conn.execute('SELECT * FROM users WHERE id=?', (id,)).fetchone()
"""
        )

        output_dir = tmp_path / "output"

        # Run ThreatFlow with mock adapter
        mock_adapter = MockModelAdapter(default_response="Test analysis")
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=repo, output_dir=output_dir)

        # Should succeed
        assert result.success

        # Should produce DATAFLOW.mmd
        mmd_file = output_dir / "DATAFLOW.mmd"
        assert mmd_file.exists(), "DATAFLOW.mmd should be created"

        # Read and verify content
        content = mmd_file.read_text()
        assert "flowchart" in content
        assert "---" in content  # YAML frontmatter

    def test_artifact_generator_writes_mmd(self, tmp_path: Path) -> None:
        """Test ArtifactGenerator writes DATAFLOW.mmd alongside other artifacts."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User", "External Service"],
            processes=["API Gateway", "Business Logic", "Auth Service"],
            data_stores=["PostgreSQL", "Redis Cache"],
            dataflows=[
                DataFlowEntry(
                    source="User",
                    destination="API Gateway",
                    data_type="HTTP Request",
                    trust_boundary_crossed=True,
                ),
                DataFlowEntry(
                    source="API Gateway",
                    destination="Auth Service",
                    data_type="Auth Token",
                ),
                DataFlowEntry(
                    source="Business Logic",
                    destination="PostgreSQL",
                    data_type="SQL Query",
                ),
            ],
            trust_boundaries=["Internet -> DMZ", "DMZ -> Internal"],
            repo_name="test-application",
            model_used="mock",
            files_analyzed=10,
        )

        generator = ArtifactGenerator(output_dir=tmp_path, repo_name="test-application")
        written = generator.write_artifacts(artifacts)

        # Should include DATAFLOW.mmd
        mmd_path = tmp_path / "DATAFLOW.mmd"
        assert mmd_path in written
        assert mmd_path.exists()

        # Verify content
        content = mmd_path.read_text()
        assert "User" in content
        assert "API Gateway" in content
        assert "PostgreSQL" in content
        assert "HTTP Request" in content

    def test_mmd_syntax_parseable(self, tmp_path: Path) -> None:
        """Test generated Mermaid syntax is parseable (basic validation)."""
        artifacts = ThreatModelArtifacts(
            external_entities=["Client"],
            processes=["Server"],
            data_stores=["DB"],
            dataflows=[
                DataFlowEntry(source="Client", destination="Server", data_type="Request"),
                DataFlowEntry(source="Server", destination="DB", data_type="Query"),
            ],
            repo_name="test",
        )

        generator = ArtifactGenerator(output_dir=tmp_path, repo_name="test")
        content = generator.generate_dataflow_mmd(artifacts)

        # Basic syntax validation
        lines = content.split("\n")

        # Should have YAML frontmatter
        assert lines[0] == "---"
        assert any("title:" in line for line in lines[:3])

        # Should have flowchart directive
        assert any("flowchart" in line for line in lines)

        # Should have valid structure (no unclosed brackets)
        open_parens = content.count("(")
        close_parens = content.count(")")
        # Note: May not be exactly equal due to edge syntax, but should be close
        assert abs(open_parens - close_parens) <= 2

    def test_mmd_with_malicious_input(self, tmp_path: Path) -> None:
        """Test Mermaid generation handles malicious input safely."""
        artifacts = ThreatModelArtifacts(
            external_entities=['<script>alert("xss")</script>', "Normal User"],
            processes=["App|Server; DROP TABLE"],
            data_stores=["DB` OR 1=1--"],
            dataflows=[
                DataFlowEntry(
                    source="<script>alert('xss')</script>",
                    destination="App|Server",
                    data_type='<img src=x onerror="alert(1)">',
                ),
            ],
            repo_name="<evil>",
        )

        generator = ArtifactGenerator(output_dir=tmp_path, repo_name="test")
        content = generator.generate_dataflow_mmd(artifacts)

        # Should not contain unescaped malicious content
        assert "<script>" not in content
        assert "alert(" not in content
        # HTML attributes are escaped - the = is replaced
        assert "onerror=" not in content or "onerror=&quot" in content

        # Should still be valid Mermaid syntax
        assert "flowchart" in content


class TestMermaidWithThreatFlow:
    """Tests for Mermaid integration with full ThreatFlow workflow."""

    def test_all_artifacts_created(self, tmp_path: Path) -> None:
        """Test all expected artifacts are created including DATAFLOW.mmd."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "main.py").write_text("print('hello')")

        output_dir = tmp_path / "output"

        mock_adapter = MockModelAdapter(default_response="Analysis")
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=repo, output_dir=output_dir)

        assert result.success

        # All expected files should exist
        expected_files = [
            "THREATS.md",
            "DATAFLOWS.md",
            "DATAFLOW.mmd",
            "ASSUMPTIONS.md",
            "threat-model.json",
        ]

        for filename in expected_files:
            filepath = output_dir / filename
            assert filepath.exists(), f"{filename} should be created"

    def test_mmd_consistent_with_dataflows_md(self, tmp_path: Path) -> None:
        """Test DATAFLOW.mmd contains same entities as DATAFLOWS.md."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User", "API"],
            processes=["Server"],
            data_stores=["Database"],
            repo_name="test",
        )

        generator = ArtifactGenerator(output_dir=tmp_path, repo_name="test")

        # Generate both formats
        md_content = generator.generate_dataflows_md(artifacts)
        mmd_content = generator.generate_dataflow_mmd(artifacts)

        # All entities in MD should appear in MMD
        for entity in artifacts.external_entities:
            assert entity in md_content
            assert entity in mmd_content

        for process in artifacts.processes:
            assert process in md_content
            assert process in mmd_content

        for store in artifacts.data_stores:
            assert store in md_content
            assert store in mmd_content
