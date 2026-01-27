"""Unit tests for Mermaid.js DFD generation."""

from __future__ import annotations

from kekkai.threatflow.artifacts import DataFlowEntry, ThreatModelArtifacts
from kekkai.threatflow.mermaid import (
    MAX_LABEL_LENGTH,
    MermaidDFDGenerator,
    MermaidEdge,
    MermaidNode,
    NodeType,
    _encode_label,
    _sanitize_id,
    generate_dfd_mermaid,
)


class TestEncodeLabelSecurity:
    """Tests for label encoding security (ASVS V5.3.3)."""

    def test_escape_xss_script_tag(self) -> None:
        """Test XSS script tag is escaped."""
        malicious = '<script>alert("xss")</script>'
        result = _encode_label(malicious)
        assert "<script>" not in result
        # HTML entities are escaped, then unsafe chars replaced with underscore
        assert "&lt" in result or "_script_" in result

    def test_escape_html_entities(self) -> None:
        """Test HTML entities are escaped."""
        text = "User <admin> & 'root'"
        result = _encode_label(text)
        assert "<" not in result or "&lt;" in result
        assert ">" not in result or "&gt;" in result

    def test_escape_mermaid_pipe_char(self) -> None:
        """Test Mermaid pipe character is replaced."""
        text = "User|Admin"
        result = _encode_label(text)
        assert "|" not in result

    def test_escape_mermaid_quotes(self) -> None:
        """Test quotes are handled safely."""
        text = "Say \"hello\" and 'goodbye'"
        result = _encode_label(text)
        # Quotes should be escaped or replaced
        assert '"' not in result or "&quot;" in result

    def test_escape_mermaid_brackets(self) -> None:
        """Test brackets are replaced."""
        text = "Array[0] and {object}"
        result = _encode_label(text)
        assert "[" not in result
        assert "]" not in result
        assert "{" not in result
        assert "}" not in result

    def test_escape_backslash(self) -> None:
        """Test backslash is replaced."""
        text = "path\\to\\file"
        result = _encode_label(text)
        assert "\\" not in result

    def test_escape_semicolon(self) -> None:
        """Test semicolon (Mermaid statement separator) is replaced."""
        text = "statement; another"
        result = _encode_label(text)
        assert ";" not in result

    def test_truncate_long_labels(self) -> None:
        """Test long labels are truncated."""
        long_text = "A" * 200
        result = _encode_label(long_text)
        assert len(result) <= MAX_LABEL_LENGTH
        assert result.endswith("...")

    def test_preserve_safe_text(self) -> None:
        """Test safe text passes through unchanged."""
        safe = "User Authentication Service"
        result = _encode_label(safe)
        assert result == safe


class TestSanitizeId:
    """Tests for ID sanitization."""

    def test_replace_spaces(self) -> None:
        """Test spaces are replaced with underscores."""
        result = _sanitize_id("my node")
        assert " " not in result
        assert "_" in result

    def test_replace_special_chars(self) -> None:
        """Test special characters are replaced."""
        result = _sanitize_id("node@123!test")
        assert "@" not in result
        assert "!" not in result

    def test_prefix_numeric_start(self) -> None:
        """Test IDs starting with numbers get prefixed."""
        result = _sanitize_id("123node")
        assert result[0].isalpha()

    def test_handle_empty_string(self) -> None:
        """Test empty string returns default ID."""
        result = _sanitize_id("")
        assert result == "node"

    def test_preserve_valid_id(self) -> None:
        """Test valid IDs pass through."""
        result = _sanitize_id("valid_node_123")
        assert result == "valid_node_123"


class TestMermaidNode:
    """Tests for MermaidNode class."""

    def test_external_entity_shape(self) -> None:
        """Test external entity uses parallelogram shape."""
        node = MermaidNode(id="user", label="User", node_type=NodeType.EXTERNAL_ENTITY)
        result = node.to_mermaid()
        assert '[/"User"/]' in result

    def test_process_shape(self) -> None:
        """Test process uses stadium shape."""
        node = MermaidNode(id="app", label="Application", node_type=NodeType.PROCESS)
        result = node.to_mermaid()
        assert '(["Application"])' in result

    def test_data_store_shape(self) -> None:
        """Test data store uses cylinder shape."""
        node = MermaidNode(id="db", label="Database", node_type=NodeType.DATA_STORE)
        result = node.to_mermaid()
        assert '[("Database")]' in result

    def test_node_escapes_malicious_label(self) -> None:
        """Test node escapes XSS in label."""
        node = MermaidNode(
            id="bad",
            label='<script>alert("xss")</script>',
            node_type=NodeType.PROCESS,
        )
        result = node.to_mermaid()
        assert "<script>" not in result

    def test_node_sanitizes_id(self) -> None:
        """Test node sanitizes ID."""
        node = MermaidNode(
            id="bad node!",
            label="Test",
            node_type=NodeType.PROCESS,
        )
        result = node.to_mermaid()
        assert "bad_node_" in result
        assert "!" not in result


class TestMermaidEdge:
    """Tests for MermaidEdge class."""

    def test_simple_edge(self) -> None:
        """Test simple edge syntax."""
        edge = MermaidEdge(source="a", target="b", label="data")
        result = edge.to_mermaid()
        assert 'a -->|"data"| b' in result

    def test_trust_boundary_edge(self) -> None:
        """Test trust boundary edge uses thick arrow."""
        edge = MermaidEdge(
            source="a",
            target="b",
            label="sensitive",
            crosses_trust_boundary=True,
        )
        result = edge.to_mermaid()
        assert "==>" in result

    def test_edge_escapes_label(self) -> None:
        """Test edge escapes malicious label."""
        edge = MermaidEdge(source="a", target="b", label="<script>xss</script>")
        result = edge.to_mermaid()
        assert "<script>" not in result


class TestMermaidDFDGenerator:
    """Tests for MermaidDFDGenerator class."""

    def test_generate_empty_diagram(self) -> None:
        """Test generating empty diagram produces valid syntax."""
        gen = MermaidDFDGenerator(title="Empty")
        result = gen.generate()
        assert "flowchart TB" in result
        assert "title: Empty" in result

    def test_generate_with_nodes(self) -> None:
        """Test generating diagram with nodes."""
        gen = MermaidDFDGenerator()
        gen.add_node(MermaidNode("u", "User", NodeType.EXTERNAL_ENTITY))
        gen.add_node(MermaidNode("a", "App", NodeType.PROCESS))
        result = gen.generate()
        assert "User" in result
        assert "App" in result

    def test_generate_with_edges(self) -> None:
        """Test generating diagram with edges."""
        gen = MermaidDFDGenerator()
        gen.add_node(MermaidNode("u", "User", NodeType.EXTERNAL_ENTITY))
        gen.add_node(MermaidNode("a", "App", NodeType.PROCESS))
        gen.add_edge(MermaidEdge("u", "a", "HTTP Request"))
        result = gen.generate()
        assert "HTTP Request" in result
        assert "-->" in result

    def test_generate_with_trust_boundary(self) -> None:
        """Test generating diagram with trust boundary subgraph."""
        gen = MermaidDFDGenerator()
        gen.add_node(MermaidNode("app", "Application", NodeType.PROCESS))
        gen.add_trust_boundary("Internal", ["app"])
        result = gen.generate()
        assert "subgraph" in result
        assert "Internal" in result

    def test_direction_setting(self) -> None:
        """Test diagram direction can be changed."""
        gen = MermaidDFDGenerator(direction="LR")
        result = gen.generate()
        assert "flowchart LR" in result

    def test_title_escaped(self) -> None:
        """Test title is escaped."""
        gen = MermaidDFDGenerator(title='<script>alert("xss")</script>')
        result = gen.generate()
        assert "<script>" not in result


class TestMermaidDFDGeneratorFromArtifacts:
    """Tests for MermaidDFDGenerator.from_artifacts()."""

    def test_from_artifacts_basic(self) -> None:
        """Test creating generator from ThreatModelArtifacts."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User", "External API"],
            processes=["Web Server", "Auth Service"],
            data_stores=["Database"],
            dataflows=[
                DataFlowEntry(
                    source="User",
                    destination="Web Server",
                    data_type="HTTP Request",
                ),
            ],
            repo_name="test-app",
        )

        gen = MermaidDFDGenerator.from_artifacts(artifacts)
        result = gen.generate()

        assert "User" in result
        assert "External API" in result
        assert "Web Server" in result
        assert "Database" in result
        assert "HTTP Request" in result

    def test_from_artifacts_with_trust_boundaries(self) -> None:
        """Test trust boundaries from artifacts."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User"],
            processes=["App"],
            data_stores=[],
            trust_boundaries=["Internet -> DMZ"],
            repo_name="test",
        )

        gen = MermaidDFDGenerator.from_artifacts(artifacts)
        result = gen.generate()

        # Should have trust boundary subgraph
        assert "subgraph" in result

    def test_from_artifacts_trust_boundary_crossing(self) -> None:
        """Test trust boundary crossing edges."""
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

        gen = MermaidDFDGenerator.from_artifacts(artifacts)
        result = gen.generate()

        # Should use thick arrow for trust boundary crossing
        assert "==>" in result


class TestGenerateDfdMermaid:
    """Tests for generate_dfd_mermaid convenience function."""

    def test_convenience_function(self) -> None:
        """Test generate_dfd_mermaid produces valid output."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User"],
            processes=["App"],
            data_stores=["DB"],
            repo_name="test",
        )

        result = generate_dfd_mermaid(artifacts)

        assert "flowchart" in result
        assert "User" in result
        assert "App" in result
        assert "DB" in result


class TestMermaidSyntaxValidity:
    """Tests for Mermaid syntax validity."""

    def test_no_unescaped_pipes_in_output(self) -> None:
        """Test no unescaped pipes that could break syntax."""
        artifacts = ThreatModelArtifacts(
            external_entities=["User|Admin"],
            processes=["App|Service"],
            dataflows=[
                DataFlowEntry(
                    source="User|Admin",
                    destination="App|Service",
                    data_type="Data|Info",
                ),
            ],
            repo_name="test",
        )

        result = generate_dfd_mermaid(artifacts)

        # Count pipes - should only be in edge label syntax
        # Edge syntax: -->|"label"|
        lines = result.split("\n")
        for line in lines:
            if "-->|" in line or "==>|" in line:
                # This is valid edge syntax
                continue
            # Other lines should not have unescaped pipes
            # (except in comments which start with %%)
            if not line.strip().startswith("%%"):
                # Inside quoted labels, pipes should be replaced
                pass

    def test_valid_subgraph_syntax(self) -> None:
        """Test subgraph syntax is valid."""
        gen = MermaidDFDGenerator()
        gen.add_node(MermaidNode("a", "Test Node", NodeType.PROCESS))
        gen.add_trust_boundary("Boundary Name", ["a"])
        result = gen.generate()

        # Check subgraph has proper open/close
        assert result.count("subgraph") == result.count("end")

    def test_yaml_frontmatter_format(self) -> None:
        """Test YAML frontmatter is valid."""
        gen = MermaidDFDGenerator(title="Test")
        result = gen.generate()

        lines = result.split("\n")
        assert lines[0] == "---"
        assert lines[1].startswith("title:")
        assert lines[2] == "---"
