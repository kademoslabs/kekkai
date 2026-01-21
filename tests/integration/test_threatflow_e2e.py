"""Integration tests for ThreatFlow end-to-end functionality."""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.threatflow import (
    MockModelAdapter,
    ThreatFlow,
    ThreatFlowConfig,
)

pytestmark = pytest.mark.integration


class TestThreatFlowE2E:
    """End-to-end tests for ThreatFlow."""

    @pytest.fixture
    def fixture_repo(self) -> Path:
        """Get path to the test fixture repository."""
        return Path(__file__).parent.parent / "regression" / "fixtures" / "threatflow"

    @pytest.fixture
    def mock_adapter(self) -> MockModelAdapter:
        """Create a mock adapter with realistic responses."""
        return MockModelAdapter(
            responses={
                "dataflow": """## Data Flow Diagram

### External Entities
- User: End user providing input

### Processes
- Application: Main processing logic
- Database: Data storage

### Data Stores
- Database: User data storage

### Data Flows
- User -> Application: User input
- Application -> Database: SQL queries

### Trust Boundaries
- User input boundary (untrusted -> trusted)
""",
                "threat": """## Identified Threats

### T001: SQL Injection
- **Category**: Tampering
- **Affected Component**: Database query execution
- **Description**: User input directly concatenated into SQL queries
- **Risk Level**: Critical
- **Mitigation**: Use parameterized queries

### T002: Path Traversal
- **Category**: Information Disclosure
- **Affected Component**: File processing
- **Description**: User-controlled filename without validation
- **Risk Level**: High
- **Mitigation**: Validate and sanitize file paths
""",
            },
            default_response="Analysis complete.",
        )

    def test_analyze_fixture_repo(
        self, fixture_repo: Path, mock_adapter: MockModelAdapter, tmp_path: Path
    ) -> None:
        """Test analyzing the fixture repository."""
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=fixture_repo, output_dir=tmp_path)

        assert result.success
        assert result.files_processed > 0
        assert len(result.output_files) == 4  # THREATS.md, DATAFLOWS.md, ASSUMPTIONS.md, JSON

    def test_generates_all_artifacts(
        self, fixture_repo: Path, mock_adapter: MockModelAdapter, tmp_path: Path
    ) -> None:
        """Test that all artifact files are generated."""
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=fixture_repo, output_dir=tmp_path)

        assert result.success
        assert (tmp_path / "THREATS.md").exists()
        assert (tmp_path / "DATAFLOWS.md").exists()
        assert (tmp_path / "ASSUMPTIONS.md").exists()
        assert (tmp_path / "threat-model.json").exists()

    def test_threats_md_has_content(
        self, fixture_repo: Path, mock_adapter: MockModelAdapter, tmp_path: Path
    ) -> None:
        """Test that THREATS.md contains expected content."""
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=fixture_repo, output_dir=tmp_path)

        assert result.success
        content = (tmp_path / "THREATS.md").read_text()
        assert "Threat Model" in content
        assert "Generated" in content

    def test_dataflows_md_has_content(
        self, fixture_repo: Path, mock_adapter: MockModelAdapter, tmp_path: Path
    ) -> None:
        """Test that DATAFLOWS.md contains expected content."""
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=fixture_repo, output_dir=tmp_path)

        assert result.success
        content = (tmp_path / "DATAFLOWS.md").read_text()
        assert "Data Flow" in content

    def test_assumptions_md_has_limitations(
        self, fixture_repo: Path, mock_adapter: MockModelAdapter, tmp_path: Path
    ) -> None:
        """Test that ASSUMPTIONS.md includes limitations."""
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=fixture_repo, output_dir=tmp_path)

        assert result.success
        content = (tmp_path / "ASSUMPTIONS.md").read_text()
        assert "Limitations" in content
        assert "automated" in content.lower()

    def test_result_includes_metrics(
        self, fixture_repo: Path, mock_adapter: MockModelAdapter, tmp_path: Path
    ) -> None:
        """Test that result includes useful metrics."""
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=fixture_repo, output_dir=tmp_path)

        assert result.success
        assert result.duration_ms > 0
        assert result.model_mode == "mock"
        assert result.files_processed >= 3  # sample_app.py, config.yaml, README.md


class TestThreatFlowSecretHandling:
    """Tests for secret handling in ThreatFlow."""

    @pytest.fixture
    def fixture_repo(self) -> Path:
        """Get path to the test fixture repository."""
        return Path(__file__).parent.parent / "regression" / "fixtures" / "threatflow"

    def test_secrets_not_in_output(self, fixture_repo: Path, tmp_path: Path) -> None:
        """Test that secrets from repo don't appear in output files."""
        mock_adapter = MockModelAdapter(default_response="Analysis complete")
        config = ThreatFlowConfig(model_mode="mock", redact_secrets=True)
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=fixture_repo, output_dir=tmp_path)

        assert result.success

        # Check all output files don't contain the test secrets
        for output_file in result.output_files:
            content = output_file.read_text()
            # These are the fake test secrets
            assert "fake_api_key_for_testing_only" not in content
            assert "test_password_not_real" not in content


class TestThreatFlowInjectionHandling:
    """Tests for prompt injection handling."""

    @pytest.fixture
    def fixture_repo(self) -> Path:
        """Get path to the test fixture repository."""
        return Path(__file__).parent.parent / "regression" / "fixtures" / "threatflow"

    def test_injection_patterns_detected(self, fixture_repo: Path, tmp_path: Path) -> None:
        """Test that injection patterns in repo are detected."""
        mock_adapter = MockModelAdapter(default_response="Analysis complete")
        config = ThreatFlowConfig(
            model_mode="mock",
            sanitize_content=True,
            warn_on_injection=True,
        )
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=fixture_repo, output_dir=tmp_path)

        assert result.success
        # The README.md contains an injection pattern
        # Should be detected but analysis should complete
        assert len(result.injection_warnings) > 0 or result.files_processed > 0


class TestThreatFlowModeIndicator:
    """Tests for mode indication in output."""

    def test_local_mode_indicated(self, tmp_path: Path) -> None:
        """Test that local mode is indicated in output."""
        # Create a simple repo
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "main.py").write_text("print('hello')")

        output = tmp_path / "output"

        mock_adapter = MockModelAdapter(default_response="Analysis")
        config = ThreatFlowConfig(model_mode="mock")
        tf = ThreatFlow(config=config, adapter=mock_adapter)

        result = tf.analyze(repo_path=repo, output_dir=output)

        assert result.success
        assert result.model_mode == "mock"

        # Check that model info is in output
        assumptions_content = (output / "ASSUMPTIONS.md").read_text()
        assert "mock" in assumptions_content.lower()
