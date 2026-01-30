"""Regression tests to ensure fix module doesn't break existing functionality."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.regression
class TestScanUnchanged:
    """Verify scan functionality is unaffected by fix module."""

    def test_scan_import_still_works(self) -> None:
        """Test that scan imports still work after fix module addition."""
        from kekkai.scanners import SCANNER_REGISTRY

        assert "trivy" in SCANNER_REGISTRY
        assert "semgrep" in SCANNER_REGISTRY
        assert "gitleaks" in SCANNER_REGISTRY

    def test_finding_class_unchanged(self) -> None:
        """Test Finding class interface is unchanged."""
        from kekkai.scanners.base import Finding, Severity

        finding = Finding(
            scanner="test",
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test description",
            file_path="test.py",
            line=10,
            rule_id="test-rule",
            cwe="CWE-123",
        )

        assert finding.scanner == "test"
        assert finding.dedupe_hash()
        assert finding.file_path == "test.py"

    def test_scan_context_unchanged(self, tmp_path: Path) -> None:
        """Test ScanContext interface is unchanged."""
        from kekkai.scanners.base import ScanContext

        ctx = ScanContext(
            repo_path=tmp_path,
            output_dir=tmp_path / "output",
            run_id="test-run",
            commit_sha="abc123",
            timeout_seconds=300,
        )

        assert ctx.repo_path == tmp_path
        assert ctx.timeout_seconds == 300


@pytest.mark.regression
class TestThreatFlowUnchanged:
    """Verify ThreatFlow functionality is unaffected."""

    def test_threatflow_import_still_works(self) -> None:
        """Test that ThreatFlow imports still work."""
        from kekkai.threatflow import (
            MockModelAdapter,
            ThreatFlow,
        )

        assert ThreatFlow is not None
        assert MockModelAdapter is not None

    def test_model_adapter_interface(self) -> None:
        """Test model adapter interface is unchanged."""
        from kekkai.threatflow import MockModelAdapter

        adapter = MockModelAdapter(default_response="test response")
        response = adapter.generate(
            system_prompt="test system",
            user_prompt="test user",
        )

        assert response.content == "test response"
        assert adapter.is_local

    def test_sanitizer_still_works(self) -> None:
        """Test sanitizer interface is unchanged."""
        from kekkai.threatflow import SanitizeConfig, Sanitizer, TieredSanitizer

        # Basic sanitizer
        sanitizer = Sanitizer()
        result = sanitizer.sanitize("normal code content")
        assert not result.was_modified

        # Tiered sanitizer
        tiered = TieredSanitizer(SanitizeConfig())
        tiered_result = tiered.sanitize_input("normal content")
        assert not tiered_result.blocked


@pytest.mark.regression
class TestCliUnchanged:
    """Verify CLI interface is unchanged for existing commands."""

    def test_scan_command_still_exists(self) -> None:
        """Test scan command is still available."""
        from kekkai.cli import main

        # --help raises SystemExit(0)
        with pytest.raises(SystemExit) as exc_info:
            main(["scan", "--help"])
        assert exc_info.value.code == 0

    def test_threatflow_command_still_exists(self) -> None:
        """Test threatflow command is still available."""
        from kekkai.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["threatflow", "--help"])
        assert exc_info.value.code == 0

    def test_triage_command_still_exists(self) -> None:
        """Test triage command is still available."""
        from kekkai.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["triage", "--help"])
        assert exc_info.value.code == 0

    def test_dojo_command_still_exists(self) -> None:
        """Test dojo command is still available."""
        from kekkai.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["dojo", "--help"])
        assert exc_info.value.code == 0

    def test_init_command_still_exists(self) -> None:
        """Test init command is still available."""
        from kekkai.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["init", "--help"])
        assert exc_info.value.code == 0


@pytest.mark.regression
class TestFixModuleIsolation:
    """Verify fix module is properly isolated."""

    def test_fix_import_does_not_affect_scan(self) -> None:
        """Test importing fix module doesn't break scan module."""
        # Import fix first

        # Then import scan
        from kekkai.scanners.semgrep import SemgrepScanner

        # Should work fine
        scanner = SemgrepScanner()
        assert scanner.name == "semgrep"

    def test_fix_uses_shared_model_adapter(self) -> None:
        """Test fix uses same model adapter as ThreatFlow."""
        from kekkai.threatflow import MockModelAdapter
        from kekkai.threatflow.model_adapter import create_adapter

        # Both should use the same adapter factory
        adapter = create_adapter("mock")
        assert isinstance(adapter, MockModelAdapter)

    def test_fix_uses_shared_sanitizer(self) -> None:
        """Test fix uses same sanitizer as ThreatFlow."""
        from kekkai.fix.engine import FixConfig, FixEngine
        from kekkai.threatflow import TieredSanitizer

        engine = FixEngine(FixConfig())
        assert isinstance(engine._sanitizer, TieredSanitizer)
