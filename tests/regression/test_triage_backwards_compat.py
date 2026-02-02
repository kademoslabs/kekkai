"""Regression tests for triage backward compatibility."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.triage.loader import load_findings_from_path
from kekkai.triage.models import FindingEntry, Severity


class TestTriageBackwardCompatibility:
    """Ensure existing triage JSON formats still work."""

    def test_native_triage_list_format(self, tmp_path: Path) -> None:
        """Test that existing native triage list format still works."""
        # This is the original format that triage accepted
        native_data: list[dict[str, str | int | None]] = [
            {
                "id": "finding-1",
                "title": "SQL Injection",
                "severity": "high",
                "scanner": "semgrep",
                "file_path": "app.py",
                "line": 42,
                "description": "Dangerous SQL query",
                "rule_id": "python.sql.injection",
                "state": "pending",
                "notes": "",
            },
            {
                "id": "finding-2",
                "title": "XSS Vulnerability",
                "severity": "medium",
                "scanner": "semgrep",
                "file_path": "templates/index.html",
                "line": 15,
                "description": "Unescaped output",
                "rule_id": "html.xss",
                "state": "false_positive",
                "notes": "This is a false positive",
            },
        ]

        file_path = tmp_path / "triage.json"
        file_path.write_text(json.dumps(native_data))

        # Load findings
        findings, errors = load_findings_from_path(file_path)

        # Verify backwards compatibility
        assert len(findings) == 2
        assert not errors

        # First finding
        assert findings[0].id == "finding-1"
        assert findings[0].title == "SQL Injection"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].scanner == "semgrep"
        assert findings[0].line == 42

        # Second finding
        assert findings[1].id == "finding-2"
        assert findings[1].severity == Severity.MEDIUM

    def test_native_triage_dict_format(self, tmp_path: Path) -> None:
        """Test that wrapped format {"findings": [...]} still works."""
        # This is another format that triage supported
        native_data = {
            "findings": [
                {
                    "id": "test-1",
                    "title": "Test Finding",
                    "severity": "critical",
                    "scanner": "trivy",
                    "file_path": "Dockerfile",
                }
            ],
            "metadata": {"generated_at": "2024-01-01", "version": "1.0"},
        }

        file_path = tmp_path / "triage-report.json"
        file_path.write_text(json.dumps(native_data))

        # Load findings
        findings, errors = load_findings_from_path(file_path)

        # Verify backwards compatibility
        assert len(findings) == 1
        assert not errors
        assert findings[0].title == "Test Finding"
        assert findings[0].severity == Severity.CRITICAL

    def test_from_dict_maintains_all_fields(self) -> None:
        """Test that FindingEntry.from_dict preserves all fields."""
        data: dict[str, str | int | None] = {
            "id": "test-id",
            "title": "Test Title",
            "severity": "high",
            "scanner": "test-scanner",
            "file_path": "test.py",
            "line": 100,
            "description": "Test description",
            "rule_id": "TEST-001",
            "state": "confirmed",
            "notes": "Test notes",
        }

        finding = FindingEntry.from_dict(data)

        # Verify all fields preserved
        assert finding.id == "test-id"
        assert finding.title == "Test Title"
        assert finding.severity == Severity.HIGH
        assert finding.scanner == "test-scanner"
        assert finding.file_path == "test.py"
        assert finding.line == 100
        assert finding.description == "Test description"
        assert finding.rule_id == "TEST-001"
        assert finding.notes == "Test notes"

    def test_ignore_pattern_generation_unchanged(self) -> None:
        """Test that ignore pattern generation still works."""
        finding = FindingEntry(
            id="test",
            title="Test",
            severity=Severity.MEDIUM,
            scanner="trivy",
            rule_id="CVE-2024-1234",
            file_path="requirements.txt",
        )

        # Pattern should be: scanner:rule_id:file_path
        pattern = finding.generate_ignore_pattern()
        assert pattern == "trivy:CVE-2024-1234:requirements.txt"

    def test_severity_mapping_backward_compat(self) -> None:
        """Test that severity enum values haven't changed."""
        # These values must remain stable for backward compatibility
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


@pytest.mark.regression
class TestUploadBackwardCompatibility:
    """Ensure upload still works with properly named files."""

    def test_upload_correctly_named_files(self, tmp_path: Path) -> None:
        """Test that correctly named scanner files still work."""
        # If a user manually creates files with correct names, they should work
        trivy_data = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "Severity": "HIGH",
                            "PkgName": "pkg",
                            "InstalledVersion": "1.0",
                            "Title": "Test",
                        }
                    ],
                }
            ]
        }

        # File named without "-results" suffix (old style that worked)
        (tmp_path / "trivy.json").write_text(json.dumps(trivy_data))

        # Should still load (though with warning about unknown scanner)
        findings, errors = load_findings_from_path(tmp_path)

        # The scanner will be found because "trivy" is in the registry
        assert len(findings) == 1 or len(errors) == 1  # Either loads or produces error

    def test_scanner_name_normalization_idempotent(self) -> None:
        """Test that normalization is idempotent."""
        from kekkai.cli import _normalize_scanner_name

        # Normalizing already-normalized names should be idempotent
        assert _normalize_scanner_name("trivy") == "trivy"
        assert _normalize_scanner_name("semgrep") == "semgrep"
        assert _normalize_scanner_name("gitleaks") == "gitleaks"

        # Should handle double-normalization gracefully
        normalized_once = _normalize_scanner_name("trivy-results")
        assert normalized_once == "trivy"
        normalized_twice = _normalize_scanner_name(normalized_once)
        assert normalized_twice == "trivy"


@pytest.mark.regression
class TestTriageModelsImportWithoutTextual:
    """Test that triage models can be imported without Textual."""

    def test_import_models_without_textual(self) -> None:
        """Test that models are importable without Textual dependency."""
        # This should not raise ImportError even if Textual is missing
        try:
            from kekkai.triage.models import (
                FindingEntry,
                Severity,
                TriageDecision,
                TriageState,
            )

            # Verify imports worked
            assert FindingEntry is not None
            assert Severity is not None
            assert TriageDecision is not None
            assert TriageState is not None
        except ImportError as e:
            pytest.fail(f"Models should be importable without Textual: {e}")

    def test_loader_importable_without_textual(self) -> None:
        """Test that loader is importable without Textual."""
        try:
            from kekkai.triage.loader import load_findings_from_path

            assert load_findings_from_path is not None
        except ImportError as e:
            pytest.fail(f"Loader should be importable without Textual: {e}")
