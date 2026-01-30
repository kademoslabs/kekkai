"""Unit tests for the fix engine module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from kekkai.fix import (
    DiffApplier,
    DiffParser,
    FixAuditLog,
    FixConfig,
    FixEngine,
    FixPromptBuilder,
    ParsedDiff,
    create_session_id,
)
from kekkai.scanners.base import Finding, Severity


class TestFixPromptBuilder:
    """Tests for FixPromptBuilder."""

    def test_build_system_prompt(self) -> None:
        """Test system prompt generation."""
        builder = FixPromptBuilder()
        prompt = builder.build_system_prompt()

        assert "security" in prompt.lower()
        assert "unified diff" in prompt.lower()
        assert "CRITICAL INSTRUCTIONS" in prompt

    def test_build_fix_prompt(self) -> None:
        """Test user prompt generation for a finding."""
        builder = FixPromptBuilder()
        prompt = builder.build_fix_prompt(
            rule_id="python.lang.security.audit.dangerous-system-call",
            severity="high",
            title="Dangerous system call",
            description="Use of os.system() is dangerous",
            file_path="app.py",
            line_number=42,
            code_context="40     import os\n41     \n42 >>> os.system(cmd)\n43     return True",
            vulnerable_line="os.system(cmd)",
            language="python",
        )

        assert "python.lang.security.audit.dangerous-system-call" in prompt
        assert "high" in prompt
        assert "app.py" in prompt
        assert "42" in prompt
        assert "os.system(cmd)" in prompt

    def test_extract_code_context(self) -> None:
        """Test code context extraction."""
        builder = FixPromptBuilder(context_lines=2)
        content = "line1\nline2\nline3\nline4\nline5"

        context, vulnerable = builder.extract_code_context(content, 3, context_lines=2)

        assert "line3" in context
        assert ">>> line3" in context
        assert vulnerable == "line3"

    def test_extract_code_context_at_start(self) -> None:
        """Test context extraction at file start."""
        builder = FixPromptBuilder()
        content = "first\nsecond\nthird"

        context, vulnerable = builder.extract_code_context(content, 1)

        assert "first" in context
        assert vulnerable == "first"

    def test_detect_language(self) -> None:
        """Test language detection from file extension."""
        builder = FixPromptBuilder()

        assert builder._detect_language("test.py") == "python"
        assert builder._detect_language("test.js") == "javascript"
        assert builder._detect_language("test.go") == "go"
        assert builder._detect_language("unknown.xyz") == ""


class TestDiffParser:
    """Tests for DiffParser."""

    def test_parse_simple_diff(self) -> None:
        """Test parsing a simple unified diff."""
        parser = DiffParser()
        diff_text = """--- a/app.py
+++ b/app.py
@@ -10,3 +10,3 @@
 import os
-os.system(cmd)
+subprocess.run(cmd, shell=False)
 return True"""

        result = parser.parse(diff_text)

        assert result.original_file == "a/app.py"
        assert result.modified_file == "b/app.py"
        assert len(result.hunks) == 1
        assert result.hunks[0].old_start == 10
        assert result.is_valid

    def test_parse_diff_with_markdown_fences(self) -> None:
        """Test parsing diff with markdown code fences."""
        parser = DiffParser()
        diff_text = """```diff
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
-bad code
+good code
```"""

        result = parser.parse(diff_text)

        assert result.is_valid
        assert len(result.hunks) == 1

    def test_parse_invalid_diff(self) -> None:
        """Test parsing invalid diff returns empty result."""
        parser = DiffParser()
        result = parser.parse("not a diff at all")

        assert not result.is_valid
        assert len(result.hunks) == 0


class TestDiffApplier:
    """Tests for DiffApplier."""

    def test_validate_good_diff(self, tmp_path: Path) -> None:
        """Test validation of applicable diff."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("line1\nline2\nline3\n")

        applier = DiffApplier()
        diff = ParsedDiff(
            original_file="test.py",
            modified_file="test.py",
            hunks=[],
        )
        # Add a valid hunk
        from kekkai.fix.differ import DiffHunk

        diff.hunks.append(DiffHunk(old_start=1, old_count=1, new_start=1, new_count=1))

        valid, error = applier.validate(diff, tmp_path)
        assert valid
        assert error == ""

    def test_validate_file_not_found(self, tmp_path: Path) -> None:
        """Test validation fails for missing file."""
        applier = DiffApplier()
        from kekkai.fix.differ import DiffHunk

        diff = ParsedDiff(
            original_file="nonexistent.py",
            modified_file="nonexistent.py",
            hunks=[DiffHunk(old_start=1, old_count=1, new_start=1, new_count=1)],
        )

        valid, error = applier.validate(diff, tmp_path)
        assert not valid
        assert "not found" in error.lower() or "cannot resolve" in error.lower()

    def test_apply_dry_run(self, tmp_path: Path) -> None:
        """Test dry run doesn't modify files."""
        test_file = tmp_path / "test.py"
        original_content = "old line\n"
        test_file.write_text(original_content)

        applier = DiffApplier()
        from kekkai.fix.differ import DiffHunk

        diff = ParsedDiff(
            original_file="test.py",
            modified_file="test.py",
            hunks=[
                DiffHunk(
                    old_start=1,
                    old_count=1,
                    new_start=1,
                    new_count=1,
                    lines=["-old line", "+new line"],
                )
            ],
        )

        result = applier.apply(diff, tmp_path, dry_run=True)

        assert result.success
        assert test_file.read_text() == original_content

    def test_apply_with_changes(self, tmp_path: Path) -> None:
        """Test apply actually modifies files."""
        test_file = tmp_path / "test.py"
        test_file.write_text("old line\n")

        applier = DiffApplier(backup_dir=tmp_path / "backups")
        from kekkai.fix.differ import DiffHunk

        diff = ParsedDiff(
            original_file="test.py",
            modified_file="test.py",
            hunks=[
                DiffHunk(
                    old_start=1,
                    old_count=1,
                    new_start=1,
                    new_count=1,
                    lines=["-old line", "+new line"],
                )
            ],
        )

        result = applier.apply(diff, tmp_path, dry_run=False, create_backup=True)

        assert result.success
        assert "new line" in test_file.read_text()
        assert result.backup_path is not None


class TestFixAuditLog:
    """Tests for FixAuditLog."""

    def test_record_attempt(self) -> None:
        """Test recording a fix attempt."""
        log = FixAuditLog(session_id="test-123", repo_path="/test/repo")

        attempt = log.record_attempt(
            finding_id="abc123",
            rule_id="test-rule",
            file_path="test.py",
            line_number=10,
            severity="high",
            model_used="mock",
        )

        assert attempt.status == "pending"
        assert len(log.attempts) == 1
        assert log.summary["pending"] == 1

    def test_mark_applied(self) -> None:
        """Test marking an attempt as applied."""
        log = FixAuditLog(session_id="test-123", repo_path="/test/repo")
        attempt = log.record_attempt(
            finding_id="abc123",
            rule_id="test-rule",
            file_path="test.py",
            line_number=10,
            severity="high",
        )

        log.mark_applied(attempt, lines_added=5, lines_removed=3)

        assert attempt.status == "applied"
        assert attempt.lines_added == 5
        assert attempt.lines_removed == 3

    def test_save_and_load(self, tmp_path: Path) -> None:
        """Test saving and loading audit log."""
        log = FixAuditLog(session_id="test-123", repo_path="/test/repo")
        log.record_attempt(
            finding_id="abc123",
            rule_id="test-rule",
            file_path="test.py",
            line_number=10,
            severity="high",
        )

        save_path = tmp_path / "audit.json"
        log.save(save_path)

        loaded = FixAuditLog.load(save_path)
        assert loaded.session_id == "test-123"
        assert len(loaded.attempts) == 1


class TestFixEngine:
    """Tests for FixEngine."""

    def test_no_findings(self) -> None:
        """Test handling empty findings list."""
        engine = FixEngine(FixConfig(dry_run=True))
        result = engine.fix([], Path("/tmp"))

        assert result.success
        assert "No findings" in result.warnings[0]

    def test_non_semgrep_findings_skipped(self) -> None:
        """Test that non-Semgrep findings are skipped."""
        engine = FixEngine(FixConfig(dry_run=True))
        findings = [
            Finding(
                scanner="trivy",
                title="CVE-2021-1234",
                severity=Severity.HIGH,
                description="Test",
                file_path="test.py",
                line=10,
            )
        ]

        result = engine.fix(findings, Path("/tmp"))

        assert result.success
        assert "No Semgrep findings" in result.warnings[0]

    def test_parse_semgrep_result(self, tmp_path: Path) -> None:
        """Test parsing Semgrep JSON format."""
        engine = FixEngine()

        semgrep_result = {
            "check_id": "python.lang.security.audit.dangerous-system-call",
            "path": "app.py",
            "start": {"line": 10, "col": 1},
            "extra": {
                "severity": "ERROR",
                "message": "Dangerous os.system call",
                "metadata": {
                    "message": "Use subprocess instead",
                    "cwe": ["CWE-78"],
                },
            },
        }

        finding = engine._parse_semgrep_result(dict(semgrep_result))

        assert finding.scanner == "semgrep"
        assert finding.rule_id == "python.lang.security.audit.dangerous-system-call"
        assert finding.file_path == "app.py"
        assert finding.line == 10
        assert finding.severity == Severity.HIGH

    def test_fix_from_scan_results(self, tmp_path: Path) -> None:
        """Test loading and processing scan results JSON."""
        # Create mock scan results
        results_file = tmp_path / "results.json"
        results_file.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "test-rule",
                            "path": "test.py",
                            "start": {"line": 5},
                            "extra": {
                                "severity": "WARNING",
                                "message": "Test issue",
                                "metadata": {"message": "Fix this"},
                            },
                        }
                    ]
                }
            )
        )

        # Create test source file
        test_file = tmp_path / "test.py"
        test_file.write_text("line1\nline2\nline3\nline4\nvulnerable\nline6\n")

        # Create engine with mock model
        config = FixConfig(model_mode="mock", dry_run=True)
        engine = FixEngine(config)

        # Mock the model to return a valid diff
        with patch.object(engine, "_get_model") as mock_get_model:
            mock_model = MagicMock()
            mock_model.name = "mock"
            mock_model.generate.return_value = MagicMock(
                success=True,
                content="--- a/test.py\n+++ b/test.py\n@@ -5,1 +5,1 @@\n-vulnerable\n+fixed\n",
            )
            mock_get_model.return_value = mock_model

            result = engine.fix_from_scan_results(results_file, tmp_path, tmp_path / "output")

        assert result.success
        assert result.findings_processed == 1


class TestCreateSessionId:
    """Tests for session ID generation."""

    def test_format(self) -> None:
        """Test session ID format."""
        session_id = create_session_id()

        assert session_id.startswith("fix-")
        assert len(session_id) > 20


class TestSanitizeLlmOutput:
    """Tests for LLM output sanitization."""

    def test_clean_markdown_fences(self) -> None:
        """Test removing markdown code fences from diff."""
        parser = DiffParser()
        raw = """```diff
--- a/test.py
+++ b/test.py
@@ -1 +1 @@
-old
+new
```"""
        cleaned = parser._clean_llm_output(raw)

        assert not cleaned.startswith("```")
        assert not cleaned.endswith("```")
        assert "--- a/test.py" in cleaned
