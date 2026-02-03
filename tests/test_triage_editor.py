"""Unit tests for editor integration and workbench features."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kekkai.triage.models import FindingEntry, Severity
from kekkai.triage.screens import FindingDetailScreen


class TestEditorIntegration:
    """Tests for Ctrl+O editor integration."""

    @pytest.fixture
    def sample_finding(self) -> FindingEntry:
        """Create a sample finding with file and line."""
        return FindingEntry(
            id="TEST-001",
            title="SQL Injection",
            severity=Severity.HIGH,
            scanner="semgrep",
            file_path="src/app.py",
            line=42,
            description="SQL injection vulnerability",
        )

    @pytest.fixture
    def finding_no_file(self) -> FindingEntry:
        """Create a finding without file path."""
        return FindingEntry(
            id="CVE-2024-1234",
            title="Dependency vulnerability",
            severity=Severity.CRITICAL,
            scanner="trivy",
        )

    def test_editor_validation_blocks_missing_editor(
        self, sample_finding: FindingEntry, tmp_path: Path
    ) -> None:
        """ASVS V5.1.3: Editor not found returns error."""
        # Test with non-existent editor
        with patch.dict(os.environ, {"EDITOR": "nonexistent_editor"}):
            with patch("shutil.which", return_value=None):
                screen = FindingDetailScreen(
                    finding=sample_finding,
                    repo_path=tmp_path,
                )
                # Mock notify
                with patch.object(screen, "notify") as mock_notify:
                    screen.action_open_in_editor()

                    # Should call notify with error
                    mock_notify.assert_called_once()
                    args = mock_notify.call_args[0]
                    assert "not found" in args[0].lower()

    def test_editor_command_construction(
        self, sample_finding: FindingEntry, tmp_path: Path
    ) -> None:
        """Test editor command built correctly (ASVS V14.2.1)."""
        # Create the file
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("print('test')\n")

        with patch.dict(os.environ, {"EDITOR": "vim"}):
            with patch("shutil.which", return_value="/usr/bin/vim"):
                with patch("subprocess.run") as mock_run:
                    with patch("kekkai.triage.screens.FindingDetailScreen.app") as mock_app:
                        mock_app.suspend.return_value.__enter__ = MagicMock()
                        mock_app.suspend.return_value.__exit__ = MagicMock(return_value=False)

                        screen = FindingDetailScreen(
                            finding=sample_finding,
                            repo_path=tmp_path,
                        )
                        screen.action_open_in_editor()

                        # Verify subprocess.run called with list (not shell string)
                        assert mock_run.called
                        call_args = mock_run.call_args[0][0]
                        assert isinstance(call_args, list)
                        assert call_args[0] == "/usr/bin/vim"
                        assert "+42" in call_args
                        assert "src/app.py" in str(call_args[2])

    def test_editor_handles_missing_file(
        self, sample_finding: FindingEntry, tmp_path: Path
    ) -> None:
        """Test graceful handling when file doesn't exist."""
        with patch.dict(os.environ, {"EDITOR": "vim"}):
            with patch("shutil.which", return_value="/usr/bin/vim"):
                screen = FindingDetailScreen(
                    finding=sample_finding,
                    repo_path=tmp_path,
                )

                with patch.object(screen, "notify") as mock_notify:
                    screen.action_open_in_editor()

                    # Should notify about missing file
                    mock_notify.assert_called_once()
                    args = mock_notify.call_args[0]
                    assert "not found" in args[0].lower()

    def test_editor_requires_file_path_and_line(
        self, finding_no_file: FindingEntry, tmp_path: Path
    ) -> None:
        """Test that finding without file/line shows error."""
        screen = FindingDetailScreen(
            finding=finding_no_file,
            repo_path=tmp_path,
        )

        with patch.object(screen, "notify") as mock_notify:
            screen.action_open_in_editor()

            # Should notify about missing file path/line
            mock_notify.assert_called_once()
            args = mock_notify.call_args[0]
            assert "no file path" in args[0].lower()


class TestContextExpansion:
    """Tests for E/S hotkeys to expand/shrink context."""

    @pytest.fixture
    def sample_finding(self) -> FindingEntry:
        """Create a sample finding."""
        return FindingEntry(
            id="TEST-002",
            title="XSS vulnerability",
            severity=Severity.MEDIUM,
            scanner="semgrep",
            file_path="src/web.py",
            line=10,
        )

    def test_expand_context_increases_lines(
        self, sample_finding: FindingEntry, tmp_path: Path
    ) -> None:
        """Test E key expands context."""
        screen = FindingDetailScreen(
            finding=sample_finding,
            repo_path=tmp_path,
            context_lines=10,
        )

        with patch.object(screen, "notify") as mock_notify:
            with patch.object(screen, "_refresh_code_context") as mock_refresh:
                screen.action_expand_context()

                assert screen.context_lines == 20
                mock_refresh.assert_called_once()
                mock_notify.assert_called_once()

    def test_shrink_context_decreases_lines(
        self, sample_finding: FindingEntry, tmp_path: Path
    ) -> None:
        """Test S key shrinks context."""
        screen = FindingDetailScreen(
            finding=sample_finding,
            repo_path=tmp_path,
            context_lines=20,
        )

        with patch.object(screen, "notify") as _:
            with patch.object(screen, "_refresh_code_context") as mock_refresh:
                screen.action_shrink_context()

                assert screen.context_lines == 10
                mock_refresh.assert_called_once()

    def test_context_has_minimum_limit(self, sample_finding: FindingEntry, tmp_path: Path) -> None:
        """Test context cannot go below 5 lines."""
        screen = FindingDetailScreen(
            finding=sample_finding,
            repo_path=tmp_path,
            context_lines=5,
        )

        with patch.object(screen, "notify"), patch.object(screen, "_refresh_code_context"):
            screen.action_shrink_context()

            # Should stay at 5 (minimum)
            assert screen.context_lines == 5

    def test_context_has_maximum_limit(self, sample_finding: FindingEntry, tmp_path: Path) -> None:
        """Test context cannot exceed 100 lines."""
        screen = FindingDetailScreen(
            finding=sample_finding,
            repo_path=tmp_path,
            context_lines=100,
        )

        with patch.object(screen, "notify"), patch.object(screen, "_refresh_code_context"):
            screen.action_expand_context()

            # Should stay at 100 (maximum)
            assert screen.context_lines == 100

    def test_context_lines_passed_from_cli(
        self, sample_finding: FindingEntry, tmp_path: Path
    ) -> None:
        """Test that context_lines from CLI is used."""
        screen = FindingDetailScreen(
            finding=sample_finding,
            repo_path=tmp_path,
            context_lines=30,
        )

        assert screen.context_lines == 30


class TestAIFixWorkflow:
    """Tests for AI fix discoverability."""

    @pytest.fixture
    def sample_finding(self) -> FindingEntry:
        """Create a sample finding."""
        return FindingEntry(
            id="TEST-003",
            title="Hardcoded password",
            severity=Severity.HIGH,
            scanner="gitleaks",
            file_path="config.py",
            line=5,
        )

    def test_action_hints_displayed(self, sample_finding: FindingEntry, tmp_path: Path) -> None:
        """Test that action hints are rendered."""
        screen = FindingDetailScreen(
            finding=sample_finding,
            repo_path=tmp_path,
        )

        hints = screen._action_hints()

        # Should mention X and Ctrl+O
        hints_text = str(hints)
        assert "X" in hints_text or "x" in hints_text.lower()
        assert "Ctrl+O" in hints_text or "ctrl+o" in hints_text.lower()
        assert "EDITOR" in hints_text or "editor" in hints_text.lower()

    def test_fix_with_ai_requires_file_and_line(self, tmp_path: Path) -> None:
        """Test AI fix requires file path and line."""
        finding_no_file = FindingEntry(
            id="CVE-2024-1234",
            title="Dependency issue",
            severity=Severity.CRITICAL,
            scanner="trivy",
        )

        screen = FindingDetailScreen(
            finding=finding_no_file,
            repo_path=tmp_path,
        )

        with patch.object(screen, "notify") as mock_notify:
            screen.action_fix_with_ai()

            # Should notify about missing requirements
            mock_notify.assert_called_once()
            args = mock_notify.call_args[0]
            assert "cannot generate fix" in args[0].lower()


class TestVerificationHints:
    """Tests for post-fix verification hints."""

    def test_verification_hints_for_python(self) -> None:
        """Test hints suggest pytest for Python files."""
        from kekkai.triage.fix_screen import FixGenerationScreen

        finding = FindingEntry(
            id="TEST-004",
            title="SQL Injection",
            severity=Severity.HIGH,
            scanner="semgrep",
            file_path="src/db.py",
            line=10,
        )

        screen = FixGenerationScreen(finding=finding)
        hints = screen._get_verification_hints()

        assert "pytest" in hints.lower()
        assert "kekkai scan" in hints.lower()
        assert "git add" in hints.lower()

    def test_verification_hints_for_javascript(self) -> None:
        """Test hints suggest npm test for JS files."""
        from kekkai.triage.fix_screen import FixGenerationScreen

        finding = FindingEntry(
            id="TEST-005",
            title="XSS vulnerability",
            severity=Severity.MEDIUM,
            scanner="semgrep",
            file_path="src/app.js",
            line=20,
        )

        screen = FixGenerationScreen(finding=finding)
        hints = screen._get_verification_hints()

        assert "npm test" in hints.lower()

    def test_verification_hints_include_file_name(self) -> None:
        """Test hints include the modified file name."""
        from kekkai.triage.fix_screen import FixGenerationScreen

        finding = FindingEntry(
            id="TEST-006",
            title="Security issue",
            severity=Severity.HIGH,
            scanner="semgrep",
            file_path="src/utils/helpers.py",
            line=5,
        )

        screen = FixGenerationScreen(finding=finding)
        hints = screen._get_verification_hints()

        assert "helpers.py" in hints
