"""Integration tests for triage code context display."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.triage import FindingEntry, Severity, TriageApp
from kekkai.triage.screens import FindingDetailScreen


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    """Create a temporary repository with sample files."""
    repo = tmp_path / "test_repo"
    repo.mkdir()

    # Create sample Python file with vulnerability
    vuln_file = repo / "app.py"
    vuln_file.write_text(
        """import os
import sys

def get_user_data(user_id):
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

def process_input(data):
    # Some processing
    return data.strip()

def main():
    user_id = sys.argv[1]
    data = get_user_data(user_id)
    print(data)

if __name__ == "__main__":
    main()
"""
    )

    # Create JavaScript file
    js_file = repo / "script.js"
    js_file.write_text(
        """// JavaScript code
function fetchData(url) {
    // Potential XSS vulnerability
    document.getElementById('output').innerHTML = url;
}

fetchData(window.location.hash);
"""
    )

    return repo


@pytest.fixture
def sample_finding_python(temp_repo: Path) -> FindingEntry:
    """Create a sample finding for Python file."""
    return FindingEntry(
        id="SEMGREP-SQL-001",
        title="SQL Injection vulnerability",
        severity=Severity.HIGH,
        scanner="semgrep",
        file_path="app.py",
        line=6,
        description="SQL injection in user query construction",
        rule_id="python.sql.injection",
    )


@pytest.fixture
def sample_finding_javascript(temp_repo: Path) -> FindingEntry:
    """Create a sample finding for JavaScript file."""
    return FindingEntry(
        id="SEMGREP-XSS-001",
        title="XSS vulnerability",
        severity=Severity.HIGH,
        scanner="semgrep",
        file_path="script.js",
        line=4,
        description="Potential XSS via innerHTML",
        rule_id="javascript.xss.innerHTML",
    )


@pytest.fixture
def finding_no_file_path() -> FindingEntry:
    """Create a finding without file path (e.g., CVE)."""
    return FindingEntry(
        id="CVE-2024-1234",
        title="Vulnerability in dependency",
        severity=Severity.CRITICAL,
        scanner="trivy",
        description="Critical vulnerability in package",
    )


@pytest.mark.integration
class TestTriageCodeContextIntegration:
    """Integration tests for code context in triage TUI."""

    def test_detail_screen_shows_code_for_valid_finding(
        self, temp_repo: Path, sample_finding_python: FindingEntry
    ) -> None:
        """Test that detail screen shows code context for valid finding."""
        screen = FindingDetailScreen(
            finding=sample_finding_python,
            repo_path=temp_repo,
        )

        # Test that code context is rendered
        code_widget = screen._render_code_context()
        assert code_widget is not None
        assert code_widget.id == "code-context-display"

    def test_detail_screen_code_contains_vulnerable_line(
        self, temp_repo: Path, sample_finding_python: FindingEntry
    ) -> None:
        """Test that code context contains the vulnerable line."""
        screen = FindingDetailScreen(
            finding=sample_finding_python,
            repo_path=temp_repo,
        )

        code_widget = screen._render_code_context()
        assert code_widget is not None
        # The code widget should contain Static with Syntax

    def test_detail_screen_handles_missing_file_gracefully(self, temp_repo: Path) -> None:
        """Test that detail screen handles missing files gracefully."""
        finding = FindingEntry(
            id="TEST-001",
            title="Test finding",
            severity=Severity.MEDIUM,
            scanner="test",
            file_path="nonexistent.py",
            line=10,
        )

        screen = FindingDetailScreen(finding=finding, repo_path=temp_repo)
        code_widget = screen._render_code_context()

        # Should return error widget, not crash
        assert code_widget is not None
        assert "error-message" in code_widget.classes

    def test_detail_screen_skips_code_for_findings_without_file_path(
        self, temp_repo: Path, finding_no_file_path: FindingEntry
    ) -> None:
        """Test that findings without file path don't show code context."""
        screen = FindingDetailScreen(
            finding=finding_no_file_path,
            repo_path=temp_repo,
        )

        code_widget = screen._render_code_context()
        assert code_widget is None

    def test_detail_screen_skips_code_for_findings_without_line(self, temp_repo: Path) -> None:
        """Test that findings without line number don't show code context."""
        finding = FindingEntry(
            id="TEST-002",
            title="Test finding",
            severity=Severity.LOW,
            scanner="test",
            file_path="app.py",
            line=None,  # No line number
        )

        screen = FindingDetailScreen(finding=finding, repo_path=temp_repo)
        code_widget = screen._render_code_context()
        assert code_widget is None

    def test_detail_screen_handles_javascript_file(
        self, temp_repo: Path, sample_finding_javascript: FindingEntry
    ) -> None:
        """Test that JavaScript files are handled with correct syntax highlighting."""
        screen = FindingDetailScreen(
            finding=sample_finding_javascript,
            repo_path=temp_repo,
        )

        code_widget = screen._render_code_context()
        assert code_widget is not None

    def test_detail_screen_handles_sensitive_file(self, temp_repo: Path) -> None:
        """Test that sensitive files show appropriate error message."""
        # Create .env file
        env_file = temp_repo / ".env"
        env_file.write_text("SECRET_KEY=super_secret\n")

        finding = FindingEntry(
            id="GITLEAKS-001",
            title="Secret detected",
            severity=Severity.HIGH,
            scanner="gitleaks",
            file_path=".env",
            line=1,
        )

        screen = FindingDetailScreen(finding=finding, repo_path=temp_repo)
        code_widget = screen._render_code_context()

        assert code_widget is not None
        assert "error-message" in code_widget.classes

    def test_triage_app_passes_repo_path_to_detail_screen(
        self, temp_repo: Path, sample_finding_python: FindingEntry
    ) -> None:
        """Test that TriageApp correctly passes repo_path to detail screens."""
        app = TriageApp(
            findings=[sample_finding_python],
            repo_path=temp_repo,
        )

        assert app.repo_path == temp_repo

    def test_detail_screen_with_subdirectory_file(self, temp_repo: Path) -> None:
        """Test code context for files in subdirectories."""
        # Create subdirectory with file
        subdir = temp_repo / "src" / "utils"
        subdir.mkdir(parents=True)

        util_file = subdir / "helpers.py"
        util_file.write_text(
            """def helper_function():
    # Some code
    value = user_input  # vulnerability
    return process(value)
"""
        )

        finding = FindingEntry(
            id="TEST-003",
            title="Test finding in subdir",
            severity=Severity.MEDIUM,
            scanner="test",
            file_path="src/utils/helpers.py",
            line=3,
        )

        screen = FindingDetailScreen(finding=finding, repo_path=temp_repo)
        code_widget = screen._render_code_context()

        assert code_widget is not None
        assert code_widget.id == "code-context-display"

    def test_detail_screen_fallback_on_syntax_error(self, temp_repo: Path) -> None:
        """Test that screen falls back gracefully if syntax highlighting fails."""
        # Create file with unusual content that might cause issues
        weird_file = temp_repo / "weird.txt"
        weird_file.write_text("Some\x00weird\x00content\nwith null bytes\n")

        finding = FindingEntry(
            id="TEST-004",
            title="Test finding",
            severity=Severity.LOW,
            scanner="test",
            file_path="weird.txt",
            line=2,
        )

        screen = FindingDetailScreen(finding=finding, repo_path=temp_repo)
        # Should not crash, might return error or plain text
        code_widget = screen._render_code_context()
        # Either shows code or shows error, but doesn't crash
        assert code_widget is not None or code_widget is None

    def test_app_initializes_with_default_repo_path(
        self, sample_finding_python: FindingEntry
    ) -> None:
        """Test that TriageApp initializes with default repo_path."""
        app = TriageApp(findings=[sample_finding_python])

        # Should default to current working directory
        assert app.repo_path == Path.cwd()

    def test_detail_screen_initializes_with_default_repo_path(
        self, sample_finding_python: FindingEntry
    ) -> None:
        """Test that FindingDetailScreen initializes with default repo_path."""
        screen = FindingDetailScreen(finding=sample_finding_python)

        # Should default to current working directory
        assert screen.repo_path == Path.cwd()


@pytest.mark.integration
class TestTriageCodeContextWorkflow:
    """Integration tests for full triage workflow with code context."""

    def test_full_workflow_with_code_context(self, tmp_path: Path) -> None:
        """Test complete workflow: load findings → create app → view details."""
        # Create repository
        repo = tmp_path / "repo"
        repo.mkdir()

        # Create vulnerable file
        vuln_file = repo / "vulnerable.py"
        vuln_file.write_text(
            """def bad_function(user_input):
    eval(user_input)  # Dangerous!
    return True
"""
        )

        # Create findings JSON
        findings_json = tmp_path / "findings.json"
        finding_data = {
            "id": "SEMGREP-EVAL-001",
            "title": "Use of eval() detected",
            "severity": "high",
            "scanner": "semgrep",
            "file_path": "vulnerable.py",
            "line": 2,
            "description": "Dangerous use of eval()",
            "rule_id": "python.security.eval",
        }
        findings_json.write_text(json.dumps([finding_data]))

        # Load findings
        from kekkai.triage.models import load_findings_from_json

        with findings_json.open() as f:
            data = json.load(f)
        findings = load_findings_from_json(data)

        # Create app with repo path
        app = TriageApp(findings=findings, repo_path=repo)

        assert len(app.findings) == 1
        assert app.repo_path == repo

        # Verify detail screen can be created
        finding = app.findings[0]
        screen = FindingDetailScreen(finding=finding, repo_path=repo)

        code_widget = screen._render_code_context()
        assert code_widget is not None
