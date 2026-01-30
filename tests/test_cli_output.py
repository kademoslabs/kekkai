"""Unit tests for Rich CLI output utilities."""

from __future__ import annotations

from kekkai.output import (
    ScanSummaryRow,
    console,
    print_dashboard,
    print_scan_summary,
    sanitize_error,
    sanitize_for_terminal,
    splash,
)


class TestSanitizeForTerminal:
    """Tests for ANSI escape sequence sanitization."""

    def test_strip_ansi_escape_codes(self) -> None:
        malicious = "\x1b[31mFake Safe\x1b[0m - Actually Dangerous"
        sanitized = sanitize_for_terminal(malicious)
        assert "\x1b[" not in sanitized
        assert "Fake Safe - Actually Dangerous" in sanitized

    def test_strip_multiple_escape_sequences(self) -> None:
        text = "\x1b[1m\x1b[31mBold Red\x1b[0m Normal \x1b[32mGreen\x1b[0m"
        sanitized = sanitize_for_terminal(text)
        assert "\x1b[" not in sanitized
        assert "Bold Red Normal Green" in sanitized

    def test_preserve_normal_text(self) -> None:
        text = "Normal text without escape codes"
        assert sanitize_for_terminal(text) == text

    def test_empty_string(self) -> None:
        assert sanitize_for_terminal("") == ""

    def test_strip_cursor_movement_codes(self) -> None:
        text = "\x1b[2J\x1b[HClear screen and home"
        sanitized = sanitize_for_terminal(text)
        assert "\x1b[" not in sanitized


class TestSanitizeError:
    """Tests for error message sanitization."""

    def test_truncate_long_message(self) -> None:
        long_msg = "A" * 500
        sanitized = sanitize_error(long_msg, max_length=100)
        assert len(sanitized) <= 103  # 100 + "..."
        assert sanitized.endswith("...")

    def test_redact_unix_paths(self) -> None:
        error = "File not found: /home/user/secret/config.py"
        sanitized = sanitize_error(error)
        assert "/home/user/secret/config.py" not in sanitized
        assert "[path]" in sanitized

    def test_redact_windows_paths(self) -> None:
        error = r"File not found: C:\Users\secret\config.py"
        sanitized = sanitize_error(error)
        assert "Users" not in sanitized

    def test_redact_line_numbers(self) -> None:
        error = "Error at line 42 in module"
        sanitized = sanitize_error(error)
        assert "line 42" not in sanitized
        assert "line [N]" in sanitized

    def test_strip_ansi_from_error(self) -> None:
        error = "\x1b[31mError:\x1b[0m Something went wrong"
        sanitized = sanitize_error(error)
        assert "\x1b[" not in sanitized

    def test_handle_exception_object(self) -> None:
        exc = ValueError("Test error message")
        sanitized = sanitize_error(exc)
        assert "Test error message" in sanitized


class TestSplash:
    """Tests for splash banner rendering."""

    def test_splash_returns_version(self) -> None:
        output = splash()
        assert "Kekkai" in output
        assert "Local-First AppSec Orchestrator" in output

    def test_splash_force_plain(self) -> None:
        output = splash(force_plain=True)
        assert "Kekkai" in output
        assert "\x1b[" not in output  # No ANSI codes

    def test_splash_contains_branding(self) -> None:
        output = splash(force_plain=True)
        assert "Local-First AppSec Orchestrator" in output


class TestPrintDashboard:
    """Tests for dashboard rendering."""

    def test_print_dashboard_exists(self) -> None:
        # print_dashboard should exist and be callable
        assert callable(print_dashboard)


class TestPrintScanSummary:
    """Tests for scan summary table rendering."""

    def test_empty_results(self, capsys: object) -> None:
        import sys
        from io import StringIO

        captured = StringIO()
        sys.stdout = captured
        try:
            print_scan_summary([], force_plain=True)
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        assert "Scan Summary:" in output

    def test_single_scanner_success(self, capsys: object) -> None:
        import sys
        from io import StringIO

        rows = [
            ScanSummaryRow(
                scanner="trivy",
                success=True,
                findings_count=5,
                duration_ms=1234,
            )
        ]
        captured = StringIO()
        sys.stdout = captured
        try:
            print_scan_summary(rows, force_plain=True)
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        assert "trivy" in output
        assert "OK" in output
        assert "5" in output
        assert "1234ms" in output

    def test_scanner_failure(self, capsys: object) -> None:
        import sys
        from io import StringIO

        rows = [
            ScanSummaryRow(
                scanner="semgrep",
                success=False,
                findings_count=0,
                duration_ms=500,
            )
        ]
        captured = StringIO()
        sys.stdout = captured
        try:
            print_scan_summary(rows, force_plain=True)
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        assert "semgrep" in output
        assert "FAIL" in output

    def test_multiple_scanners(self, capsys: object) -> None:
        import sys
        from io import StringIO

        rows = [
            ScanSummaryRow("trivy", True, 3, 1000),
            ScanSummaryRow("semgrep", True, 7, 2000),
            ScanSummaryRow("gitleaks", False, 0, 100),
        ]
        captured = StringIO()
        sys.stdout = captured
        try:
            print_scan_summary(rows, force_plain=True)
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        assert "trivy" in output
        assert "semgrep" in output
        assert "gitleaks" in output

    def test_sanitizes_scanner_names(self, capsys: object) -> None:
        import sys
        from io import StringIO

        rows = [
            ScanSummaryRow(
                scanner="\x1b[31mmalicious\x1b[0m",
                success=True,
                findings_count=0,
                duration_ms=100,
            )
        ]
        captured = StringIO()
        sys.stdout = captured
        try:
            print_scan_summary(rows, force_plain=True)
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        assert "\x1b[" not in output
        assert "malicious" in output


class TestConsole:
    """Tests for console configuration."""

    def test_console_exists(self) -> None:
        # Console should be instantiated
        assert console is not None

    def test_console_is_terminal_attribute(self) -> None:
        # Console should have is_terminal attribute
        assert hasattr(console, "is_terminal")
