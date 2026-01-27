from __future__ import annotations

import platform
from pathlib import Path
from unittest import mock

import pytest

from kekkai.scanners.base import ScanContext, Severity
from kekkai.scanners.falco import FalcoScanner, create_falco_scanner

SAMPLE_FALCO_OUTPUT = (
    '{"time":"2024-01-15T10:30:00Z","rule":"Terminal shell in container",'
    '"priority":"Notice","output":"Terminal shell spawned",'
    '"output_fields":{"container.id":"abc123","container.name":"web-app",'
    '"proc.name":"bash","proc.cmdline":"bash -i"}}\n'
    '{"time":"2024-01-15T10:31:00Z","rule":"Write below etc",'
    '"priority":"Error","output":"File write in /etc",'
    '"output_fields":{"container.id":"abc123","container.name":"web-app",'
    '"proc.name":"cat","proc.cmdline":"cat > /etc/passwd"}}\n'
    '{"time":"2024-01-15T10:32:00Z","rule":"Sensitive file read",'
    '"priority":"Warning","output":"Read of sensitive file",'
    '"output_fields":{"proc.name":"cat","proc.cmdline":"cat /etc/shadow"}}\n'
)


class TestFalcoScannerParse:
    def test_parse_jsonl_output(self) -> None:
        scanner = FalcoScanner(enabled=True)
        findings = scanner.parse(SAMPLE_FALCO_OUTPUT)

        assert len(findings) == 3

        terminal = findings[0]
        assert terminal.scanner == "falco"
        assert terminal.title == "Terminal shell in container"
        assert terminal.severity == Severity.LOW  # Notice
        assert "bash" in terminal.description
        assert terminal.extra["container_name"] == "web-app"

        etc_write = findings[1]
        assert etc_write.title == "Write below etc"
        assert etc_write.severity == Severity.HIGH  # Error

        sensitive = findings[2]
        assert sensitive.title == "Sensitive file read"
        assert sensitive.severity == Severity.MEDIUM  # Warning

    def test_parse_empty_output(self) -> None:
        scanner = FalcoScanner(enabled=True)
        findings = scanner.parse("")
        assert findings == []

    def test_parse_ignores_invalid_json_lines(self) -> None:
        scanner = FalcoScanner(enabled=True)
        output = """{"rule":"Valid Alert","priority":"Notice"}
invalid json line
{"rule":"Another Alert","priority":"Warning"}"""
        findings = scanner.parse(output)
        assert len(findings) == 2


class TestFalcoScannerPriorityMapping:
    def test_emergency_is_critical(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("emergency") == Severity.CRITICAL

    def test_alert_is_critical(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("alert") == Severity.CRITICAL

    def test_critical_is_critical(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("critical") == Severity.CRITICAL

    def test_error_is_high(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("error") == Severity.HIGH

    def test_warning_is_medium(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("warning") == Severity.MEDIUM

    def test_notice_is_low(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("notice") == Severity.LOW

    def test_informational_is_info(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("informational") == Severity.INFO

    def test_debug_is_info(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("debug") == Severity.INFO

    def test_unknown_is_unknown(self) -> None:
        scanner = FalcoScanner(enabled=True)
        assert scanner._map_priority_to_severity("foo") == Severity.UNKNOWN


class TestFalcoScannerAvailability:
    @pytest.mark.skipif(platform.system() != "Linux", reason="Falco is Linux-only")
    def test_not_available_when_disabled(self) -> None:
        scanner = FalcoScanner(enabled=False)
        available, reason = scanner.is_available()
        assert not available
        assert "requires explicit" in reason

    @pytest.mark.skipif(platform.system() == "Linux", reason="Test for non-Linux")
    def test_not_available_on_non_linux(self) -> None:
        scanner = FalcoScanner(enabled=True)
        available, reason = scanner.is_available()
        assert not available
        assert "Linux-only" in reason

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_not_available_without_binary(self) -> None:
        scanner = FalcoScanner(enabled=True)
        with mock.patch("shutil.which", return_value=None):
            available, reason = scanner.is_available()
            assert not available
            assert "not found" in reason


class TestFalcoScannerRun:
    def test_returns_error_when_not_available(self, tmp_path: Path) -> None:
        scanner = FalcoScanner(enabled=False)
        ctx = ScanContext(
            repo_path=tmp_path,
            output_dir=tmp_path,
            run_id="test-run",
        )
        result = scanner.run(ctx)

        assert not result.success
        assert "not available" in (result.error or "")

    def test_reads_existing_alerts_file(self, tmp_path: Path) -> None:
        # Create alerts file
        alerts_file = tmp_path / "falco-alerts.json"
        alerts_file.write_text(SAMPLE_FALCO_OUTPUT)

        scanner = FalcoScanner(enabled=True)

        # Mock availability check to pass
        with mock.patch.object(scanner, "is_available", return_value=(True, "ok")):
            ctx = ScanContext(
                repo_path=tmp_path,
                output_dir=tmp_path,
                run_id="test-run",
            )
            result = scanner.run(ctx)

            assert result.success
            assert len(result.findings) == 3


class TestCreateFalcoScanner:
    def test_creates_disabled_by_default(self) -> None:
        scanner = create_falco_scanner()
        assert not scanner._enabled

    def test_creates_enabled_when_specified(self) -> None:
        scanner = create_falco_scanner(enabled=True)
        assert scanner._enabled

    def test_creates_with_rules_file(self) -> None:
        scanner = create_falco_scanner(rules_file=Path("/custom/rules.yaml"))
        assert scanner._rules_file == Path("/custom/rules.yaml")


class TestFalcoScannerProperties:
    def test_name(self) -> None:
        scanner = FalcoScanner()
        assert scanner.name == "falco"

    def test_scan_type(self) -> None:
        scanner = FalcoScanner()
        assert scanner.scan_type == "Falco Scan"
