"""Unit tests for policy enforcement module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from kekkai.policy import (
    EXIT_POLICY_VIOLATION,
    EXIT_SCAN_ERROR,
    EXIT_SUCCESS,
    PolicyConfig,
    PolicyResult,
    PolicyViolation,
    SeverityCount,
    count_findings_by_severity,
    default_ci_policy,
    evaluate_policy,
    parse_fail_on,
)
from kekkai.scanners.base import Finding, Severity


class TestSeverityFromString:
    """Test Severity.from_string for coverage."""

    def test_normalizes_moderate_to_medium(self) -> None:
        assert Severity.from_string("moderate") == Severity.MEDIUM

    def test_normalizes_informational_to_info(self) -> None:
        assert Severity.from_string("informational") == Severity.INFO

    def test_normalizes_warning_to_low(self) -> None:
        assert Severity.from_string("warning") == Severity.LOW


def make_finding(severity: str, title: str = "Test") -> Finding:
    """Helper to create a finding with specific severity."""
    return Finding(
        scanner="test",
        title=title,
        severity=Severity.from_string(severity),
        description="Test finding",
    )


class TestPolicyConfig:
    def test_default_values(self) -> None:
        config = PolicyConfig()
        assert config.fail_on_critical is True
        assert config.fail_on_high is True
        assert config.fail_on_medium is False
        assert config.max_critical == 0
        assert config.max_high == 0
        assert config.max_medium == -1

    def test_validate_valid_config(self) -> None:
        config = PolicyConfig()
        errors = config.validate()
        assert errors == []

    def test_validate_invalid_threshold(self) -> None:
        config = PolicyConfig(max_critical=-5)
        errors = config.validate()
        assert len(errors) == 1
        assert "max_critical must be >= -1" in errors[0]


class TestSeverityCount:
    def test_total_calculation(self) -> None:
        counts = SeverityCount(critical=1, high=2, medium=3, low=4, info=5, unknown=1)
        assert counts.total == 16

    def test_default_zeros(self) -> None:
        counts = SeverityCount()
        assert counts.total == 0


class TestCountFindingsBySeverity:
    def test_counts_severities_correctly(self) -> None:
        findings = [
            make_finding("critical"),
            make_finding("critical"),
            make_finding("high"),
            make_finding("medium"),
            make_finding("low"),
            make_finding("info"),
        ]
        counts = count_findings_by_severity(findings)
        assert counts.critical == 2
        assert counts.high == 1
        assert counts.medium == 1
        assert counts.low == 1
        assert counts.info == 1
        assert counts.unknown == 0

    def test_empty_findings(self) -> None:
        counts = count_findings_by_severity([])
        assert counts.total == 0


class TestEvaluatePolicy:
    def test_passes_with_no_findings(self) -> None:
        config = PolicyConfig()
        result = evaluate_policy([], config)
        assert result.passed is True
        assert result.exit_code == EXIT_SUCCESS
        assert result.violations == []

    def test_fails_on_critical(self) -> None:
        config = PolicyConfig(fail_on_critical=True, max_critical=0)
        findings = [make_finding("critical")]
        result = evaluate_policy(findings, config)
        assert result.passed is False
        assert result.exit_code == EXIT_POLICY_VIOLATION
        assert len(result.violations) == 1
        assert result.violations[0].severity == "critical"

    def test_fails_on_high(self) -> None:
        config = PolicyConfig(fail_on_high=True, max_high=0)
        findings = [make_finding("high")]
        result = evaluate_policy(findings, config)
        assert result.passed is False
        assert result.exit_code == EXIT_POLICY_VIOLATION

    def test_passes_when_below_threshold(self) -> None:
        config = PolicyConfig(fail_on_high=True, max_high=2)
        findings = [make_finding("high"), make_finding("high")]
        result = evaluate_policy(findings, config)
        assert result.passed is True
        assert result.exit_code == EXIT_SUCCESS

    def test_fails_when_exceeds_threshold(self) -> None:
        config = PolicyConfig(fail_on_high=True, max_high=1)
        findings = [make_finding("high"), make_finding("high")]
        result = evaluate_policy(findings, config)
        assert result.passed is False
        assert result.exit_code == EXIT_POLICY_VIOLATION

    def test_ignores_disabled_severities(self) -> None:
        config = PolicyConfig(
            fail_on_critical=False,
            fail_on_high=False,
            fail_on_medium=False,
        )
        findings = [
            make_finding("critical"),
            make_finding("high"),
            make_finding("medium"),
        ]
        result = evaluate_policy(findings, config)
        assert result.passed is True
        assert result.exit_code == EXIT_SUCCESS

    def test_no_limit_means_unlimited(self) -> None:
        config = PolicyConfig(fail_on_medium=True, max_medium=-1)
        findings = [make_finding("medium") for _ in range(100)]
        result = evaluate_policy(findings, config)
        assert result.passed is True

    def test_total_threshold_enforced(self) -> None:
        config = PolicyConfig(
            fail_on_critical=False,
            fail_on_high=False,
            max_total=5,
        )
        findings = [make_finding("low") for _ in range(6)]
        result = evaluate_policy(findings, config)
        assert result.passed is False
        assert any(v.severity == "total" for v in result.violations)

    def test_scan_errors_cause_failure(self) -> None:
        config = PolicyConfig()
        result = evaluate_policy([], config, scan_errors=["Scanner failed"])
        assert result.passed is False
        assert result.exit_code == EXIT_SCAN_ERROR
        assert "Scanner failed" in result.scan_errors

    def test_invalid_config_fails_securely(self) -> None:
        # Create config with invalid threshold (would need custom construction)
        # For now test the validation path
        config = PolicyConfig(max_critical=-5)
        result = evaluate_policy([], config)
        assert result.passed is False
        assert result.exit_code == EXIT_SCAN_ERROR


class TestPolicyResult:
    def test_to_dict(self) -> None:
        result = PolicyResult(
            passed=True,
            exit_code=0,
            violations=[],
            counts=SeverityCount(critical=1, high=2),
        )
        d = result.to_dict()
        assert d["passed"] is True
        assert d["exit_code"] == 0
        counts = d["counts"]
        assert isinstance(counts, dict)
        assert counts["critical"] == 1

    def test_to_json(self) -> None:
        result = PolicyResult(
            passed=False,
            exit_code=1,
            violations=[
                PolicyViolation(
                    severity="critical",
                    count=1,
                    threshold=0,
                    message="Found 1 critical",
                )
            ],
            counts=SeverityCount(critical=1),
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["passed"] is False
        assert len(parsed["violations"]) == 1

    def test_write_json(self) -> None:
        result = PolicyResult(passed=True, exit_code=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "result.json"
            result.write_json(path)
            assert path.exists()
            content = json.loads(path.read_text())
            assert content["passed"] is True


class TestParseFailOn:
    def test_parse_critical(self) -> None:
        config = parse_fail_on("critical")
        assert config.fail_on_critical is True
        assert config.fail_on_high is False
        assert config.fail_on_medium is False

    def test_parse_high_cascades(self) -> None:
        config = parse_fail_on("high")
        assert config.fail_on_critical is True
        assert config.fail_on_high is True
        assert config.fail_on_medium is False

    def test_parse_medium_cascades(self) -> None:
        config = parse_fail_on("medium")
        assert config.fail_on_critical is True
        assert config.fail_on_high is True
        assert config.fail_on_medium is True
        assert config.fail_on_low is False

    def test_parse_comma_separated(self) -> None:
        config = parse_fail_on("critical,high")
        assert config.fail_on_critical is True
        assert config.fail_on_high is True

    def test_parse_empty_string(self) -> None:
        config = parse_fail_on("")
        # Returns default config
        assert config.fail_on_critical is True  # default

    def test_parse_unknown_severity_ignored(self) -> None:
        config = parse_fail_on("unknown_severity")
        # Should not crash, just log warning
        assert isinstance(config, PolicyConfig)


class TestDefaultCIPolicy:
    def test_fails_on_critical_and_high(self) -> None:
        config = default_ci_policy()
        assert config.fail_on_critical is True
        assert config.fail_on_high is True
        assert config.fail_on_medium is False
        assert config.max_critical == 0
        assert config.max_high == 0


class TestExitCodes:
    def test_exit_code_values(self) -> None:
        assert EXIT_SUCCESS == 0
        assert EXIT_POLICY_VIOLATION == 1
        assert EXIT_SCAN_ERROR == 2


class TestBoundaryConditions:
    """Test edge cases and boundary conditions for policy evaluation."""

    def test_exactly_at_threshold(self) -> None:
        config = PolicyConfig(fail_on_critical=True, max_critical=2)
        findings = [make_finding("critical"), make_finding("critical")]
        result = evaluate_policy(findings, config)
        # 2 findings with max 2 should pass
        assert result.passed is True

    def test_one_over_threshold(self) -> None:
        config = PolicyConfig(fail_on_critical=True, max_critical=2)
        findings = [make_finding("critical") for _ in range(3)]
        result = evaluate_policy(findings, config)
        assert result.passed is False

    def test_zero_threshold_fails_on_any(self) -> None:
        config = PolicyConfig(fail_on_info=True, max_info=0)
        findings = [make_finding("info")]
        result = evaluate_policy(findings, config)
        assert result.passed is False

    def test_mixed_severities(self) -> None:
        config = PolicyConfig(
            fail_on_critical=True,
            fail_on_high=True,
            max_critical=0,
            max_high=0,
        )
        findings = [
            make_finding("critical"),
            make_finding("high"),
            make_finding("medium"),
        ]
        result = evaluate_policy(findings, config)
        assert result.passed is False
        # Should have two violations
        assert len(result.violations) == 2

    def test_unknown_severity_finding(self) -> None:
        """Test that unknown severity findings are counted."""
        finding = Finding(
            scanner="test",
            title="Test",
            severity=Severity.UNKNOWN,
            description="Unknown severity finding",
        )
        counts = count_findings_by_severity([finding])
        assert counts.unknown == 1


class TestParseFailOnEdgeCases:
    """Test edge cases in --fail-on parsing."""

    def test_parse_low_includes_all_higher(self) -> None:
        config = parse_fail_on("low")
        assert config.fail_on_critical is True
        assert config.fail_on_high is True
        assert config.fail_on_medium is True
        assert config.fail_on_low is True
        assert config.fail_on_info is False

    def test_parse_info_includes_all(self) -> None:
        config = parse_fail_on("info")
        assert config.fail_on_critical is True
        assert config.fail_on_high is True
        assert config.fail_on_medium is True
        assert config.fail_on_low is True
        assert config.fail_on_info is True

    def test_parse_whitespace_handling(self) -> None:
        config = parse_fail_on("  critical , high  ")
        assert config.fail_on_critical is True
        assert config.fail_on_high is True
