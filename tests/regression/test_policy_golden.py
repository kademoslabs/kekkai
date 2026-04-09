"""Regression tests for policy evaluation with golden fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kekkai.policy import PolicyConfig, evaluate_policy
from kekkai.scanners.base import Finding, Severity

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "policy"


def make_finding_from_dict(data: dict[str, Any]) -> Finding:
    """Create a Finding from test fixture data."""
    return Finding(
        scanner="test",
        title=data.get("title", "Test"),
        severity=Severity.from_string(data.get("severity", "info")),
        description=data.get("description", "Test finding"),
    )


def make_policy_from_dict(data: dict[str, Any]) -> PolicyConfig:
    """Create a PolicyConfig from test fixture data."""
    return PolicyConfig(
        fail_on_critical=data.get("fail_on_critical", True),
        fail_on_high=data.get("fail_on_high", True),
        fail_on_medium=data.get("fail_on_medium", False),
        fail_on_low=data.get("fail_on_low", False),
        fail_on_info=data.get("fail_on_info", False),
        max_critical=data.get("max_critical", 0),
        max_high=data.get("max_high", 0),
        max_medium=data.get("max_medium", -1),
        max_low=data.get("max_low", -1),
        max_info=data.get("max_info", -1),
        max_total=data.get("max_total", -1),
    )


@pytest.mark.regression
class TestPolicyGolden:
    """Golden tests for policy evaluation."""

    @pytest.fixture
    def golden_cases(self) -> list[dict[str, Any]]:
        """Load golden test cases."""
        fixture_path = FIXTURES_DIR / "golden_inputs.json"
        data = json.loads(fixture_path.read_text())
        result: list[dict[str, Any]] = data["test_cases"]
        return result

    def test_golden_policy_decisions(self, golden_cases: list[dict[str, Any]]) -> None:
        """Test all golden policy decisions."""
        for case in golden_cases:
            name = case["name"]
            findings = [make_finding_from_dict(f) for f in case.get("findings", [])]
            policy = make_policy_from_dict(case.get("policy", {}))
            scan_errors = case.get("scan_errors")
            expected = case["expected"]

            result = evaluate_policy(findings, policy, scan_errors)

            assert result.passed == expected["passed"], f"Case '{name}': passed mismatch"
            assert result.exit_code == expected["exit_code"], f"Case '{name}': exit_code mismatch"
            assert len(result.violations) == expected["violation_count"], (
                f"Case '{name}': violation_count mismatch"
            )

    def test_no_findings_passes(self, golden_cases: list[dict[str, Any]]) -> None:
        """Explicit test for no findings case."""
        case = next(c for c in golden_cases if c["name"] == "no_findings_passes")
        policy = make_policy_from_dict(case["policy"])
        result = evaluate_policy([], policy)
        assert result.passed is True
        assert result.exit_code == 0

    def test_critical_finding_fails(self, golden_cases: list[dict[str, Any]]) -> None:
        """Explicit test for critical finding case."""
        case = next(c for c in golden_cases if c["name"] == "critical_finding_fails")
        findings = [make_finding_from_dict(f) for f in case["findings"]]
        policy = make_policy_from_dict(case["policy"])
        result = evaluate_policy(findings, policy)
        assert result.passed is False
        assert result.exit_code == 1

    def test_scan_error_fails_with_exit_2(self, golden_cases: list[dict[str, Any]]) -> None:
        """Explicit test for scan error case."""
        case = next(c for c in golden_cases if c["name"] == "scan_error_fails")
        policy = make_policy_from_dict(case["policy"])
        result = evaluate_policy([], policy, case["scan_errors"])
        assert result.passed is False
        assert result.exit_code == 2


@pytest.mark.regression
class TestPolicyOutputSchema:
    """Test policy result JSON schema stability."""

    def test_result_json_has_required_fields(self) -> None:
        """Verify JSON output contains all required fields."""
        policy = PolicyConfig()
        result = evaluate_policy([], policy)
        json_dict = result.to_dict()

        required_fields = ["passed", "exit_code", "violations", "counts", "scan_errors"]
        for field in required_fields:
            assert field in json_dict, f"Missing required field: {field}"

    def test_counts_json_has_severity_fields(self) -> None:
        """Verify counts contain all severity levels."""
        policy = PolicyConfig()
        result = evaluate_policy([], policy)
        counts = result.to_dict()["counts"]
        assert isinstance(counts, dict)

        severity_fields = ["critical", "high", "medium", "low", "info", "unknown"]
        for field in severity_fields:
            assert field in counts, f"Missing severity field: {field}"

    def test_violation_json_structure(self) -> None:
        """Verify violation JSON structure."""
        policy = PolicyConfig(fail_on_critical=True, max_critical=0)
        findings = [
            Finding(
                scanner="test",
                title="Test",
                severity=Severity.CRITICAL,
                description="Test",
            )
        ]
        result = evaluate_policy(findings, policy)
        violations = result.to_dict()["violations"]
        assert isinstance(violations, list)
        violation = violations[0]
        assert isinstance(violation, dict)

        required_fields = ["severity", "count", "threshold", "message"]
        for field in required_fields:
            assert field in violation, f"Missing violation field: {field}"
