"""Policy enforcement module for CI-grade security gates.

Evaluates scan findings against configurable thresholds and produces
machine-readable results for CI/CD integration.

ASVS Requirements:
- V2.3.2: Business logic limits (threshold validation)
- V16.3.3: Log attempts to bypass controls
- V16.5.3: Fail securely (errors default to failure)
- V15.3.5: Strict typing for comparisons
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .scanners.base import Finding

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

# Exit codes for CI mode
EXIT_SUCCESS = 0
EXIT_POLICY_VIOLATION = 1
EXIT_SCAN_ERROR = 2


@dataclass(frozen=True)
class PolicyConfig:
    """Configuration for policy enforcement.

    Thresholds define the maximum number of findings allowed per severity.
    Setting a threshold to 0 means any finding of that severity fails the policy.
    Setting to -1 (or None) means no limit for that severity.
    """

    fail_on_critical: bool = True
    fail_on_high: bool = True
    fail_on_medium: bool = False
    fail_on_low: bool = False
    fail_on_info: bool = False

    max_critical: int = 0
    max_high: int = 0
    max_medium: int = -1  # -1 = no limit
    max_low: int = -1
    max_info: int = -1

    # Total findings limit across all severities
    max_total: int = -1

    def validate(self) -> list[str]:
        """Validate policy configuration, return list of errors."""
        errors: list[str] = []

        # Validate threshold values are integers and reasonable
        for attr in ("max_critical", "max_high", "max_medium", "max_low", "max_info", "max_total"):
            value = getattr(self, attr)
            if not isinstance(value, int):
                errors.append(f"{attr} must be an integer, got {type(value).__name__}")
            elif value < -1:
                errors.append(f"{attr} must be >= -1, got {value}")

        return errors


@dataclass(frozen=True)
class PolicyViolation:
    """A single policy violation."""

    severity: str
    count: int
    threshold: int
    message: str


@dataclass(frozen=True)
class SeverityCount:
    """Count of findings by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info + self.unknown


@dataclass
class PolicyResult:
    """Result of policy evaluation."""

    passed: bool
    exit_code: int
    violations: list[PolicyViolation] = field(default_factory=list)
    counts: SeverityCount = field(default_factory=SeverityCount)
    scan_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for JSON serialization."""
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "violations": [asdict(v) for v in self.violations],
            "counts": asdict(self.counts),
            "scan_errors": self.scan_errors,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def write_json(self, path: Path) -> None:
        """Write result to JSON file."""
        path.write_text(self.to_json())


def count_findings_by_severity(findings: Sequence[Finding]) -> SeverityCount:
    """Count findings grouped by severity level."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }

    for finding in findings:
        severity = finding.severity.value.lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["unknown"] += 1

    return SeverityCount(**counts)


def evaluate_policy(
    findings: Sequence[Finding],
    config: PolicyConfig,
    scan_errors: Sequence[str] | None = None,
) -> PolicyResult:
    """Evaluate findings against policy configuration.

    Args:
        findings: List of findings from scanners
        config: Policy configuration with thresholds
        scan_errors: Optional list of scan errors to include

    Returns:
        PolicyResult with pass/fail status and violations
    """
    # Validate config first - fail securely on invalid config
    config_errors = config.validate()
    if config_errors:
        logger.warning("Invalid policy config: %s", config_errors)
        return PolicyResult(
            passed=False,
            exit_code=EXIT_SCAN_ERROR,
            scan_errors=[f"Invalid policy configuration: {e}" for e in config_errors],
        )

    errors = list(scan_errors) if scan_errors else []
    counts = count_findings_by_severity(findings)
    violations: list[PolicyViolation] = []

    # Check severity thresholds
    severity_checks = [
        ("critical", config.fail_on_critical, config.max_critical, counts.critical),
        ("high", config.fail_on_high, config.max_high, counts.high),
        ("medium", config.fail_on_medium, config.max_medium, counts.medium),
        ("low", config.fail_on_low, config.max_low, counts.low),
        ("info", config.fail_on_info, config.max_info, counts.info),
    ]

    for severity, fail_on, max_count, actual_count in severity_checks:
        # Skip if not configured to fail on this severity
        if not fail_on:
            continue

        # -1 means no limit
        if max_count == -1:
            continue

        # Check threshold - use strict integer comparison (ASVS V15.3.5)
        if not isinstance(actual_count, int) or not isinstance(max_count, int):
            logger.warning(
                "Policy bypass attempt: non-integer comparison for %s (count=%r, max=%r)",
                severity,
                actual_count,
                max_count,
            )
            violations.append(
                PolicyViolation(
                    severity=severity,
                    count=actual_count if isinstance(actual_count, int) else 0,
                    threshold=max_count if isinstance(max_count, int) else 0,
                    message=f"Type error in {severity} threshold check",
                )
            )
            continue

        if actual_count > max_count:
            violations.append(
                PolicyViolation(
                    severity=severity,
                    count=actual_count,
                    threshold=max_count,
                    message=f"Found {actual_count} {severity} findings (max allowed: {max_count})",
                )
            )

    # Check total threshold
    if config.max_total >= 0 and counts.total > config.max_total:
        violations.append(
            PolicyViolation(
                severity="total",
                count=counts.total,
                threshold=config.max_total,
                message=f"Found {counts.total} total findings (max: {config.max_total})",
            )
        )

    # Determine final status
    if errors:
        # Scan errors = fail securely (ASVS V16.5.3)
        return PolicyResult(
            passed=False,
            exit_code=EXIT_SCAN_ERROR,
            violations=violations,
            counts=counts,
            scan_errors=errors,
        )

    if violations:
        return PolicyResult(
            passed=False,
            exit_code=EXIT_POLICY_VIOLATION,
            violations=violations,
            counts=counts,
            scan_errors=errors,
        )

    return PolicyResult(
        passed=True,
        exit_code=EXIT_SUCCESS,
        violations=[],
        counts=counts,
        scan_errors=[],
    )


def parse_fail_on(fail_on_str: str) -> PolicyConfig:
    """Parse --fail-on shorthand to PolicyConfig.

    Examples:
        "critical" -> fail on critical only
        "critical,high" -> fail on critical and high
        "medium" -> fail on critical, high, and medium
    """
    parts = [p.strip().lower() for p in fail_on_str.split(",") if p.strip()]

    if not parts:
        return PolicyConfig()

    # Determine cascade: if "medium" is specified, also fail on high and critical
    severities = {"critical", "high", "medium", "low", "info"}
    cascade_order = ["critical", "high", "medium", "low", "info"]

    fail_on = {
        "critical": False,
        "high": False,
        "medium": False,
        "low": False,
        "info": False,
    }

    for part in parts:
        if part not in severities:
            logger.warning("Unknown severity in --fail-on: %s", part)
            continue

        # Enable this severity and all higher ones
        idx = cascade_order.index(part)
        for sev in cascade_order[: idx + 1]:
            fail_on[sev] = True

    return PolicyConfig(
        fail_on_critical=fail_on["critical"],
        fail_on_high=fail_on["high"],
        fail_on_medium=fail_on["medium"],
        fail_on_low=fail_on["low"],
        fail_on_info=fail_on["info"],
        max_critical=0 if fail_on["critical"] else -1,
        max_high=0 if fail_on["high"] else -1,
        max_medium=0 if fail_on["medium"] else -1,
        max_low=0 if fail_on["low"] else -1,
        max_info=0 if fail_on["info"] else -1,
    )


def default_ci_policy() -> PolicyConfig:
    """Default policy for CI mode: fail on critical and high."""
    return PolicyConfig(
        fail_on_critical=True,
        fail_on_high=True,
        fail_on_medium=False,
        fail_on_low=False,
        fail_on_info=False,
        max_critical=0,
        max_high=0,
        max_medium=-1,
        max_low=-1,
        max_info=-1,
    )
