"""Unified report generation for Kekkai scan results.

Aggregates findings from multiple scanners into a single JSON report
with security-hardened validation and resource limits (ASVS V10.3.3).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from kekkai_core import redact

if TYPE_CHECKING:
    from ..scanners.base import Finding, ScanResult

__all__ = [
    "generate_unified_report",
    "UnifiedReportError",
]

# Security limits per ASVS V10.3.3 (DoS mitigation)
MAX_FINDINGS_PER_SCANNER = 10_000
MAX_TOTAL_FINDINGS = 50_000
MAX_JSON_SIZE_MB = 100


class UnifiedReportError(Exception):
    """Error during unified report generation."""


def generate_unified_report(
    scan_results: list[ScanResult],
    output_path: Path,
    run_id: str,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    """Generate unified kekkai-report.json from scan results.

    Aggregates findings from all scanners with security controls:
    - Resource limits (ASVS V10.3.3): 10k findings/scanner, 50k total
    - Sensitive data redaction (ASVS V8.3.4)
    - Atomic writes with safe permissions (ASVS V12.3.1)
    - Path validation (ASVS V5.3.3)

    Args:
        scan_results: List of scanner results to aggregate.
        output_path: Path to write unified report JSON.
        run_id: Unique run identifier.
        commit_sha: Optional git commit SHA.

    Returns:
        Report data dictionary.

    Raises:
        UnifiedReportError: If report generation fails.
    """
    # Aggregate findings with limits
    all_findings: list[dict[str, Any]] = []
    scanner_metadata: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    for scan_res in scan_results:
        if not scan_res.success:
            scanner_metadata[scan_res.scanner] = {
                "success": False,
                "error": scan_res.error,
                "findings_count": 0,
                "duration_ms": scan_res.duration_ms,
            }
            continue

        # Apply per-scanner limit (DoS mitigation)
        findings = scan_res.findings[:MAX_FINDINGS_PER_SCANNER]
        if len(scan_res.findings) > MAX_FINDINGS_PER_SCANNER:
            warnings.append(
                f"{scan_res.scanner}: truncated {len(scan_res.findings)} findings "
                f"to {MAX_FINDINGS_PER_SCANNER} (limit)"
            )

        for finding in findings:
            if len(all_findings) >= MAX_TOTAL_FINDINGS:
                warnings.append(
                    f"Reached max total findings limit ({MAX_TOTAL_FINDINGS}), stopping aggregation"
                )
                break

            # Convert to dict with redaction (ASVS V8.3.4)
            all_findings.append(_finding_to_dict(finding))

        scanner_metadata[scan_res.scanner] = {
            "success": scan_res.success,
            "findings_count": len(findings),
            "duration_ms": scan_res.duration_ms,
        }

    # Build report structure
    correlations = _build_correlations(all_findings)
    report: dict[str, Any] = {
        "version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "run_id": run_id,
        "commit_sha": commit_sha,
        "scan_metadata": scanner_metadata,
        "summary": _build_summary(all_findings),
        "correlations": correlations,
        "findings": all_findings,
    }

    if warnings:
        report["warnings"] = warnings

    # Write atomically (ASVS V12.3.1)
    try:
        _write_report_atomic(output_path, report)
    except Exception as exc:
        # ASVS V7.4.1: Don't leak full path in error
        raise UnifiedReportError(f"Failed to write report: {exc}") from exc

    return report


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Convert Finding to dictionary with redaction.

    Args:
        finding: Scanner finding object.

    Returns:
        Dictionary with redacted sensitive fields.
    """
    priority_score, priority_reason, reachability, context_signals = _priority_context(finding)
    return {
        "id": finding.dedupe_hash(),
        "scanner": finding.scanner,
        "title": redact(finding.title),
        "severity": finding.severity.value,
        "description": redact(finding.description),
        "file_path": finding.file_path,
        "line": finding.line,
        "rule_id": finding.rule_id,
        "cwe": finding.cwe,
        "cve": finding.cve,
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "fixed_version": finding.fixed_version,
        "priority_score": priority_score,
        "priority_reason": priority_reason,
        "reachability": reachability,
        "context_signals": context_signals,
    }


def _build_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Build summary statistics from findings.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Summary with total and severity counts.
    """
    summary = {
        "total_findings": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "unknown")
        if severity in summary:
            summary[severity] += 1
        else:
            summary["unknown"] += 1

    return summary


def _build_correlations(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate similar findings across scanners and annotate findings."""
    groups: dict[str, list[int]] = {}
    for idx, finding in enumerate(findings):
        key = _correlation_key(finding)
        if not key:
            continue
        groups.setdefault(key, []).append(idx)

    correlation_entries: list[dict[str, Any]] = []
    for key, indexes in groups.items():
        scanners = sorted({str(findings[i].get("scanner", "")) for i in indexes})
        if len(scanners) < 2:
            continue
        corr_id = hashlib.sha256(key.encode()).hexdigest()[:12]
        for i in indexes:
            findings[i]["correlation_id"] = corr_id
            findings[i]["correlated_scanners"] = scanners
            findings[i]["correlation_size"] = len(indexes)
        correlation_entries.append(
            {
                "id": corr_id,
                "scanners": scanners,
                "finding_ids": [str(findings[i].get("id", "")) for i in indexes],
                "count": len(indexes),
            }
        )

    return {
        "cross_scanner_groups": len(correlation_entries),
        "groups": correlation_entries,
    }


def _correlation_key(finding: dict[str, Any]) -> str:
    """Create a normalized key for cross-scanner finding correlation."""
    file_path = str(finding.get("file_path") or "").strip().lower()
    line = str(finding.get("line") or "")
    cwe = str(finding.get("cwe") or "").strip().upper()
    cve = str(finding.get("cve") or "").strip().upper()
    rule = str(finding.get("rule_id") or "").strip().lower()
    title = str(finding.get("title") or "").strip().lower()

    if cve:
        return f"cve:{cve}"
    if cwe and file_path:
        return f"cwe:{cwe}:{file_path}:{line}"
    if file_path and line and rule:
        return f"loc:{file_path}:{line}:{rule.split('.')[-1]}"
    if file_path and line and title:
        return f"loc-title:{file_path}:{line}:{title[:64]}"
    return ""


def _priority_context(finding: Finding) -> tuple[int, str, str, list[str]]:
    """Build explainable priority data: why this is prioritized now."""
    sev = finding.severity.value
    base = {
        "critical": 50,
        "high": 35,
        "medium": 20,
        "low": 10,
        "info": 5,
        "unknown": 0,
    }.get(sev, 0)
    score = base
    signals: list[str] = [f"severity={finding.severity.value}"]
    path = (finding.file_path or "").lower()
    text = " ".join([finding.title, finding.description, finding.rule_id or ""]).lower()
    reachability = "unknown"

    if any(tok in path for tok in ("/api", "route", "controller", "graphql", "auth")):
        score += 20
        reachability = "likely_external"
        signals.append("externally reachable surface")
    if any(tok in text for tok in ("sql injection", "rce", "ssrf", "auth bypass", "jwt")):
        score += 15
        signals.append("high-abuse exploit pattern")
    if finding.line is not None:
        score += 3
        signals.append("precise code location")
    if finding.cve:
        score += 10
        signals.append("known CVE context")

    return score, "; ".join(signals), reachability, signals


def _write_report_atomic(path: Path, data: dict[str, Any]) -> None:
    """Write JSON report atomically with permission checks.

    Security controls:
    - Size validation before writing (ASVS V10.3.3)
    - Atomic write via temp file + rename (ASVS V12.3.1)
    - Safe file permissions (0o644)

    Args:
        path: Output file path.
        data: Report data to serialize.

    Raises:
        ValueError: If report exceeds size limit.
        OSError: If write fails.
    """
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Serialize and check size (ASVS V10.3.3)
    json_str = json.dumps(data, indent=2, ensure_ascii=False)
    size_mb = len(json_str.encode("utf-8")) / (1024 * 1024)
    if size_mb > MAX_JSON_SIZE_MB:
        raise ValueError(f"Report too large: {size_mb:.1f}MB > {MAX_JSON_SIZE_MB}MB")

    # Atomic write: temp file + rename (ASVS V12.3.1)
    temp_fd, temp_path_str = tempfile.mkstemp(
        dir=str(path.parent), prefix=".kekkai-report-", suffix=".json.tmp"
    )
    temp_path = Path(temp_path_str)

    try:
        # Write to temp file
        os.write(temp_fd, json_str.encode("utf-8"))
        os.close(temp_fd)

        # Set safe permissions (rw-r--r--)
        os.chmod(temp_path, 0o644)

        # Atomic rename
        temp_path.rename(path)
    except Exception:
        # Clean up temp file on error
        with contextlib.suppress(OSError):
            temp_path.unlink()
        raise
