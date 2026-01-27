"""Docker image security scanning with Trivy."""

import json
import subprocess
from pathlib import Path
from typing import Any, Literal, cast

SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


class TrivyScanError(Exception):
    """Raised when Trivy scan fails."""


def run_trivy_scan(
    image: str,
    output_format: Literal["json", "sarif", "table"] = "json",
    severity: list[SeverityLevel] | None = None,
    output_file: Path | None = None,
) -> dict[str, Any]:
    """
    Run Trivy security scan on Docker image.

    Args:
        image: Docker image to scan (e.g., 'kademoslabs/kekkai:latest')
        output_format: Output format (json, sarif, table)
        severity: List of severity levels to include (default: all)
        output_file: Path to write scan results (optional)

    Returns:
        Scan results as dictionary

    Raises:
        TrivyScanError: If scan fails
    """
    cmd = ["trivy", "image", "--format", output_format]

    if severity:
        cmd.extend(["--severity", ",".join(severity)])

    if output_file:
        cmd.extend(["--output", str(output_file)])

    cmd.append(image)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )

        if output_format == "json" or output_format == "sarif":
            return json.loads(result.stdout) if result.stdout else {}
        else:
            # For table format, return raw output
            return {"output": result.stdout}

    except subprocess.CalledProcessError as e:
        raise TrivyScanError(f"Trivy scan failed: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise TrivyScanError("Trivy scan timed out after 300s") from e
    except json.JSONDecodeError as e:
        raise TrivyScanError(f"Failed to parse Trivy output: {e}") from e
    except Exception as e:
        raise TrivyScanError(f"Trivy scan failed: {e}") from e


def filter_vulnerabilities(
    scan_results: dict[str, Any],
    severity_threshold: SeverityLevel = "HIGH",
) -> list[dict[str, Any]]:
    """
    Filter vulnerabilities by severity threshold.

    Args:
        scan_results: Trivy scan results (JSON format)
        severity_threshold: Minimum severity to include

    Returns:
        List of vulnerabilities meeting threshold
    """
    severity_order: dict[SeverityLevel, int] = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }

    threshold_level = severity_order.get(severity_threshold, 0)
    filtered: list[dict[str, Any]] = []

    # Trivy JSON format has "Results" array
    results = scan_results.get("Results", [])

    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "UNKNOWN")
            severity_value = severity_order.get(severity, 0)
            if severity_value >= threshold_level:
                filtered.append(vuln)

    return filtered


def count_vulnerabilities_by_severity(
    scan_results: dict[str, Any],
) -> dict[SeverityLevel, int]:
    """
    Count vulnerabilities by severity level.

    Args:
        scan_results: Trivy scan results (JSON format)

    Returns:
        Dictionary mapping severity to count
    """
    counts: dict[SeverityLevel, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    results = scan_results.get("Results", [])

    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "UNKNOWN")
            if severity in counts:
                severity_key = cast(SeverityLevel, severity)
                counts[severity_key] += 1

    return counts


def has_critical_vulnerabilities(
    scan_results: dict[str, Any],
    severity_threshold: SeverityLevel = "HIGH",
) -> bool:
    """
    Check if scan results contain vulnerabilities at or above threshold.

    Args:
        scan_results: Trivy scan results (JSON format)
        severity_threshold: Minimum severity to check

    Returns:
        True if vulnerabilities found at or above threshold
    """
    filtered = filter_vulnerabilities(scan_results, severity_threshold)
    return len(filtered) > 0
