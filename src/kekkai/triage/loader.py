"""Triage findings loader with scanner format detection.

Supports loading findings from:
- Native triage JSON (list or {"findings": [...]})
- Raw scanner outputs (Semgrep/Trivy/Gitleaks)
- Run directories (aggregates all *-results.json)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..scanners.base import Finding
    from ..scanners.base import Severity as ScannerSeverity

from .models import FindingEntry
from .models import Severity as TriageSeverity

__all__ = [
    "load_findings_from_path",
]

# Size limits for DoS mitigation (ASVS V10.3.3)
MAX_FILE_SIZE_MB = 200
WARN_FILE_SIZE_MB = 50


def load_findings_from_path(
    path: Path,
) -> tuple[list[FindingEntry], list[str]]:
    """Load findings from file or directory.

    Supports:
    - Native triage JSON (list or {"findings": [...]})
    - Raw scanner outputs (Semgrep/Trivy/Gitleaks)
    - Run directories (aggregates all *-results.json)

    Args:
        path: Path to findings file or run directory.

    Returns:
        Tuple of (findings, error_messages).
        Error messages include filename only (no full paths) per ASVS V7.4.1.
    """
    errors: list[str] = []

    # Determine input type
    if path.is_dir():
        # Prefer canonical scan outputs first
        files = sorted(path.glob("*-results.json"))
        if not files:
            # Fallback to all JSON (excluding metadata files)
            files = sorted(
                [p for p in path.glob("*.json") if p.name not in ("run.json", "policy-result.json")]
            )
    else:
        files = [path]

    findings: list[FindingEntry] = []
    for file in files:
        # Check if file exists first
        if not file.exists():
            errors.append(f"{file.name}: OSError")
            continue

        # Size check (DoS mitigation per ASVS V10.3.3)
        size_mb = file.stat().st_size / (1024 * 1024)
        if size_mb > MAX_FILE_SIZE_MB:
            msg = f"{file.name}: file too large ({size_mb:.1f} MB, max {MAX_FILE_SIZE_MB} MB)"
            errors.append(msg)
            continue

        try:
            content = file.read_text(encoding="utf-8")
            if not content.strip():
                continue
            data = json.loads(content)
        except (OSError, json.JSONDecodeError) as exc:
            # ASVS V7.4.1: Don't leak full path, only filename
            errors.append(f"{file.name}: {type(exc).__name__}")
            continue

        # Detect format and parse
        try:
            batch = _parse_findings(data, file.stem)
            findings.extend(batch)
        except Exception as exc:
            errors.append(f"{file.name}: unsupported format ({str(exc)[:50]})")

    # Deduplicate by stable key
    seen: set[str] = set()
    deduped: list[FindingEntry] = []
    for f in findings:
        key = f"{f.scanner}:{f.rule_id}:{f.file_path}:{f.line}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped, errors


def _parse_findings(data: Any, stem: str) -> list[FindingEntry]:
    """Parse findings from JSON data.

    Args:
        data: Parsed JSON data.
        stem: File stem (used to detect scanner type).

    Returns:
        List of FindingEntry objects.

    Raises:
        ValueError: If format is unknown or scanner not found.
    """
    # Try native triage format first (ASVS V5.1.2: strongly typed validation)
    if isinstance(data, list) and data and isinstance(data[0], dict) and "scanner" in data[0]:
        return [FindingEntry.from_dict(item) for item in data]

    if isinstance(data, dict) and "findings" in data:
        findings_data = data["findings"]
        if isinstance(findings_data, list):
            return [FindingEntry.from_dict(item) for item in findings_data]

    # Try scanner-specific format
    scanner_name = stem.replace("-results", "")

    # Lazy import to avoid circular dependency
    from ..cli import _create_scanner

    scanner = _create_scanner(scanner_name)
    if not scanner:
        raise ValueError(f"Unknown scanner: {scanner_name}")

    # Use canonical scanner parser (reuses validated logic)
    raw_json = json.dumps(data)
    canonical_findings = scanner.parse(raw_json)

    # Convert to triage format
    return [_finding_to_entry(f) for f in canonical_findings]


def _finding_to_entry(f: Finding) -> FindingEntry:
    """Convert scanner Finding to triage FindingEntry.

    Args:
        f: Scanner Finding object.

    Returns:
        Triage FindingEntry object.
    """
    return FindingEntry(
        id=f.dedupe_hash(),
        title=f.title,
        severity=_map_severity(f.severity),
        scanner=f.scanner,
        file_path=f.file_path or "",
        line=f.line,
        description=f.description,
        rule_id=f.rule_id or "",
    )


def _map_severity(s: ScannerSeverity) -> TriageSeverity:
    """Map scanner Severity to triage Severity.

    Both use the same enum values, just different type namespaces.

    Args:
        s: Scanner severity enum.

    Returns:
        Triage severity enum.
    """
    try:
        return TriageSeverity(s.value)
    except ValueError:
        # Fallback to INFO for unknown severities
        return TriageSeverity.INFO
