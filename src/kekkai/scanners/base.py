from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str) -> Severity:
        normalized = value.lower().strip()
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "warning": cls.LOW,
        }
        return mapping.get(normalized, cls.UNKNOWN)


@dataclass(frozen=True)
class Finding:
    scanner: str
    title: str
    severity: Severity
    description: str
    file_path: str | None = None
    line: int | None = None
    rule_id: str | None = None
    cwe: str | None = None
    cve: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def dedupe_hash(self) -> str:
        parts = [
            self.scanner,
            self.title,
            self.file_path or "",
            str(self.line or ""),
            self.rule_id or "",
            self.cve or "",
            self.package_name or "",
            self.package_version or "",
        ]
        content = "|".join(parts)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class ScanContext:
    repo_path: Path
    output_dir: Path
    run_id: str
    commit_sha: str | None = None
    timeout_seconds: int = 600


@dataclass(frozen=True)
class ScanResult:
    scanner: str
    success: bool
    findings: list[Finding]
    raw_output_path: Path | None = None
    error: str | None = None
    duration_ms: int = 0


@runtime_checkable
class Scanner(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def scan_type(self) -> str:
        """DefectDojo scan type for import."""
        ...

    def run(self, ctx: ScanContext) -> ScanResult: ...

    def parse(self, raw_output: str) -> list[Finding]: ...


def dedupe_findings(findings: Sequence[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result: list[Finding] = []
    for f in findings:
        h = _dedupe_key(f)
        if h not in seen:
            seen.add(h)
            result.append(f)
    return result


def _dedupe_key(finding: Finding) -> str:
    """Return a stable dedupe key, with Semgrep-specific noise collapsing.

    Semgrep may emit multiple overlapping findings on the same sink/source line
    from different rule families (e.g. flask/django/sqlalchemy variants). For
    those, dedupe by location + severity + message to reduce duplicate-style noise.
    """
    if finding.scanner == "semgrep" and finding.file_path and finding.line is not None:
        message = " ".join(finding.description.split())
        rule_tail = ""
        if finding.rule_id:
            tokens = finding.rule_id.split(".")
            rule_tail = tokens[-1] if tokens else finding.rule_id
        parts = [
            finding.scanner,
            finding.file_path,
            str(finding.line),
            finding.severity.value,
            rule_tail,
            message[:96],
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return finding.dedupe_hash()
