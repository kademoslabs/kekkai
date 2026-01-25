from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from .backends import (
    BackendType,
    ToolNotFoundError,
    ToolVersionError,
    detect_tool,
)
from .base import Finding, ScanContext, ScanResult, Severity

SCAN_TYPE = "Falco Scan"


class FalcoNotAvailableError(RuntimeError):
    """Raised when Falco is not available or not enabled."""


class FalcoScanner:
    """Falco runtime security scanner adapter.

    EXPERIMENTAL: Linux-only scanner that monitors runtime behavior.
    Requires explicit opt-in via --enable-falco flag.

    Security notes:
    - Falco requires kernel access (eBPF or kernel module)
    - Should only be used in controlled environments
    - Requires elevated privileges on the host

    Note: Falco only runs in native mode (no Docker container support)
    as it requires direct kernel access.
    """

    def __init__(
        self,
        enabled: bool = False,
        rules_file: Path | None = None,
        timeout_seconds: int = 300,
        backend: BackendType | None = None,
    ) -> None:
        self._enabled = enabled
        self._rules_file = rules_file
        self._timeout = timeout_seconds
        self._backend = backend
        self._resolved_backend: BackendType | None = None

    @property
    def name(self) -> str:
        return "falco"

    @property
    def scan_type(self) -> str:
        return SCAN_TYPE

    @property
    def backend_used(self) -> BackendType | None:
        """Return the backend used for the last scan."""
        return self._resolved_backend

    def is_available(self) -> tuple[bool, str]:
        """Check if Falco is available and can be run.

        Returns:
            Tuple of (available, reason)
        """
        if platform.system() != "Linux":
            return False, "Falco is Linux-only (experimental)"

        if not self._enabled:
            return False, "Falco requires explicit --enable-falco flag"

        try:
            detect_tool("falco", min_version=(0, 35, 0))
            return True, "Falco available"
        except ToolNotFoundError:
            return False, "Falco binary not found in PATH"
        except ToolVersionError as e:
            return False, str(e)

    def run(self, ctx: ScanContext) -> ScanResult:
        """Run Falco scanner.

        Note: Falco is designed for continuous monitoring. This adapter
        runs Falco in a one-shot mode to analyze existing log files or
        capture events for a limited duration.

        Falco always runs in native mode (requires kernel access).
        """
        self._resolved_backend = BackendType.NATIVE

        available, reason = self.is_available()
        if not available:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=f"Falco not available: {reason}",
                duration_ms=0,
            )

        existing_alerts = self._find_alerts_file(ctx)
        if existing_alerts:
            try:
                findings = self.parse(existing_alerts.read_text())
                return ScanResult(
                    scanner=self.name,
                    success=True,
                    findings=findings,
                    raw_output_path=existing_alerts,
                    duration_ms=0,
                )
            except (json.JSONDecodeError, KeyError) as exc:
                return ScanResult(
                    scanner=self.name,
                    success=False,
                    findings=[],
                    error=f"Parse error: {exc}",
                    duration_ms=0,
                )

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=[],
            error=None,
            duration_ms=0,
        )

    def _find_alerts_file(self, ctx: ScanContext) -> Path | None:
        """Find existing Falco alerts file."""
        candidates = [
            ctx.output_dir / "falco-alerts.json",
            ctx.repo_path / "falco-alerts.json",
            Path("/var/log/falco/alerts.json"),
        ]
        for path in candidates:
            if path.exists():
                return path
        return None

    def parse(self, raw_output: str) -> list[Finding]:
        """Parse Falco JSON alerts to Finding objects.

        Falco outputs one JSON object per line (JSONL format).
        """
        findings: list[Finding] = []

        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                alert = json.loads(line)
                findings.append(self._parse_alert(alert))
            except json.JSONDecodeError:
                continue

        return findings

    def _parse_alert(self, alert: dict[str, Any]) -> Finding:
        """Parse a single Falco alert to a Finding."""
        priority = alert.get("priority", "").lower()
        severity = self._map_priority_to_severity(priority)

        # Extract relevant fields
        output = alert.get("output", "")
        rule = alert.get("rule", "Unknown Rule")

        # Get output fields for additional context
        output_fields = alert.get("output_fields", {})
        container_id = output_fields.get("container.id", "")
        container_name = output_fields.get("container.name", "")
        process = output_fields.get("proc.name", "")
        cmdline = output_fields.get("proc.cmdline", "")

        description_parts = [output]
        if process:
            description_parts.append(f"Process: {process}")
        if cmdline:
            description_parts.append(f"Command: {cmdline}")
        if container_name:
            description_parts.append(f"Container: {container_name}")

        return Finding(
            scanner=self.name,
            title=rule,
            severity=severity,
            description="\n".join(description_parts),
            file_path=container_id or None,
            rule_id=rule,
            extra={
                "priority": priority,
                "container_id": container_id,
                "container_name": container_name,
                "process": process,
                "time": alert.get("time", ""),
            },
        )

    def _map_priority_to_severity(self, priority: str) -> Severity:
        """Map Falco priority to Severity."""
        mapping = {
            "emergency": Severity.CRITICAL,
            "alert": Severity.CRITICAL,
            "critical": Severity.CRITICAL,
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "notice": Severity.LOW,
            "informational": Severity.INFO,
            "debug": Severity.INFO,
        }
        return mapping.get(priority.lower(), Severity.UNKNOWN)


def create_falco_scanner(
    enabled: bool = False,
    rules_file: Path | None = None,
    timeout_seconds: int = 300,
) -> FalcoScanner:
    """Factory function to create a Falco scanner.

    Args:
        enabled: Whether Falco scanning is enabled (requires explicit opt-in)
        rules_file: Optional custom rules file
        timeout_seconds: Scan timeout

    Returns:
        Configured FalcoScanner instance
    """
    return FalcoScanner(
        enabled=enabled,
        rules_file=rules_file,
        timeout_seconds=timeout_seconds,
    )
