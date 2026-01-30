from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .backends import (
    BackendType,
    NativeBackend,
    ToolNotFoundError,
    ToolVersionError,
    detect_tool,
    docker_available,
)
from .base import Finding, ScanContext, ScanResult, Severity
from .container import ContainerConfig, run_container

SEMGREP_IMAGE = "returntocorp/semgrep"
SEMGREP_DIGEST: str | None = None  # Allow Docker to pull architecture-appropriate image
SCAN_TYPE = "Semgrep JSON Report"


class SemgrepScanner:
    def __init__(
        self,
        image: str = SEMGREP_IMAGE,
        digest: str | None = SEMGREP_DIGEST,
        timeout_seconds: int = 600,
        config: str = "auto",
        backend: BackendType | None = None,
    ) -> None:
        self._image = image
        self._digest = digest
        self._timeout = timeout_seconds
        self._config = config
        self._backend = backend
        self._resolved_backend: BackendType | None = None

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def scan_type(self) -> str:
        return SCAN_TYPE

    @property
    def backend_used(self) -> BackendType | None:
        """Return the backend used for the last scan."""
        return self._resolved_backend

    def _select_backend(self) -> BackendType:
        """Select backend: explicit choice, or auto-detect (Docker preferred)."""
        if self._backend is not None:
            return self._backend

        available, _ = docker_available()
        if available:
            return BackendType.DOCKER

        try:
            detect_tool("semgrep")
            return BackendType.NATIVE
        except (ToolNotFoundError, ToolVersionError):
            return BackendType.DOCKER

    def run(self, ctx: ScanContext) -> ScanResult:
        backend = self._select_backend()
        self._resolved_backend = backend

        if backend == BackendType.NATIVE:
            return self._run_native(ctx)
        return self._run_docker(ctx)

    def _run_docker(self, ctx: ScanContext) -> ScanResult:
        """Run Semgrep in Docker container."""
        output_file = ctx.output_dir / "semgrep-results.json"
        config = ContainerConfig(
            image=self._image,
            image_digest=self._digest,
            read_only=True,
            network_disabled=False,
            no_new_privileges=True,
        )

        command = [
            "semgrep",
            "scan",
            "--config",
            self._config,
            "--json",
            "--output",
            "/output/semgrep-results.json",
            "/repo",
        ]

        result = run_container(
            config=config,
            repo_path=ctx.repo_path,
            output_path=ctx.output_dir,
            command=command,
            timeout_seconds=self._timeout,
        )

        return self._process_result(
            result.timed_out, result.duration_ms, result.stderr, output_file
        )

    def _run_native(self, ctx: ScanContext) -> ScanResult:
        """Run Semgrep natively."""
        try:
            tool_info = detect_tool("semgrep")
        except (ToolNotFoundError, ToolVersionError) as e:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=str(e),
                duration_ms=0,
            )

        output_file = ctx.output_dir / "semgrep-results.json"
        backend = NativeBackend()

        args = [
            "scan",
            "--config",
            self._config,
            "--json",
            "--output",
            str(output_file),
            str(ctx.repo_path),
        ]

        result = backend.execute(
            tool=tool_info.path,
            args=args,
            repo_path=ctx.repo_path,
            output_path=ctx.output_dir,
            timeout_seconds=self._timeout,
            network_required=True,
        )

        return self._process_result(
            result.timed_out, result.duration_ms, result.stderr, output_file
        )

    def _process_result(
        self, timed_out: bool, duration_ms: int, stderr: str, output_file: Path
    ) -> ScanResult:
        """Process scan result from either backend."""
        if timed_out:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error="Scan timed out",
                duration_ms=duration_ms,
            )

        if not output_file.exists():
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=stderr or "No output file produced",
                duration_ms=duration_ms,
            )

        try:
            findings = self.parse(output_file.read_text())
        except (json.JSONDecodeError, KeyError) as exc:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                raw_output_path=output_file,
                error=f"Parse error: {exc}",
                duration_ms=duration_ms,
            )

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=findings,
            raw_output_path=output_file,
            duration_ms=duration_ms,
        )

    def parse(self, raw_output: str) -> list[Finding]:
        data = json.loads(raw_output)
        findings: list[Finding] = []

        for result in data.get("results", []):
            findings.append(self._parse_result(result))

        return findings

    def _parse_result(self, result: dict[str, Any]) -> Finding:
        extra_data = result.get("extra", {})
        metadata = extra_data.get("metadata", {})

        severity_str = extra_data.get("severity", "warning")
        if severity_str == "ERROR":
            severity = Severity.HIGH
        elif severity_str == "WARNING":
            severity = Severity.MEDIUM
        else:
            severity = Severity.from_string(severity_str)

        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0] if cwe_list else None

        return Finding(
            scanner=self.name,
            title=metadata.get("message") or result.get("check_id", "Semgrep finding"),
            severity=severity,
            description=extra_data.get("message", ""),
            file_path=result.get("path"),
            line=result.get("start", {}).get("line"),
            rule_id=result.get("check_id"),
            cwe=cwe,
            extra={
                "fingerprint": extra_data.get("fingerprint", ""),
                "fix": extra_data.get("fix", ""),
            },
        )
