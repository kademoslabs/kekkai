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

GITLEAKS_IMAGE = "zricethezav/gitleaks"
GITLEAKS_DIGEST: str | None = None  # Allow Docker to pull architecture-appropriate image
SCAN_TYPE = "Gitleaks Scan"


class GitleaksScanner:
    def __init__(
        self,
        image: str = GITLEAKS_IMAGE,
        digest: str | None = GITLEAKS_DIGEST,
        timeout_seconds: int = 300,
        backend: BackendType | None = None,
    ) -> None:
        self._image = image
        self._digest = digest
        self._timeout = timeout_seconds
        self._backend = backend
        self._resolved_backend: BackendType | None = None

    @property
    def name(self) -> str:
        return "gitleaks"

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
            detect_tool("gitleaks")
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
        """Run Gitleaks in Docker container."""
        output_file = ctx.output_dir / "gitleaks-results.json"
        config = ContainerConfig(
            image=self._image,
            image_digest=self._digest,
            read_only=True,
            network_disabled=True,
            no_new_privileges=True,
        )

        command = [
            "detect",
            "--source",
            "/repo",
            "--no-git",  # Scan all files, not just git-tracked
            "--report-format",
            "json",
            "--report-path",
            "/output/gitleaks-results.json",
            "--exit-code",
            "0",
        ]

        result = run_container(
            config=config,
            repo_path=ctx.repo_path,
            output_path=ctx.output_dir,
            command=command,
            timeout_seconds=self._timeout,
        )

        return self._process_result(
            result.timed_out, result.exit_code, result.duration_ms, result.stderr, output_file
        )

    def _run_native(self, ctx: ScanContext) -> ScanResult:
        """Run Gitleaks natively."""
        try:
            tool_info = detect_tool("gitleaks")
        except (ToolNotFoundError, ToolVersionError) as e:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=str(e),
                duration_ms=0,
            )

        output_file = ctx.output_dir / "gitleaks-results.json"
        backend = NativeBackend()

        args = [
            "detect",
            "--source",
            str(ctx.repo_path),
            "--no-git",  # Scan all files, not just git-tracked
            "--report-format",
            "json",
            "--report-path",
            str(output_file),
            "--exit-code",
            "0",
        ]

        result = backend.execute(
            tool=tool_info.path,
            args=args,
            repo_path=ctx.repo_path,
            output_path=ctx.output_dir,
            timeout_seconds=self._timeout,
            network_required=False,
        )

        return self._process_result(
            result.timed_out, result.exit_code, result.duration_ms, result.stderr, output_file
        )

    def _process_result(
        self, timed_out: bool, exit_code: int, duration_ms: int, stderr: str, output_file: Path
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
            if exit_code == 0:
                return ScanResult(
                    scanner=self.name,
                    success=True,
                    findings=[],
                    duration_ms=duration_ms,
                )
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=stderr or "Scan failed",
                duration_ms=duration_ms,
            )

        try:
            content = output_file.read_text().strip()
            if not content:
                return ScanResult(
                    scanner=self.name,
                    success=True,
                    findings=[],
                    raw_output_path=output_file,
                    duration_ms=duration_ms,
                )
            findings = self.parse(content)
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

        if not isinstance(data, list):
            return findings

        for leak in data:
            findings.append(self._parse_leak(leak))

        return findings

    def _parse_leak(self, leak: dict[str, Any]) -> Finding:
        # Redact the actual secret from description
        match = leak.get("Match", "")
        redacted_match = match[:10] + "..." if len(match) > 10 else "[REDACTED]"

        return Finding(
            scanner=self.name,
            title=f"Secret detected: {leak.get('RuleID', 'unknown')}",
            severity=Severity.HIGH,  # Secrets are always high severity
            description=f"Potential secret found: {redacted_match}",
            file_path=leak.get("File"),
            line=leak.get("StartLine"),
            rule_id=leak.get("RuleID"),
            extra={
                "commit": leak.get("Commit", ""),
                "author": leak.get("Author", ""),
                "entropy": str(leak.get("Entropy", "")),
            },
        )
