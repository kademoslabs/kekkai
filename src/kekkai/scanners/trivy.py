from __future__ import annotations

import json
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

TRIVY_IMAGE = "aquasec/trivy"
TRIVY_DIGEST: str | None = None  # Allow Docker to pull architecture-appropriate image
SCAN_TYPE = "Trivy Scan"


class TrivyScanner:
    def __init__(
        self,
        image: str = TRIVY_IMAGE,
        digest: str | None = TRIVY_DIGEST,
        timeout_seconds: int = 600,
        backend: BackendType | None = None,
    ) -> None:
        self._image = image
        self._digest = digest
        self._timeout = timeout_seconds
        self._backend = backend
        self._resolved_backend: BackendType | None = None

    @property
    def name(self) -> str:
        return "trivy"

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
            detect_tool("trivy")
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
        """Run Trivy in Docker container."""
        output_file = ctx.output_dir / "trivy-results.json"
        config = ContainerConfig(
            image=self._image,
            image_digest=self._digest,
            read_only=True,
            network_disabled=False,
            no_new_privileges=True,
        )

        command = [
            "fs",
            "--format",
            "json",
            "--output",
            "/output/trivy-results.json",
            "--severity",
            "CRITICAL,HIGH,MEDIUM,LOW",
            "--scanners",
            "vuln,secret,misconfig",
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
        """Run Trivy natively."""
        try:
            tool_info = detect_tool("trivy")
        except (ToolNotFoundError, ToolVersionError) as e:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=str(e),
                duration_ms=0,
            )

        output_file = ctx.output_dir / "trivy-results.json"
        backend = NativeBackend()

        args = [
            "fs",
            "--format",
            "json",
            "--output",
            str(output_file),
            "--severity",
            "CRITICAL,HIGH,MEDIUM,LOW",
            "--scanners",
            "vuln,secret,misconfig",
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
        self, timed_out: bool, duration_ms: int, stderr: str, output_file: Any
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

        results = data.get("Results", [])
        for target in results:
            target_name = target.get("Target", "")
            target_type = target.get("Type", "")

            for vuln in target.get("Vulnerabilities", []):
                findings.append(self._parse_vulnerability(vuln, target_name, target_type))

            for secret in target.get("Secrets", []):
                findings.append(self._parse_secret(secret, target_name))

            for misconfig in target.get("Misconfigurations", []):
                findings.append(self._parse_misconfig(misconfig, target_name))

        return findings

    def _parse_vulnerability(self, vuln: dict[str, Any], target: str, target_type: str) -> Finding:
        return Finding(
            scanner=self.name,
            title=vuln.get("Title") or vuln.get("VulnerabilityID", "Unknown"),
            severity=Severity.from_string(vuln.get("Severity", "unknown")),
            description=vuln.get("Description", ""),
            file_path=target,
            cve=vuln.get("VulnerabilityID"),
            package_name=vuln.get("PkgName"),
            package_version=vuln.get("InstalledVersion"),
            fixed_version=vuln.get("FixedVersion"),
            extra={"target_type": target_type},
        )

    def _parse_secret(self, secret: dict[str, Any], target: str) -> Finding:
        return Finding(
            scanner=self.name,
            title=secret.get("Title", "Secret detected"),
            severity=Severity.from_string(secret.get("Severity", "high")),
            description=secret.get("Match", ""),
            file_path=target,
            line=secret.get("StartLine"),
            rule_id=secret.get("RuleID"),
        )

    def _parse_misconfig(self, misconfig: dict[str, Any], target: str) -> Finding:
        return Finding(
            scanner=self.name,
            title=misconfig.get("Title", "Misconfiguration"),
            severity=Severity.from_string(misconfig.get("Severity", "medium")),
            description=misconfig.get("Description", ""),
            file_path=target,
            rule_id=misconfig.get("ID"),
            extra={"resolution": misconfig.get("Resolution", "")},
        )
