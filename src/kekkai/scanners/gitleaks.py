from __future__ import annotations

import json
from typing import Any

from .base import Finding, ScanContext, ScanResult, Severity
from .container import ContainerConfig, run_container

GITLEAKS_IMAGE = "zricethezav/gitleaks"
GITLEAKS_DIGEST = "sha256:b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
SCAN_TYPE = "Gitleaks Scan"


class GitleaksScanner:
    def __init__(
        self,
        image: str = GITLEAKS_IMAGE,
        digest: str | None = GITLEAKS_DIGEST,
        timeout_seconds: int = 300,
    ) -> None:
        self._image = image
        self._digest = digest
        self._timeout = timeout_seconds

    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def scan_type(self) -> str:
        return SCAN_TYPE

    def run(self, ctx: ScanContext) -> ScanResult:
        output_file = ctx.output_dir / "gitleaks-results.json"
        config = ContainerConfig(
            image=self._image,
            image_digest=self._digest,
            read_only=True,
            network_disabled=True,  # Gitleaks doesn't need network
            no_new_privileges=True,
        )

        command = [
            "detect",
            "--source",
            "/repo",
            "--report-format",
            "json",
            "--report-path",
            "/output/gitleaks-results.json",
            "--exit-code",
            "0",  # Don't fail on findings, we handle them
        ]

        result = run_container(
            config=config,
            repo_path=ctx.repo_path,
            output_path=ctx.output_dir,
            command=command,
            timeout_seconds=self._timeout,
        )

        if result.timed_out:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error="Scan timed out",
                duration_ms=result.duration_ms,
            )

        if not output_file.exists():
            # Gitleaks may not create file if no findings - that's OK
            if result.exit_code == 0:
                return ScanResult(
                    scanner=self.name,
                    success=True,
                    findings=[],
                    duration_ms=result.duration_ms,
                )
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=result.stderr or "Scan failed",
                duration_ms=result.duration_ms,
            )

        try:
            content = output_file.read_text().strip()
            if not content:
                return ScanResult(
                    scanner=self.name,
                    success=True,
                    findings=[],
                    raw_output_path=output_file,
                    duration_ms=result.duration_ms,
                )
            findings = self.parse(content)
        except (json.JSONDecodeError, KeyError) as exc:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                raw_output_path=output_file,
                error=f"Parse error: {exc}",
                duration_ms=result.duration_ms,
            )

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=findings,
            raw_output_path=output_file,
            duration_ms=result.duration_ms,
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
