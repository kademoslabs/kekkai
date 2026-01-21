from __future__ import annotations

import json
from typing import Any

from .base import Finding, ScanContext, ScanResult, Severity
from .container import ContainerConfig, run_container
from .url_policy import UrlPolicy, UrlPolicyError, validate_target_url

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy"
ZAP_DIGEST = "sha256:a1b2c3d4e5f6"  # Placeholder - update with real digest
SCAN_TYPE = "ZAP Scan"


class ZapScanner:
    """OWASP ZAP baseline scanner adapter.

    DAST scanner that requires explicit target URL and enforces URL policy.
    By default, blocks scanning of private/internal networks (SSRF protection).
    """

    def __init__(
        self,
        target_url: str | None = None,
        policy: UrlPolicy | None = None,
        image: str = ZAP_IMAGE,
        digest: str | None = ZAP_DIGEST,
        timeout_seconds: int = 900,
    ) -> None:
        self._target_url = target_url
        self._policy = policy or UrlPolicy()
        self._image = image
        self._digest = digest
        self._timeout = timeout_seconds
        self._validated_url: str | None = None

    @property
    def name(self) -> str:
        return "zap"

    @property
    def scan_type(self) -> str:
        return SCAN_TYPE

    def validate_target(self) -> str:
        """Validate and return the target URL.

        Raises:
            UrlPolicyError: If target URL is missing or invalid
        """
        if not self._target_url:
            raise UrlPolicyError("ZAP requires explicit --target-url")
        self._validated_url = validate_target_url(self._target_url, self._policy)
        return self._validated_url

    def run(self, ctx: ScanContext) -> ScanResult:
        # Validate target URL before running
        try:
            validated_url = self.validate_target()
        except UrlPolicyError as e:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=f"URL policy violation: {e}",
                duration_ms=0,
            )

        config = ContainerConfig(
            image=self._image,
            image_digest=self._digest,
            read_only=False,  # ZAP needs to write its own files
            network_disabled=False,  # ZAP needs network to scan target
            no_new_privileges=True,
            memory_limit="4g",  # ZAP can be memory-hungry
            cpu_limit="2",
        )

        # ZAP baseline scan command
        # Uses zap-baseline.py which is designed for CI/CD
        command = [
            "zap-baseline.py",
            "-t",
            validated_url,
            "-J",
            "/zap/wrk/zap-results.json",
            "-I",  # Don't fail on warnings
            "-d",  # Show debug messages
        ]

        result = run_container(
            config=config,
            repo_path=ctx.repo_path,  # Not really used for ZAP
            output_path=ctx.output_dir,
            command=command,
            timeout_seconds=self._timeout,
            workdir="/zap/wrk",
            output_mount="/zap/wrk",
            skip_repo_mount=True,  # ZAP doesn't need repo
            user=None,  # ZAP container has its own user setup
        )

        if result.timed_out:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error="ZAP scan timed out",
                duration_ms=result.duration_ms,
            )

        # Check for output file (ZAP may write to different locations)
        zap_output = ctx.output_dir / "zap-results.json"
        if not zap_output.exists():
            # Try alternate location
            alt_output = ctx.output_dir / "wrk" / "zap-results.json"
            if alt_output.exists():
                zap_output = alt_output

        if not zap_output.exists():
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                error=result.stderr or "No output file produced",
                duration_ms=result.duration_ms,
            )

        try:
            findings = self.parse(zap_output.read_text())
        except (json.JSONDecodeError, KeyError) as exc:
            return ScanResult(
                scanner=self.name,
                success=False,
                findings=[],
                raw_output_path=zap_output,
                error=f"Parse error: {exc}",
                duration_ms=result.duration_ms,
            )

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=findings,
            raw_output_path=zap_output,
            duration_ms=result.duration_ms,
        )

    def parse(self, raw_output: str) -> list[Finding]:
        """Parse ZAP JSON output to Finding objects."""
        data = json.loads(raw_output)
        findings: list[Finding] = []

        # ZAP baseline outputs alerts in "site" -> "alerts" structure
        for site in data.get("site", []):
            site_name = site.get("@name", "")
            for alert in site.get("alerts", []):
                findings.append(self._parse_alert(alert, site_name))

        return findings

    def _parse_alert(self, alert: dict[str, Any], site: str) -> Finding:
        """Parse a single ZAP alert to a Finding."""
        # Map ZAP risk levels to our severity
        risk = alert.get("riskcode", "0")
        severity = self._map_risk_to_severity(risk)

        # Get CWE if available
        cwe = None
        if cweid := alert.get("cweid"):
            cwe = f"CWE-{cweid}"

        # Build description from multiple fields
        desc_parts = [alert.get("desc", "")]
        if solution := alert.get("solution"):
            desc_parts.append(f"Solution: {solution}")
        if reference := alert.get("reference"):
            desc_parts.append(f"Reference: {reference}")

        # Get affected instances
        instances = alert.get("instances", [])
        affected_url = instances[0].get("uri", site) if instances else site

        return Finding(
            scanner=self.name,
            title=alert.get("name", "ZAP Alert"),
            severity=severity,
            description="\n\n".join(desc_parts),
            file_path=affected_url,
            rule_id=alert.get("pluginid"),
            cwe=cwe,
            extra={
                "confidence": alert.get("confidence", ""),
                "count": str(alert.get("count", len(instances))),
                "site": site,
            },
        )

    def _map_risk_to_severity(self, risk: str | int) -> Severity:
        """Map ZAP risk code to Severity."""
        risk_int = int(risk) if isinstance(risk, str) else risk
        mapping = {
            3: Severity.HIGH,
            2: Severity.MEDIUM,
            1: Severity.LOW,
            0: Severity.INFO,
        }
        return mapping.get(risk_int, Severity.UNKNOWN)


def create_zap_scanner(
    target_url: str | None = None,
    allow_private_ips: bool = False,
    allowed_domains: list[str] | None = None,
    timeout_seconds: int = 900,
) -> ZapScanner:
    """Factory function to create a ZAP scanner with policy.

    Args:
        target_url: The URL to scan (required)
        allow_private_ips: Whether to allow scanning private IPs (default: False)
        allowed_domains: Optional allowlist of domains
        timeout_seconds: Scan timeout

    Returns:
        Configured ZapScanner instance
    """
    policy = UrlPolicy(
        allow_private_ips=allow_private_ips,
        allowed_domains=frozenset(allowed_domains) if allowed_domains else frozenset(),
    )
    return ZapScanner(
        target_url=target_url,
        policy=policy,
        timeout_seconds=timeout_seconds,
    )
