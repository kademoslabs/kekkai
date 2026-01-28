from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from . import dojo, manifest
from .config import ConfigOverrides, DojoSettings, PolicySettings, load_config
from .dojo_import import DojoConfig, import_results_to_dojo
from .output import (
    VERSION,
    ScanSummaryRow,
    console,
    print_dashboard,
    print_scan_summary,
    sanitize_error,
    sanitize_for_terminal,
)
from .paths import app_base_dir, config_path, ensure_dir, is_within_base, safe_join
from .policy import (
    EXIT_SCAN_ERROR,
    PolicyConfig,
    PolicyResult,
    default_ci_policy,
    evaluate_policy,
    parse_fail_on,
)
from .runner import StepResult, run_step
from .scanners import (
    OPTIONAL_SCANNERS,
    SCANNER_REGISTRY,
    Finding,
    ScanContext,
    Scanner,
    ScanResult,
    create_falco_scanner,
    create_zap_scanner,
    dedupe_findings,
)

RUN_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args:
        return _handle_no_args()

    parser = argparse.ArgumentParser(prog="kekkai")
    parser.add_argument("--version", action="version", version=f"kekkai {VERSION}")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="initialize config and directories")
    init_parser.add_argument("--config", type=str, help="Path to config file")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing config")

    scan_parser = subparsers.add_parser("scan", help="run a scan pipeline")
    scan_parser.add_argument("--config", type=str, help="Path to config file")
    scan_parser.add_argument("--repo", type=str, help="Path to repository")
    scan_parser.add_argument("--run-dir", type=str, help="Override run output directory")
    scan_parser.add_argument("--run-id", type=str, help="Override run id")
    scan_parser.add_argument(
        "--scanners",
        type=str,
        help="Comma-separated list of scanners (trivy,semgrep,gitleaks)",
    )
    scan_parser.add_argument(
        "--import-dojo",
        action="store_true",
        help="Import results to local DefectDojo",
    )
    scan_parser.add_argument("--dojo-url", type=str, help="DefectDojo base URL")
    scan_parser.add_argument("--dojo-api-key", type=str, help="DefectDojo API key")

    # ZAP DAST scanner options
    scan_parser.add_argument(
        "--target-url",
        type=str,
        help="Target URL for ZAP DAST scanning (required if zap in scanners)",
    )
    scan_parser.add_argument(
        "--allow-private-ips",
        action="store_true",
        help="Allow ZAP to scan private/internal IPs (DANGEROUS)",
    )

    # Falco runtime security options
    scan_parser.add_argument(
        "--enable-falco",
        action="store_true",
        help="Enable Falco runtime security (Linux-only, experimental)",
    )

    # CI mode and policy enforcement options
    scan_parser.add_argument(
        "--ci",
        action="store_true",
        help="Enable CI mode: fail on policy violations (default: critical/high)",
    )
    scan_parser.add_argument(
        "--fail-on",
        type=str,
        help="Severity levels to fail on (e.g., 'critical,high' or 'medium')",
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        help="Path for policy result JSON output",
    )

    # GitHub PR comment options
    scan_parser.add_argument(
        "--pr-comment",
        action="store_true",
        help="Post findings as GitHub PR review comments",
    )
    scan_parser.add_argument(
        "--github-token",
        type=str,
        help="GitHub token (or set GITHUB_TOKEN env var)",
    )
    scan_parser.add_argument(
        "--pr-number",
        type=int,
        help="PR number to comment on (auto-detected in GitHub Actions)",
    )
    scan_parser.add_argument(
        "--github-repo",
        type=str,
        help="GitHub repository (owner/repo, auto-detected in GitHub Actions)",
    )
    scan_parser.add_argument(
        "--max-comments",
        type=int,
        default=50,
        help="Maximum PR comments to post (default: 50)",
    )
    scan_parser.add_argument(
        "--comment-severity",
        type=str,
        default="medium",
        help="Minimum severity for PR comments (default: medium)",
    )

    dojo_parser = subparsers.add_parser("dojo", help="manage local DefectDojo stack")
    dojo_subparsers = dojo_parser.add_subparsers(dest="dojo_command")

    dojo_up = dojo_subparsers.add_parser("up", help="start the local DefectDojo stack")
    dojo_up.add_argument("--compose-dir", type=str, help="Directory for compose files")
    dojo_up.add_argument("--project-name", type=str, help="Docker Compose project name")
    dojo_up.add_argument("--port", type=int, help="HTTP port for the UI")
    dojo_up.add_argument("--tls-port", type=int, help="HTTPS port for the UI")
    dojo_up.add_argument("--wait", action="store_true", help="Wait for UI readiness")
    dojo_up.add_argument("--open", action="store_true", help="Open the UI in a browser")

    dojo_down = dojo_subparsers.add_parser("down", help="stop the local DefectDojo stack")
    dojo_down.add_argument("--compose-dir", type=str, help="Directory for compose files")
    dojo_down.add_argument("--project-name", type=str, help="Docker Compose project name")

    dojo_status = dojo_subparsers.add_parser("status", help="show stack status")
    dojo_status.add_argument("--compose-dir", type=str, help="Directory for compose files")
    dojo_status.add_argument("--project-name", type=str, help="Docker Compose project name")

    dojo_open = dojo_subparsers.add_parser("open", help="open the local UI in a browser")
    dojo_open.add_argument("--compose-dir", type=str, help="Directory for compose files")
    dojo_open.add_argument("--port", type=int, help="HTTP port for the UI")

    # ThreatFlow threat modeling subcommand
    threatflow_parser = subparsers.add_parser(
        "threatflow", help="generate threat model for a repository"
    )
    threatflow_parser.add_argument("--repo", type=str, help="Path to repository to analyze")
    threatflow_parser.add_argument("--output-dir", type=str, help="Output directory for artifacts")
    threatflow_parser.add_argument(
        "--model-mode",
        type=str,
        choices=["local", "openai", "anthropic", "mock"],
        help="LLM backend: local (default), openai, anthropic, or mock for testing",
    )
    threatflow_parser.add_argument(
        "--model-path", type=str, help="Path to local model file (for local mode)"
    )
    threatflow_parser.add_argument(
        "--api-key", type=str, help="API key for remote LLM (prefer env var)"
    )
    threatflow_parser.add_argument("--model-name", type=str, help="Specific model name to use")
    threatflow_parser.add_argument(
        "--max-files", type=int, default=500, help="Maximum files to analyze"
    )
    threatflow_parser.add_argument(
        "--timeout", type=int, default=300, help="Timeout in seconds for model calls"
    )
    threatflow_parser.add_argument(
        "--no-redact", action="store_true", help="Disable secret redaction (NOT RECOMMENDED)"
    )
    threatflow_parser.add_argument(
        "--no-sanitize",
        action="store_true",
        help="Disable prompt injection sanitization (NOT RECOMMENDED)",
    )

    # Triage TUI subcommand
    triage_parser = subparsers.add_parser("triage", help="interactively triage security findings")
    triage_parser.add_argument(
        "--input",
        type=str,
        help="Path to findings JSON file (from scan output)",
    )
    triage_parser.add_argument(
        "--output",
        type=str,
        help="Path for .kekkaiignore output (default: .kekkaiignore)",
    )

    parsed = parser.parse_args(args)
    if parsed.command == "init":
        return _command_init(parsed.config, parsed.force)
    if parsed.command == "scan":
        return _command_scan(
            parsed.config,
            parsed.repo,
            parsed.run_dir,
            parsed.run_id,
            parsed.scanners,
            parsed.import_dojo,
            parsed.dojo_url,
            parsed.dojo_api_key,
            parsed.target_url,
            parsed.allow_private_ips,
            parsed.enable_falco,
            parsed.ci,
            parsed.fail_on,
            parsed.output,
            pr_comment=parsed.pr_comment,
            github_token=parsed.github_token,
            pr_number=parsed.pr_number,
            github_repo=parsed.github_repo,
            max_comments=parsed.max_comments,
            comment_severity=parsed.comment_severity,
        )
    if parsed.command == "dojo":
        return _command_dojo(parsed)
    if parsed.command == "threatflow":
        return _command_threatflow(parsed)
    if parsed.command == "triage":
        return _command_triage(parsed)

    parser.print_help()
    return 1


def _handle_no_args() -> int:
    cfg_path = config_path()
    if not cfg_path.exists():
        return _command_init(None, False)
    print_dashboard()
    return 0


def _command_init(config_override: str | None, force: bool) -> int:
    cfg_path = _resolve_config_path(config_override)
    if cfg_path.exists() and not force:
        print(f"Config already exists at {cfg_path}. Use --force to overwrite.")
        return 1

    base_dir = app_base_dir()
    ensure_dir(base_dir)
    ensure_dir(base_dir / "runs")
    ensure_dir(cfg_path.parent)

    cfg_path.write_text(load_config_text(base_dir))
    print_dashboard()
    console.print(f"\n[success]Initialized config at[/success] [cyan]{cfg_path}[/cyan]\n")
    return 0


def _command_scan(
    config_override: str | None,
    repo_override: str | None,
    run_dir_override: str | None,
    run_id_override: str | None,
    scanners_override: str | None,
    import_dojo: bool,
    dojo_url_override: str | None,
    dojo_api_key_override: str | None,
    target_url_override: str | None = None,
    allow_private_ips: bool = False,
    enable_falco: bool = False,
    ci_mode: bool = False,
    fail_on_override: str | None = None,
    output_path: str | None = None,
    *,
    pr_comment: bool = False,
    github_token: str | None = None,
    pr_number: int | None = None,
    github_repo: str | None = None,
    max_comments: int = 50,
    comment_severity: str = "medium",
) -> int:
    cfg_path = _resolve_config_path(config_override)
    if not cfg_path.exists():
        print(f"Config not found at {cfg_path}. Run `kekkai init`.")
        return 1

    overrides = ConfigOverrides(repo_path=Path(repo_override) if repo_override else None)
    cfg = load_config(cfg_path, overrides=overrides, base_dir=app_base_dir())

    repo_path = _resolve_repo_path(cfg.repo_path)
    if not repo_path.exists() or not repo_path.is_dir():
        print(f"Repo path not found: {repo_path}")
        return 1

    run_id = _resolve_run_id(run_id_override)
    if not RUN_ID_PATTERN.match(run_id):
        print("Run id must be 3-64 chars (letters, digits, ._-)")
        return 1

    base_dir = app_base_dir()
    run_dir = _resolve_run_dir(base_dir, cfg.run_base_dir, run_id, run_dir_override)
    ensure_dir(run_dir)

    # Determine which scanners to run
    scanner_names = _resolve_scanners(scanners_override, cfg.scanners)

    started_at = _now_iso()
    step_results: list[StepResult] = []
    scan_results: list[ScanResult] = []
    status_ok = True

    # Run pipeline steps if configured
    for step in cfg.pipeline:
        result = run_step(
            step,
            cwd=repo_path,
            env_allowlist=cfg.env_allowlist,
            timeout_seconds=cfg.timeout_seconds,
        )
        step_results.append(result)
        if result.exit_code != 0:
            status_ok = False
            break

    # Run container-based scanners
    if scanner_names and status_ok:
        commit_sha = _get_commit_sha(repo_path)
        ctx = ScanContext(
            repo_path=repo_path,
            output_dir=run_dir,
            run_id=run_id,
            commit_sha=commit_sha,
            timeout_seconds=cfg.timeout_seconds,
        )
        scanners_map = {}

        # Resolve ZAP target URL
        zap_target_url = target_url_override or os.environ.get("KEKKAI_ZAP_TARGET_URL")
        if cfg.zap and cfg.zap.target_url:
            zap_target_url = zap_target_url or cfg.zap.target_url

        # Resolve ZAP allow_private_ips
        zap_allow_private = allow_private_ips
        if cfg.zap and cfg.zap.allow_private_ips:
            zap_allow_private = True

        # Resolve Falco enabled
        falco_enabled = enable_falco or os.environ.get("KEKKAI_ENABLE_FALCO") == "1"
        if cfg.falco and cfg.falco.enabled:
            falco_enabled = True

        for name in scanner_names:
            scanner = _create_scanner(
                name=name,
                zap_target_url=zap_target_url,
                zap_allow_private_ips=zap_allow_private,
                zap_allowed_domains=cfg.zap.allowed_domains if cfg.zap else [],
                falco_enabled=falco_enabled,
            )
            if scanner is None:
                console.print(f"[warning]Unknown scanner: {sanitize_for_terminal(name)}[/warning]")
                continue

            scanners_map[name] = scanner
            console.print(f"Running [cyan]{sanitize_for_terminal(name)}[/cyan]...")
            scan_result = scanner.run(ctx)
            scan_results.append(scan_result)
            if not scan_result.success:
                err_msg = sanitize_error(scan_result.error or "Unknown error")
                console.print(f"  [danger]{sanitize_for_terminal(name)} failed:[/danger] {err_msg}")
                # For ZAP/Falco: failures should not be hidden
                if name in ("zap", "falco"):
                    status_ok = False
            else:
                deduped = dedupe_findings(scan_result.findings)
                console.print(
                    f"  [success]{sanitize_for_terminal(name)}:[/success] {len(deduped)} findings"
                )

        # Import to DefectDojo if requested
        if import_dojo or (cfg.dojo and cfg.dojo.enabled):
            dojo_cfg = _resolve_dojo_config(
                cfg.dojo,
                dojo_url_override,
                dojo_api_key_override,
            )
            if dojo_cfg and dojo_cfg.api_key:
                console.print("Importing to DefectDojo...")
                import_results = import_results_to_dojo(
                    config=dojo_cfg,
                    results=scan_results,
                    scanners=scanners_map,
                    run_id=run_id,
                    commit_sha=commit_sha,
                )
                for ir in import_results:
                    if ir.success:
                        created, closed = ir.findings_created, ir.findings_closed
                        console.print(
                            f"  [success]Imported:[/success] {created} created, {closed} closed"
                        )
                    else:
                        err = sanitize_error(ir.error or "")
                        console.print(f"  [danger]Import failed:[/danger] {err}")
            else:
                console.print("[muted]DefectDojo import skipped: no API key configured[/muted]")

    finished_at = _now_iso()
    run_manifest = manifest.build_manifest(
        run_id=run_id,
        repo_path=repo_path,
        run_dir=run_dir,
        started_at=started_at,
        finished_at=finished_at,
        steps=step_results,
    )
    manifest.write_manifest(run_dir / "run.json", run_manifest)

    # Collect all findings for policy evaluation
    all_findings: list[Finding] = []
    scan_errors: list[str] = []
    for scan_res in scan_results:
        if scan_res.success:
            all_findings.extend(dedupe_findings(scan_res.findings))
        elif scan_res.error:
            scan_errors.append(f"{scan_res.scanner}: {scan_res.error}")

    # Post PR comments if requested
    if pr_comment and all_findings:
        _post_pr_comments(
            all_findings,
            github_token=github_token,
            pr_number=pr_number,
            github_repo=github_repo,
            max_comments=max_comments,
            min_severity=comment_severity,
        )

    # Apply policy in CI mode
    if ci_mode or fail_on_override:
        policy_config = _resolve_policy_config(cfg.policy, fail_on_override, ci_mode)
        policy_result = evaluate_policy(all_findings, policy_config, scan_errors)

        # Write policy result JSON
        result_path = Path(output_path) if output_path else (run_dir / "policy-result.json")
        policy_result.write_json(result_path)

        # Print summary
        _print_policy_summary(policy_result)

        # Print scan summary table
        _print_scan_summary_table(scan_results)

        console.print(f"Run complete: [cyan]{run_dir}[/cyan]")
        return policy_result.exit_code

    # Print scan summary table
    _print_scan_summary_table(scan_results)

    console.print(f"Run complete: [cyan]{run_dir}[/cyan]")
    return 0 if status_ok else EXIT_SCAN_ERROR


def _resolve_scanners(override: str | None, config_scanners: list[str] | None) -> list[str]:
    if override:
        return [s.strip() for s in override.split(",") if s.strip()]
    if config_scanners:
        return config_scanners
    return []


def _resolve_policy_config(
    settings: PolicySettings | None,
    fail_on_override: str | None,
    ci_mode: bool,
) -> PolicyConfig:
    """Resolve policy configuration from settings and overrides.

    Priority: --fail-on > config file [policy] > default CI policy
    """
    # --fail-on takes highest priority
    if fail_on_override:
        return parse_fail_on(fail_on_override)

    # Use config file settings if available
    if settings:
        return PolicyConfig(
            fail_on_critical=settings.fail_on_critical,
            fail_on_high=settings.fail_on_high,
            fail_on_medium=settings.fail_on_medium,
            fail_on_low=settings.fail_on_low,
            fail_on_info=settings.fail_on_info,
            max_critical=settings.max_critical,
            max_high=settings.max_high,
            max_medium=settings.max_medium,
            max_low=settings.max_low,
            max_info=settings.max_info,
            max_total=settings.max_total,
        )

    # Default CI policy
    if ci_mode:
        return default_ci_policy()

    # Fallback (shouldn't reach here if ci_mode or fail_on is set)
    return default_ci_policy()


def _print_scan_summary_table(scan_results: list[ScanResult]) -> None:
    """Print scan results summary table."""
    if not scan_results:
        return

    rows = [
        ScanSummaryRow(
            scanner=r.scanner,
            success=r.success,
            findings_count=len(dedupe_findings(r.findings)) if r.success else 0,
            duration_ms=r.duration_ms,
        )
        for r in scan_results
    ]
    console.print(print_scan_summary(rows))


def _print_policy_summary(result: PolicyResult) -> None:
    """Print policy evaluation summary to stdout."""
    counts = result.counts
    status = "[success]PASSED[/success]" if result.passed else "[danger]FAILED[/danger]"
    console.print(f"\nPolicy Evaluation: {status}")
    console.print(f"  Findings: {counts.total} total")
    console.print(f"    [danger]Critical:[/danger] {counts.critical}")
    console.print(f"    [warning]High:[/warning] {counts.high}")
    console.print(f"    [info]Medium:[/info] {counts.medium}")
    console.print(f"    Low: {counts.low}")
    console.print(f"    [muted]Info:[/muted] {counts.info}")

    if result.violations:
        console.print("  [danger]Violations:[/danger]")
        for v in result.violations:
            console.print(f"    - {sanitize_for_terminal(v.message)}")

    if result.scan_errors:
        console.print("  [warning]Scan Errors:[/warning]")
        for e in result.scan_errors:
            console.print(f"    - {sanitize_error(e)}")


def _post_pr_comments(
    findings: list[Finding],
    *,
    github_token: str | None,
    pr_number: int | None,
    github_repo: str | None,
    max_comments: int,
    min_severity: str,
) -> None:
    """Post findings as GitHub PR review comments."""
    # Resolve token from env if not provided
    token = github_token or os.environ.get("GITHUB_TOKEN")
    if not token:
        console.print("[warning]PR comment requested but no GitHub token provided[/warning]")
        return

    # Auto-detect PR number from GitHub Actions event
    if pr_number is None:
        pr_number = _detect_pr_number()
    if pr_number is None:
        console.print("[warning]PR comment requested but no PR number detected[/warning]")
        return

    # Resolve owner/repo
    owner, repo = _resolve_github_repo(github_repo)
    if not owner or not repo:
        console.print("[warning]PR comment requested but repository not detected[/warning]")
        return

    try:
        from .github import GitHubConfig
        from .github import post_pr_comments as _post_comments

        config = GitHubConfig(
            token=token,
            owner=owner,
            repo=repo,
            pr_number=pr_number,
        )
        result = _post_comments(
            findings,
            config,
            max_comments=max_comments,
            min_severity=min_severity,
        )
        if result.success:
            console.print(f"[success]Posted {result.comments_posted} PR comment(s)[/success]")
            if result.review_url:
                console.print(f"  Review: [link]{result.review_url}[/link]")
        else:
            for err in result.errors:
                console.print(f"[warning]PR comment error: {sanitize_error(err)}[/warning]")
    except Exception as e:
        console.print(f"[warning]Failed to post PR comments: {sanitize_error(str(e))}[/warning]")


def _detect_pr_number() -> int | None:
    """Auto-detect PR number from GitHub Actions environment."""
    import json as _json

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None

    try:
        with open(event_path) as f:
            event: dict[str, dict[str, int]] = _json.load(f)
        pr = event.get("pull_request", {})
        return pr.get("number")
    except (OSError, ValueError, KeyError):
        return None


def _resolve_github_repo(override: str | None) -> tuple[str | None, str | None]:
    """Resolve GitHub owner/repo from override or environment."""
    if override and "/" in override:
        parts = override.split("/", 1)
        return parts[0], parts[1]

    # Try GITHUB_REPOSITORY env var (set in GitHub Actions)
    repo_env = os.environ.get("GITHUB_REPOSITORY")
    if repo_env and "/" in repo_env:
        parts = repo_env.split("/", 1)
        return parts[0], parts[1]

    return None, None


def _create_scanner(
    name: str,
    zap_target_url: str | None = None,
    zap_allow_private_ips: bool = False,
    zap_allowed_domains: list[str] | None = None,
    falco_enabled: bool = False,
) -> Scanner | None:
    """Create a scanner instance by name.

    Handles both core scanners (SAST/SCA) and optional scanners (DAST/runtime).
    """
    # Check core scanners first
    scanner_cls = SCANNER_REGISTRY.get(name)
    if scanner_cls:
        scanner: Scanner = scanner_cls()
        return scanner

    # Handle optional scanners with special configuration
    if name == "zap":
        zap: Scanner = create_zap_scanner(
            target_url=zap_target_url,
            allow_private_ips=zap_allow_private_ips,
            allowed_domains=zap_allowed_domains or [],
        )
        return zap

    if name == "falco":
        falco: Scanner = create_falco_scanner(enabled=falco_enabled)
        return falco

    # Check optional scanners registry (shouldn't reach here normally)
    if name in OPTIONAL_SCANNERS:
        optional: Scanner = OPTIONAL_SCANNERS[name]()
        return optional

    return None


def _resolve_dojo_config(
    settings: DojoSettings | None,
    url_override: str | None,
    api_key_override: str | None,
) -> DojoConfig | None:
    base_url = url_override or os.environ.get("KEKKAI_DOJO_URL")
    api_key = api_key_override or os.environ.get("KEKKAI_DOJO_API_KEY")

    if settings:
        base_url = base_url or settings.base_url
        api_key = api_key or settings.api_key
        return DojoConfig(
            base_url=base_url or "http://localhost:8080",
            api_key=api_key or "",
            product_name=settings.product_name,
            engagement_name=settings.engagement_name,
        )

    if base_url or api_key:
        return DojoConfig(
            base_url=base_url or "http://localhost:8080",
            api_key=api_key or "",
        )
    return None


def _get_commit_sha(repo_path: Path) -> str | None:
    import shutil
    import subprocess  # nosec B404

    git = shutil.which("git")
    if not git:
        return None
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [git, "rev-parse", "HEAD"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def _command_dojo(parsed: argparse.Namespace) -> int:
    compose_root = dojo.compose_dir(_resolve_dojo_compose_dir(parsed))
    project_name = _resolve_dojo_project_name(parsed)

    if parsed.dojo_command == "up":
        port = _resolve_dojo_port(parsed)
        tls_port = _resolve_dojo_tls_port(parsed, port)
        try:
            env = dojo.compose_up(
                compose_root=compose_root,
                project_name=project_name,
                port=port,
                tls_port=tls_port,
                wait=bool(parsed.wait),
                open_browser=bool(parsed.open),
            )
        except RuntimeError as exc:
            print(str(exc))
            return 1
        print(f"DefectDojo is starting at http://localhost:{port}/")
        print(f"Admin user: {env.get('DD_ADMIN_USER', 'admin')}")
        print("Admin password stored in .env")
        return 0

    if parsed.dojo_command == "down":
        try:
            dojo.compose_down(compose_root=compose_root, project_name=project_name)
        except RuntimeError as exc:
            print(str(exc))
            return 1
        print("DefectDojo stack stopped")
        return 0

    if parsed.dojo_command == "status":
        try:
            statuses = dojo.compose_status(compose_root=compose_root, project_name=project_name)
        except RuntimeError as exc:
            print(str(exc))
            return 1
        if not statuses:
            print("No running services found. Run `kekkai dojo up`.")
            return 0
        for status in statuses:
            details = [status.state]
            if status.health:
                details.append(f"health={status.health}")
            if status.ports:
                details.append(f"ports={status.ports}")
            print(f"{status.name}: {' '.join(details)}")
        return 0

    if parsed.dojo_command == "open":
        port = _resolve_dojo_open_port(parsed, compose_root)
        dojo.open_ui(port)
        return 0

    print("Unknown dojo command. Use `kekkai dojo --help`.")
    return 1


def _command_threatflow(parsed: argparse.Namespace) -> int:
    """Run ThreatFlow threat model analysis."""
    from .threatflow import ThreatFlow, ThreatFlowConfig

    # Resolve repository path
    repo_override = cast(str | None, getattr(parsed, "repo", None))
    repo_path = Path(repo_override) if repo_override else Path.cwd()
    repo_path = repo_path.expanduser().resolve()

    if not repo_path.exists() or not repo_path.is_dir():
        print(f"Error: Repository path not found: {repo_path}")
        return 1

    # Build config from CLI args and environment
    model_mode_raw = getattr(parsed, "model_mode", None) or os.environ.get("KEKKAI_THREATFLOW_MODE")
    model_mode: str = model_mode_raw if model_mode_raw else "local"
    model_path = getattr(parsed, "model_path", None) or os.environ.get(
        "KEKKAI_THREATFLOW_MODEL_PATH"
    )
    api_key = getattr(parsed, "api_key", None) or os.environ.get("KEKKAI_THREATFLOW_API_KEY")
    model_name = getattr(parsed, "model_name", None) or os.environ.get(
        "KEKKAI_THREATFLOW_MODEL_NAME"
    )

    config = ThreatFlowConfig(
        model_mode=model_mode,
        model_path=model_path,
        api_key=api_key,
        model_name=model_name,
        max_files=getattr(parsed, "max_files", 500),
        timeout_seconds=getattr(parsed, "timeout", 300),
        redact_secrets=not getattr(parsed, "no_redact", False),
        sanitize_content=not getattr(parsed, "no_sanitize", False),
    )

    # Resolve output directory
    output_dir_override = cast(str | None, getattr(parsed, "output_dir", None))
    output_dir = Path(output_dir_override) if output_dir_override else None

    # Display banner
    print(_threatflow_banner())
    print(f"Repository: {repo_path}")
    print(f"Model mode: {model_mode}")

    # Warn about remote mode
    if model_mode in ("openai", "anthropic"):
        print(
            "\n*** WARNING: Using remote API. Code content will be sent to external service. ***\n"
        )
        if not api_key:
            print("Error: API key required for remote mode.")
            print("  Set --api-key or KEKKAI_THREATFLOW_API_KEY")
            return 1

    # Warn about disabled security controls
    if config.redact_secrets is False:
        print("*** WARNING: Secret redaction is DISABLED. Secrets may be sent to LLM. ***")
    if config.sanitize_content is False:
        print("*** WARNING: Prompt sanitization is DISABLED. Injection attacks possible. ***")

    print("\nAnalyzing repository...")

    # Run analysis
    tf = ThreatFlow(config=config)
    result = tf.analyze(repo_path=repo_path, output_dir=output_dir)

    if not result.success:
        print(f"\nAnalysis failed: {result.error}")
        return 1

    # Print results
    print(f"\nAnalysis complete in {result.duration_ms}ms")
    print(f"Files processed: {result.files_processed}")
    print(f"Files skipped: {result.files_skipped}")

    if result.warnings:
        print("\nWarnings:")
        for w in result.warnings:
            print(f"  - {w}")

    if result.injection_warnings:
        print("\nInjection patterns detected (sanitized):")
        for w in result.injection_warnings[:5]:  # Limit output
            print(f"  - {w}")
        if len(result.injection_warnings) > 5:
            print(f"  ... and {len(result.injection_warnings) - 5} more")

    print("\nOutput files:")
    for path in result.output_files:
        print(f"  - {path}")

    # Print threat summary if available
    if result.artifacts:
        counts = result.artifacts.threat_count_by_risk()
        total = len(result.artifacts.threats)
        print(f"\nThreats identified: {total}")
        for level in ["critical", "high", "medium", "low"]:
            if counts.get(level, 0) > 0:
                print(f"  - {level.capitalize()}: {counts[level]}")

    return 0


def _threatflow_banner() -> str:
    """Return ThreatFlow banner."""
    return (
        "\n"
        "ThreatFlow — AI-Assisted Threat Modeling\n"
        "=========================================\n"
        "STRIDE analysis powered by local-first LLM\n"
    )


def _command_triage(parsed: argparse.Namespace) -> int:
    """Run interactive triage TUI."""
    from .triage import run_triage

    input_path_str = cast(str | None, getattr(parsed, "input", None))
    output_path_str = cast(str | None, getattr(parsed, "output", None))

    input_path = Path(input_path_str).expanduser().resolve() if input_path_str else None
    output_path = Path(output_path_str).expanduser().resolve() if output_path_str else None

    if input_path and not input_path.exists():
        console.print(f"[danger]Error:[/danger] Input file not found: {input_path}")
        return 1

    console.print("[bold cyan]Kekkai Triage[/bold cyan] - Interactive Finding Review")
    console.print("Use j/k to navigate, f=false positive, c=confirmed, d=deferred")
    console.print("Press Ctrl+S to save, q to quit\n")

    return run_triage(input_path=input_path, output_path=output_path)


def _resolve_dojo_compose_dir(parsed: argparse.Namespace) -> str | None:
    compose_dir = cast(str | None, getattr(parsed, "compose_dir", None))
    if compose_dir:
        return compose_dir
    return os.environ.get("KEKKAI_DOJO_COMPOSE_DIR")


def _resolve_dojo_project_name(parsed: argparse.Namespace) -> str:
    project_name = cast(str | None, getattr(parsed, "project_name", None))
    if project_name:
        return project_name
    return os.environ.get("KEKKAI_DOJO_PROJECT_NAME", dojo.DEFAULT_PROJECT_NAME)


def _resolve_dojo_port(parsed: argparse.Namespace) -> int:
    port = cast(int | None, getattr(parsed, "port", None))
    if port is not None:
        return port
    if env_port := os.environ.get("KEKKAI_DOJO_PORT"):
        return int(env_port)
    return dojo.DEFAULT_PORT


def _resolve_dojo_tls_port(parsed: argparse.Namespace, port: int) -> int:
    tls_port = cast(int | None, getattr(parsed, "tls_port", None))
    if tls_port is not None:
        return tls_port
    if env_port := os.environ.get("KEKKAI_DOJO_TLS_PORT"):
        return int(env_port)
    return dojo.DEFAULT_TLS_PORT if port != dojo.DEFAULT_TLS_PORT else port + 1


def _resolve_dojo_open_port(parsed: argparse.Namespace, compose_root: Path) -> int:
    port = cast(int | None, getattr(parsed, "port", None))
    if port is not None:
        return port
    env = dojo.load_env_file(compose_root / ".env")
    if value := env.get("DD_PORT"):
        return int(value)
    if env_port := os.environ.get("KEKKAI_DOJO_PORT"):
        return int(env_port)
    return dojo.DEFAULT_PORT


def _resolve_config_path(config_override: str | None) -> Path:
    if config_override:
        return Path(config_override).expanduser().resolve()
    return config_path()


def _resolve_repo_path(repo_path: Path) -> Path:
    if repo_path.is_absolute():
        return repo_path.resolve()
    return (Path.cwd() / repo_path).resolve()


def _resolve_run_id(override: str | None) -> str:
    return override or os.environ.get("KEKKAI_RUN_ID") or _generate_run_id()


def _resolve_run_dir(
    base_dir: Path,
    run_base_dir: Path,
    run_id: str,
    run_dir_override: str | None,
) -> Path:
    env_override = os.environ.get("KEKKAI_RUN_DIR")
    override = run_dir_override or env_override
    if override:
        return Path(override).expanduser().resolve()

    resolved_base = run_base_dir.expanduser()
    if not resolved_base.is_absolute():
        resolved_base = (base_dir / resolved_base).resolve()

    if is_within_base(base_dir, resolved_base):
        return safe_join(resolved_base, run_id)
    return (resolved_base / run_id).resolve()


def _generate_run_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"run-{timestamp}"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def load_config_text(base_dir: Path) -> str:
    from .config import default_config_text

    return default_config_text(base_dir)
