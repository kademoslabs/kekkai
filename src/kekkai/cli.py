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
from .config import ConfigOverrides, DojoSettings, load_config
from .dojo_import import DojoConfig, import_results_to_dojo
from .paths import app_base_dir, config_path, ensure_dir, is_within_base, safe_join
from .runner import StepResult, run_step
from .scanners import (
    OPTIONAL_SCANNERS,
    SCANNER_REGISTRY,
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
        )
    if parsed.command == "dojo":
        return _command_dojo(parsed)

    parser.print_help()
    return 1


def _handle_no_args() -> int:
    cfg_path = config_path()
    if not cfg_path.exists():
        return _command_init(None, False)
    print(_splash())
    print("Config exists. Run one of:")
    print("  kekkai scan")
    print("  kekkai init --force")
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
    print(_splash())
    print(f"Initialized config at {cfg_path}")
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
                print(f"Unknown scanner: {name}")
                continue

            scanners_map[name] = scanner
            print(f"Running {name}...")
            scan_result = scanner.run(ctx)
            scan_results.append(scan_result)
            if not scan_result.success:
                print(f"  {name} failed: {scan_result.error}")
                # For ZAP/Falco: failures should not be hidden
                if name in ("zap", "falco"):
                    status_ok = False
            else:
                deduped = dedupe_findings(scan_result.findings)
                print(f"  {name}: {len(deduped)} findings")

        # Import to DefectDojo if requested
        if import_dojo or (cfg.dojo and cfg.dojo.enabled):
            dojo_cfg = _resolve_dojo_config(
                cfg.dojo,
                dojo_url_override,
                dojo_api_key_override,
            )
            if dojo_cfg and dojo_cfg.api_key:
                print("Importing to DefectDojo...")
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
                        print(f"  Imported: {created} created, {closed} closed")
                    else:
                        print(f"  Import failed: {ir.error}")
            else:
                print("DefectDojo import skipped: no API key configured")

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

    print(f"Run complete: {run_dir}")
    return 0 if status_ok else 1


def _resolve_scanners(override: str | None, config_scanners: list[str] | None) -> list[str]:
    if override:
        return [s.strip() for s in override.split(",") if s.strip()]
    if config_scanners:
        return config_scanners
    return []


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


def _splash() -> str:
    return (
        "Kekkai — Security that moves at developer speed.\n"
        "===============================================\n"
        "[shield]>_\n"
    )


def load_config_text(base_dir: Path) -> str:
    from .config import default_config_text

    return default_config_text(base_dir)
