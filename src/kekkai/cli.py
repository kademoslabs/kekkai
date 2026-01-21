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
from .config import ConfigOverrides, load_config
from .paths import app_base_dir, config_path, ensure_dir, is_within_base, safe_join
from .runner import StepResult, run_step

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
        return _command_scan(parsed.config, parsed.repo, parsed.run_dir, parsed.run_id)
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

    started_at = _now_iso()
    results: list[StepResult] = []
    status_ok = True

    for step in cfg.pipeline:
        result = run_step(
            step,
            cwd=repo_path,
            env_allowlist=cfg.env_allowlist,
            timeout_seconds=cfg.timeout_seconds,
        )
        results.append(result)
        if result.exit_code != 0:
            status_ok = False
            break

    finished_at = _now_iso()
    run_manifest = manifest.build_manifest(
        run_id=run_id,
        repo_path=repo_path,
        run_dir=run_dir,
        started_at=started_at,
        finished_at=finished_at,
        steps=results,
    )
    manifest.write_manifest(run_dir / "run.json", run_manifest)

    print(f"Run complete: {run_dir}")
    return 0 if status_ok else 1


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
