from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .paths import app_base_dir

DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_ENV_ALLOWLIST = [
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
]
DEFAULT_SCANNERS = ["trivy", "semgrep", "gitleaks"]


@dataclass(frozen=True)
class PipelineStep:
    name: str
    args: list[str]


@dataclass(frozen=True)
class DojoSettings:
    enabled: bool = False
    base_url: str = "http://localhost:8080"
    api_key: str = ""
    product_name: str = "Kekkai Scans"
    engagement_name: str = "Default Engagement"


@dataclass(frozen=True)
class ZapSettings:
    """ZAP DAST scanner settings.

    ZAP requires explicit target URL and enforces URL policy by default.
    Private IPs are blocked unless explicitly allowed.
    """

    enabled: bool = False
    target_url: str | None = None
    allow_private_ips: bool = False  # Default: block private/internal IPs
    allowed_domains: list[str] = field(default_factory=list)
    timeout_seconds: int = 900


@dataclass(frozen=True)
class FalcoSettings:
    """Falco runtime security settings.

    EXPERIMENTAL: Linux-only. Requires explicit opt-in.
    """

    enabled: bool = False  # Must be explicitly enabled
    rules_file: str | None = None
    timeout_seconds: int = 300


@dataclass(frozen=True)
class PolicySettings:
    """Policy enforcement settings for CI mode.

    Configures which severity levels trigger failures and threshold limits.
    """

    fail_on_critical: bool = True
    fail_on_high: bool = True
    fail_on_medium: bool = False
    fail_on_low: bool = False
    fail_on_info: bool = False
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = -1  # -1 = no limit
    max_low: int = -1
    max_info: int = -1
    max_total: int = -1


@dataclass(frozen=True)
class ThreatFlowSettings:
    """ThreatFlow threat modeling settings.

    Configures LLM backend and security controls.
    """

    enabled: bool = False
    model_mode: str = "local"  # local, openai, anthropic, mock
    model_path: str | None = None  # For local models
    api_key: str | None = None  # For remote APIs (should use env var)
    api_base: str | None = None  # Custom API endpoint
    model_name: str | None = None  # Specific model to use
    max_files: int = 500
    timeout_seconds: int = 300
    redact_secrets: bool = True
    sanitize_content: bool = True
    warn_on_injection: bool = True


@dataclass(frozen=True)
class Config:
    repo_path: Path
    run_base_dir: Path
    timeout_seconds: int
    env_allowlist: list[str]
    pipeline: list[PipelineStep]
    scanners: list[str] | None = None
    dojo: DojoSettings | None = None
    zap: ZapSettings | None = None
    falco: FalcoSettings | None = None
    policy: PolicySettings | None = None
    threatflow: ThreatFlowSettings | None = None


@dataclass(frozen=True)
class ConfigOverrides:
    repo_path: Path | None = None
    run_base_dir: Path | None = None
    timeout_seconds: int | None = None
    env_allowlist: list[str] | None = None


def default_config(base_dir: Path) -> dict[str, object]:
    return {
        "repo_path": ".",
        "run_base_dir": str(base_dir / "runs"),
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "env_allowlist": list(DEFAULT_ENV_ALLOWLIST),
        "pipeline": [],
    }


def default_config_text(base_dir: Path) -> str:
    env_allowlist = ", ".join(f'"{item}"' for item in DEFAULT_ENV_ALLOWLIST)
    # Use forward slashes for TOML compatibility on Windows (backslashes are escape chars)
    run_base_dir = str(base_dir / "runs").replace("\\", "/")
    return (
        "# Kekkai config\n"
        "# Values can be overridden via env (KEKKAI_*) or CLI flags.\n\n"
        f'repo_path = "."\n'
        f'run_base_dir = "{run_base_dir}"\n'
        f"timeout_seconds = {DEFAULT_TIMEOUT_SECONDS}\n"
        f"env_allowlist = [{env_allowlist}]\n\n"
        "# [[pipeline]]\n"
        '# name = "example"\n'
        '# args = ["echo", "hello"]\n'
    )


def load_config(
    path: Path,
    env: Mapping[str, str] | None = None,
    overrides: ConfigOverrides | None = None,
    base_dir: Path | None = None,
) -> Config:
    env = env or os.environ
    overrides = overrides or ConfigOverrides()
    base_dir = base_dir or app_base_dir()

    values: dict[str, object] = default_config(base_dir)
    values.update(_load_from_file(path))
    values.update(_load_from_env(env))
    values.update(_load_from_overrides(overrides))

    return _coerce_config(values)


def _load_from_file(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text())
    if isinstance(data, dict) and "kekkai" in data and isinstance(data["kekkai"], dict):
        data = data["kekkai"]
    if not isinstance(data, dict):
        raise ValueError("config file must contain a table")
    return dict(data)


def _load_from_env(env: Mapping[str, str]) -> dict[str, object]:
    result: dict[str, object] = {}
    if value := env.get("KEKKAI_REPO_PATH"):
        result["repo_path"] = value
    if value := env.get("KEKKAI_RUN_BASE_DIR"):
        result["run_base_dir"] = value
    if value := env.get("KEKKAI_TIMEOUT_SECONDS"):
        result["timeout_seconds"] = value
    if value := env.get("KEKKAI_ENV_ALLOWLIST"):
        result["env_allowlist"] = value
    return result


def _load_from_overrides(overrides: ConfigOverrides) -> dict[str, object]:
    result: dict[str, object] = {}
    if overrides.repo_path is not None:
        result["repo_path"] = str(overrides.repo_path)
    if overrides.run_base_dir is not None:
        result["run_base_dir"] = str(overrides.run_base_dir)
    if overrides.timeout_seconds is not None:
        result["timeout_seconds"] = overrides.timeout_seconds
    if overrides.env_allowlist is not None:
        result["env_allowlist"] = overrides.env_allowlist
    return result


def _coerce_config(values: Mapping[str, object]) -> Config:
    repo_path = _expect_str(values.get("repo_path"), "repo_path")
    run_base_dir = _expect_str(values.get("run_base_dir"), "run_base_dir")
    timeout_seconds = _expect_int(values.get("timeout_seconds"), "timeout_seconds")
    env_allowlist = _expect_str_list(values.get("env_allowlist"), "env_allowlist")
    pipeline = _parse_pipeline(values.get("pipeline", []))
    scanners = _parse_scanners(values.get("scanners"))
    dojo = _parse_dojo(values.get("dojo"))
    zap = _parse_zap(values.get("zap"))
    falco = _parse_falco(values.get("falco"))
    policy = _parse_policy(values.get("policy"))
    threatflow = _parse_threatflow(values.get("threatflow"))

    return Config(
        repo_path=Path(repo_path),
        run_base_dir=Path(run_base_dir).expanduser(),
        timeout_seconds=timeout_seconds,
        env_allowlist=env_allowlist,
        pipeline=pipeline,
        scanners=scanners,
        dojo=dojo,
        zap=zap,
        falco=falco,
        policy=policy,
        threatflow=threatflow,
    )


def _parse_scanners(value: object) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return [s.strip() for s in value.split(",") if s.strip()]
    if isinstance(value, list):
        return [str(s) for s in value]
    return None


def _parse_dojo(value: object) -> DojoSettings | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return None
    return DojoSettings(
        enabled=bool(value.get("enabled", False)),
        base_url=str(value.get("base_url", "http://localhost:8080")),
        api_key=str(value.get("api_key", "")),
        product_name=str(value.get("product_name", "Kekkai Scans")),
        engagement_name=str(value.get("engagement_name", "Default Engagement")),
    )


def _parse_zap(value: object) -> ZapSettings | None:
    """Parse ZAP settings from config.

    ZAP is disabled by default and requires explicit target URL.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        return None

    allowed_domains = value.get("allowed_domains", [])
    if isinstance(allowed_domains, str):
        allowed_domains = [d.strip() for d in allowed_domains.split(",") if d.strip()]
    elif not isinstance(allowed_domains, list):
        allowed_domains = []

    return ZapSettings(
        enabled=bool(value.get("enabled", False)),
        target_url=value.get("target_url") if value.get("target_url") else None,
        allow_private_ips=bool(value.get("allow_private_ips", False)),
        allowed_domains=list(allowed_domains),
        timeout_seconds=int(value.get("timeout_seconds", 900)),
    )


def _parse_falco(value: object) -> FalcoSettings | None:
    """Parse Falco settings from config.

    Falco is disabled by default (Linux-only, experimental).
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        return None
    return FalcoSettings(
        enabled=bool(value.get("enabled", False)),
        rules_file=value.get("rules_file") if value.get("rules_file") else None,
        timeout_seconds=int(value.get("timeout_seconds", 300)),
    )


def _expect_str(value: object, name: str) -> str:
    if isinstance(value, str):
        return value
    raise ValueError(f"{name} must be a string")


def _expect_int(value: object, name: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ValueError(f"{name} must be an integer")


def _expect_str_list(value: object, name: str) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        items: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"{name} must be a list of strings")
            items.append(item)
        return items
    raise ValueError(f"{name} must be a list of strings")


def _parse_pipeline(value: object) -> list[PipelineStep]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("pipeline must be a list")
    steps: list[PipelineStep] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("pipeline entries must be tables")
        name = _expect_str(item.get("name"), "pipeline.name")
        args = item.get("args")
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError("pipeline.args must be a list of strings")
        steps.append(PipelineStep(name=name, args=list(args)))
    return steps


def _parse_policy(value: object) -> PolicySettings | None:
    """Parse policy settings from config.

    Policy settings control CI mode behavior and thresholds.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        return None

    def _get_int(key: str, default: int) -> int:
        v = value.get(key, default)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and (v.lstrip("-").isdigit()):
            return int(v)
        return default

    return PolicySettings(
        fail_on_critical=bool(value.get("fail_on_critical", True)),
        fail_on_high=bool(value.get("fail_on_high", True)),
        fail_on_medium=bool(value.get("fail_on_medium", False)),
        fail_on_low=bool(value.get("fail_on_low", False)),
        fail_on_info=bool(value.get("fail_on_info", False)),
        max_critical=_get_int("max_critical", 0),
        max_high=_get_int("max_high", 0),
        max_medium=_get_int("max_medium", -1),
        max_low=_get_int("max_low", -1),
        max_info=_get_int("max_info", -1),
        max_total=_get_int("max_total", -1),
    )


def _parse_threatflow(value: object) -> ThreatFlowSettings | None:
    """Parse ThreatFlow settings from config.

    ThreatFlow is disabled by default and uses local model by default when enabled.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        return None

    return ThreatFlowSettings(
        enabled=bool(value.get("enabled", False)),
        model_mode=str(value.get("model_mode", "local")),
        model_path=value.get("model_path") if value.get("model_path") else None,
        api_key=value.get("api_key") if value.get("api_key") else None,
        api_base=value.get("api_base") if value.get("api_base") else None,
        model_name=value.get("model_name") if value.get("model_name") else None,
        max_files=int(value.get("max_files", 500)),
        timeout_seconds=int(value.get("timeout_seconds", 300)),
        redact_secrets=bool(value.get("redact_secrets", True)),
        sanitize_content=bool(value.get("sanitize_content", True)),
        warn_on_injection=bool(value.get("warn_on_injection", True)),
    )
