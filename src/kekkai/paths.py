from __future__ import annotations

import os
from pathlib import Path


def app_base_dir() -> Path:
    override = os.environ.get("KEKKAI_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path("~/.kekkai").expanduser().resolve()


def config_path() -> Path:
    return app_base_dir() / "kekkai.toml"


def bin_dir() -> Path:
    """Get the directory for installed tool binaries."""
    path = app_base_dir() / "bin"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def safe_join(base: Path, *parts: str) -> Path:
    base_resolved = base.expanduser().resolve()
    candidate = base_resolved.joinpath(*parts).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError("path escapes base directory") from exc
    return candidate


def is_within_base(base: Path, path: Path) -> bool:
    base_resolved = base.expanduser().resolve()
    path_resolved = path.expanduser().resolve()
    try:
        path_resolved.relative_to(base_resolved)
    except ValueError:
        return False
    return True
