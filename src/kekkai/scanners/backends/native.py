from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .base import BackendType, ExecutionResult, ScannerBackend

if TYPE_CHECKING:
    pass


class ToolNotFoundError(RuntimeError):
    """Raised when a required tool is not found in PATH."""


class ToolVersionError(RuntimeError):
    """Raised when tool version doesn't meet requirements."""


@dataclass(frozen=True)
class ToolInfo:
    """Information about a detected tool."""

    name: str
    path: str
    version: str
    version_tuple: tuple[int, ...]


# Minimum versions required for native execution
MIN_VERSIONS: dict[str, tuple[int, ...]] = {
    "trivy": (0, 40, 0),
    "semgrep": (1, 50, 0),
    "gitleaks": (8, 18, 0),
    "zap-cli": (0, 10, 0),
    "falco": (0, 35, 0),
}

# Version extraction patterns
VERSION_PATTERNS: dict[str, re.Pattern[str]] = {
    "trivy": re.compile(r"Version:\s*(\d+\.\d+\.\d+)"),
    "semgrep": re.compile(r"(\d+\.\d+\.\d+)"),
    "gitleaks": re.compile(r"v?(\d+\.\d+\.\d+)"),
    "zap-cli": re.compile(r"(\d+\.\d+\.\d+)"),
    "falco": re.compile(r"(\d+\.\d+\.\d+)"),
}


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse version string to tuple of integers."""
    parts = version_str.split(".")
    result: list[int] = []
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            break
    return tuple(result) if result else (0,)


def detect_tool(
    name: str,
    min_version: tuple[int, ...] | None = None,
    version_args: list[str] | None = None,
) -> ToolInfo:
    """Detect a tool in PATH and validate its version.

    Args:
        name: Tool name to search for
        min_version: Minimum required version tuple (e.g., (0, 40, 0))
        version_args: Arguments to get version (default: ["--version"])

    Returns:
        ToolInfo with path and version details

    Raises:
        ToolNotFoundError: If tool not found in PATH
        ToolVersionError: If version doesn't meet minimum requirement
    """
    tool_path = shutil.which(name)

    # Also check ~/.kekkai/bin/ for installed tools
    if not tool_path:
        from kekkai.paths import bin_dir

        kekkai_bin = bin_dir() / name
        if kekkai_bin.exists() and os.access(kekkai_bin, os.X_OK):
            tool_path = str(kekkai_bin)

    if not tool_path:
        raise ToolNotFoundError(f"{name} not found in PATH")

    tool_path = os.path.realpath(tool_path)
    if not os.path.isfile(tool_path):
        raise ToolNotFoundError(f"{name} path is not a file: {tool_path}")
    if not os.access(tool_path, os.X_OK):
        raise ToolNotFoundError(f"{name} is not executable: {tool_path}")

    version_cmd = version_args or ["--version"]
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [tool_path, *version_cmd],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        version_output = result.stdout + result.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        raise ToolVersionError(f"Failed to get {name} version: {e}") from e

    pattern = VERSION_PATTERNS.get(name, re.compile(r"(\d+\.\d+\.\d+)"))
    match = pattern.search(version_output)
    if not match:
        raise ToolVersionError(f"Could not parse {name} version from: {version_output[:200]}")

    version_str = match.group(1)
    version_tuple = _parse_version(version_str)

    min_ver = min_version or MIN_VERSIONS.get(name)
    if min_ver and version_tuple < min_ver:
        min_ver_str = ".".join(str(v) for v in min_ver)
        raise ToolVersionError(f"{name} version {version_str} is below minimum {min_ver_str}")

    return ToolInfo(
        name=name,
        path=tool_path,
        version=version_str,
        version_tuple=version_tuple,
    )


class NativeBackend(ScannerBackend):
    """Native binary scanner execution backend."""

    def __init__(self, env_allowlist: list[str] | None = None) -> None:
        self._env_allowlist = env_allowlist or [
            "PATH",
            "HOME",
            "USER",
            "LANG",
            "LC_ALL",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
        ]

    @property
    def backend_type(self) -> BackendType:
        return BackendType.NATIVE

    def is_available(self) -> tuple[bool, str]:
        return (True, "Native execution always available")

    def execute(
        self,
        tool: str,
        args: list[str],
        repo_path: Path,
        output_path: Path,
        timeout_seconds: int = 600,
        env: dict[str, str] | None = None,
        network_required: bool = False,
    ) -> ExecutionResult:
        """Execute scanner tool natively.

        Args:
            tool: Tool name (will be resolved via PATH)
            args: Command arguments (must be list, no shell expansion)
            repo_path: Path to repository to scan
            output_path: Path for output files
            timeout_seconds: Execution timeout
            env: Additional environment variables
            network_required: Ignored for native execution (always has network)
        """
        if not isinstance(args, list):
            return ExecutionResult(
                exit_code=1,
                stdout="",
                stderr="Arguments must be a list (no shell expansion)",
                duration_ms=0,
                timed_out=False,
                backend=self.backend_type,
            )

        tool_path = shutil.which(tool)
        if not tool_path:
            return ExecutionResult(
                exit_code=127,
                stdout="",
                stderr=f"Tool not found: {tool}",
                duration_ms=0,
                timed_out=False,
                backend=self.backend_type,
            )

        safe_env = {key: os.environ[key] for key in self._env_allowlist if key in os.environ}
        if env:
            safe_env.update(env)

        cmd = [tool_path, *args]

        start = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603  # nosec B603
                cmd,
                cwd=str(repo_path),
                env=safe_env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            return ExecutionResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=duration_ms,
                timed_out=False,
                backend=self.backend_type,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return ExecutionResult(
                exit_code=124,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=True,
                backend=self.backend_type,
            )
