from __future__ import annotations

import shutil
import subprocess  # nosec B404
import time
from pathlib import Path

from .base import BackendType, ExecutionResult, ScannerBackend

_docker_available_cache: tuple[bool, str] | None = None


def docker_available(force_check: bool = False) -> tuple[bool, str]:
    """Check if Docker is available and running.

    Args:
        force_check: Bypass cache and re-check

    Returns:
        Tuple of (available, reason)
    """
    global _docker_available_cache

    if _docker_available_cache is not None and not force_check:
        return _docker_available_cache

    docker_path = shutil.which("docker")
    if not docker_path:
        _docker_available_cache = (False, "Docker not found in PATH")
        return _docker_available_cache

    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [docker_path, "info"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            _docker_available_cache = (True, "Docker available")
            return _docker_available_cache
        _docker_available_cache = (False, f"Docker not running: {result.stderr.strip()}")
        return _docker_available_cache
    except subprocess.TimeoutExpired:
        _docker_available_cache = (False, "Docker info timed out")
        return _docker_available_cache
    except OSError as e:
        _docker_available_cache = (False, f"Docker error: {e}")
        return _docker_available_cache


class DockerBackend(ScannerBackend):
    """Docker-based scanner execution backend."""

    def __init__(
        self,
        read_only: bool = True,
        no_new_privileges: bool = True,
        memory_limit: str = "2g",
        cpu_limit: str = "2",
    ) -> None:
        self._read_only = read_only
        self._no_new_privileges = no_new_privileges
        self._memory_limit = memory_limit
        self._cpu_limit = cpu_limit

    @property
    def backend_type(self) -> BackendType:
        return BackendType.DOCKER

    def is_available(self) -> tuple[bool, str]:
        return docker_available()

    def execute(
        self,
        tool: str,
        args: list[str],
        repo_path: Path,
        output_path: Path,
        timeout_seconds: int = 600,
        env: dict[str, str] | None = None,
        network_required: bool = False,
        skip_repo_mount: bool = False,
        workdir: str | None = None,
        output_mount: str | None = None,
        user: str | None = "1000:1000",
    ) -> ExecutionResult:
        """Execute scanner in Docker container.

        Args:
            tool: Docker image reference (e.g., "aquasec/trivy:latest")
            args: Command arguments to run in container
            repo_path: Path to repository (mounted read-only at /repo)
            output_path: Path for output (mounted read-write at /output)
            timeout_seconds: Execution timeout
            env: Environment variables
            network_required: Whether to allow network access
            skip_repo_mount: Skip mounting repo (for DAST scanners)
            workdir: Override working directory
            output_mount: Override output mount point
            user: User to run as (default: 1000:1000)
        """
        docker_path = shutil.which("docker")
        if not docker_path:
            return ExecutionResult(
                exit_code=127,
                stdout="",
                stderr="Docker not found",
                duration_ms=0,
                timed_out=False,
                backend=self.backend_type,
            )

        cmd = [docker_path, "run", "--rm"]

        if user:
            cmd.extend(["--user", user])

        if self._read_only:
            cmd.extend(["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m"])  # nosec B108  # noqa: S108

        if not network_required:
            cmd.extend(["--network", "none"])

        if self._no_new_privileges:
            cmd.append("--security-opt=no-new-privileges")

        if self._memory_limit:
            cmd.extend(["--memory", self._memory_limit])

        if self._cpu_limit:
            cmd.extend(["--cpus", self._cpu_limit])

        if not skip_repo_mount:
            cmd.extend(["-v", f"{repo_path.resolve()}:/repo:ro"])

        mount_point = output_mount or "/output"
        cmd.extend(["-v", f"{output_path.resolve()}:{mount_point}:rw"])
        cmd.extend(["-w", workdir or "/repo"])

        if env:
            for key, value in env.items():
                cmd.extend(["-e", f"{key}={value}"])

        cmd.append(tool)
        cmd.extend(args)

        start = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603  # nosec B603
                cmd,
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
