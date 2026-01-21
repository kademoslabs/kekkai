from __future__ import annotations

import shutil
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT = 600


@dataclass(frozen=True)
class ContainerConfig:
    image: str
    image_digest: str | None = None
    read_only: bool = True
    network_disabled: bool = True
    no_new_privileges: bool = True
    memory_limit: str = "2g"
    cpu_limit: str = "2"


@dataclass(frozen=True)
class ContainerResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool


def docker_command() -> str:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker not found; install docker to run scanners")
    return docker


def run_container(
    config: ContainerConfig,
    repo_path: Path,
    output_path: Path,
    command: list[str],
    timeout_seconds: int = DEFAULT_TIMEOUT,
) -> ContainerResult:
    docker = docker_command()
    image_ref = f"{config.image}@{config.image_digest}" if config.image_digest else config.image

    args = [
        docker,
        "run",
        "--rm",
        "--user",
        "1000:1000",
    ]

    if config.read_only:
        args.extend(["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m"])  # nosec B108  # noqa: S108

    if config.network_disabled:
        args.extend(["--network", "none"])

    if config.no_new_privileges:
        args.append("--security-opt=no-new-privileges")

    if config.memory_limit:
        args.extend(["--memory", config.memory_limit])

    if config.cpu_limit:
        args.extend(["--cpus", config.cpu_limit])

    args.extend(
        [
            "-v",
            f"{repo_path.resolve()}:/repo:ro",
            "-v",
            f"{output_path.resolve()}:/output:rw",
            "-w",
            "/repo",
            image_ref,
        ]
    )
    args.extend(command)

    start = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603  # nosec B603
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        return ContainerResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_ms=duration_ms,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return ContainerResult(
            exit_code=124,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=True,
        )


def pull_image(image: str, digest: str | None = None) -> bool:
    docker = docker_command()
    ref = f"{image}@{digest}" if digest else image
    proc = subprocess.run(  # noqa: S603  # nosec B603
        [docker, "pull", ref],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return proc.returncode == 0
