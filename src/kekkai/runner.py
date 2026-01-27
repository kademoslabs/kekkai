from __future__ import annotations

import os
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path

from kekkai_core import redact

from .config import PipelineStep


@dataclass(frozen=True)
class StepResult:
    name: str
    args: list[str]
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    timed_out: bool


def run_step(
    step: PipelineStep,
    cwd: Path,
    env_allowlist: list[str],
    timeout_seconds: int,
) -> StepResult:
    if not isinstance(step.args, list) or not step.args:
        raise ValueError("step args must be a non-empty list")
    if not all(isinstance(arg, str) for arg in step.args):
        raise ValueError("step args must be strings")

    env = {key: os.environ[key] for key in env_allowlist if key in os.environ}
    start = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            step.args,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        return StepResult(
            name=step.name,
            args=list(step.args),
            exit_code=completed.returncode,
            duration_ms=duration_ms,
            stdout=redact(completed.stdout),
            stderr=redact(completed.stderr),
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        stdout = redact(exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or "")
        stderr = redact(exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr or "")
        return StepResult(
            name=step.name,
            args=list(step.args),
            exit_code=124,
            duration_ms=duration_ms,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        )
