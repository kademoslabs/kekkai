from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from .runner import StepResult


@dataclass(frozen=True)
class RunManifest:
    schema_version: int
    run_id: str
    repo_path: str
    run_dir: str
    started_at: str
    finished_at: str
    status: str
    steps: list[dict[str, object]]


def build_manifest(
    *,
    run_id: str,
    repo_path: Path,
    run_dir: Path,
    started_at: str,
    finished_at: str,
    steps: Iterable[StepResult],
) -> RunManifest:
    step_entries = [
        {
            "name": step.name,
            "args": step.args,
            "exit_code": step.exit_code,
            "duration_ms": step.duration_ms,
            "stdout": step.stdout,
            "stderr": step.stderr,
            "timed_out": step.timed_out,
        }
        for step in steps
    ]
    status = "success" if all(step["exit_code"] == 0 for step in step_entries) else "failed"
    return RunManifest(
        schema_version=1,
        run_id=run_id,
        repo_path=str(repo_path),
        run_dir=str(run_dir),
        started_at=started_at,
        finished_at=finished_at,
        status=status,
        steps=step_entries,
    )


def write_manifest(path: Path, manifest: RunManifest) -> None:
    path.write_text(json.dumps(asdict(manifest), indent=2, sort_keys=True))
