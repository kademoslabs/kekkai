from __future__ import annotations

import json
from pathlib import Path

from kekkai.manifest import build_manifest, write_manifest
from kekkai.runner import StepResult


def test_write_manifest(tmp_path: Path) -> None:
    step = StepResult(
        name="step",
        args=["echo", "ok"],
        exit_code=0,
        duration_ms=10,
        stdout="ok",
        stderr="",
        timed_out=False,
    )
    manifest = build_manifest(
        run_id="run-1",
        repo_path=tmp_path,
        run_dir=tmp_path / "runs" / "run-1",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        steps=[step],
    )
    output = tmp_path / "run.json"
    write_manifest(output, manifest)

    data = json.loads(output.read_text())
    assert data["status"] == "success"
    assert data["steps"][0]["name"] == "step"
