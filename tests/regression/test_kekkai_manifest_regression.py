import json
from dataclasses import asdict
from pathlib import Path

import pytest

from kekkai.manifest import build_manifest
from kekkai.runner import StepResult


@pytest.mark.regression
def test_run_manifest_schema_snapshot() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "kekkai-run-manifest.json"
    expected = json.loads(fixture_path.read_text())

    step = StepResult(
        name="echo",
        args=["echo", "hello"],
        exit_code=0,
        duration_ms=120,
        stdout="hello",
        stderr="",
        timed_out=False,
    )

    manifest = build_manifest(
        run_id="fixed-run",
        repo_path=Path("/tmp/repo"),
        run_dir=Path("/tmp/kekkai/runs/fixed-run"),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        steps=[step],
    )

    assert json.loads(json.dumps(asdict(manifest), sort_keys=True)) == expected
