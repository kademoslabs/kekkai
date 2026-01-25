from __future__ import annotations

import sys
from pathlib import Path

import pytest

from kekkai.config import PipelineStep
from kekkai.runner import run_step


def test_runner_env_allowlist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOWED", "ok")
    monkeypatch.setenv("BLOCKED", "no")
    step = PipelineStep(
        name="env-check",
        args=[
            sys.executable,
            "-c",
            "import os; print(os.environ.get('ALLOWED', ''), os.environ.get('BLOCKED', ''))",
        ],
    )

    result = run_step(step, cwd=tmp_path, env_allowlist=["ALLOWED"], timeout_seconds=5)
    assert result.exit_code == 0
    assert result.stdout.strip() == "ok"


def test_runner_rejects_non_list_args(tmp_path: Path) -> None:
    step = PipelineStep(name="bad", args=["echo", "ok"])
    object.__setattr__(step, "args", "echo ok")
    with pytest.raises(ValueError):
        run_step(step, cwd=tmp_path, env_allowlist=[], timeout_seconds=1)


def test_runner_timeout(tmp_path: Path) -> None:
    step = PipelineStep(
        name="sleep",
        args=[sys.executable, "-c", "import time; time.sleep(0.2)"],
    )
    result = run_step(step, cwd=tmp_path, env_allowlist=[], timeout_seconds=0)
    assert result.timed_out is True
    assert result.exit_code == 124
