from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from kekkai import cli
from kekkai.cli import main
from kekkai.scanners.base import Finding, Severity


def test_main_no_args_initializes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / "kekkai_home"
    monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

    assert main([]) == 0
    assert (base_dir / "kekkai.toml").exists()


def test_main_no_args_with_existing_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / "kekkai_home"
    monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

    assert main(["init"]) == 0
    config_path = base_dir / "kekkai.toml"
    original = config_path.read_text()

    assert main([]) == 0
    assert config_path.read_text() == original


def test_resolve_run_id_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEKKAI_RUN_ID", "fixed-run")
    assert cli._resolve_run_id(None) == "fixed-run"


def test_resolve_run_dir_within_base(tmp_path: Path) -> None:
    base_dir = tmp_path / "base"
    run_base = base_dir / "runs"
    run_base.mkdir(parents=True)

    run_dir = cli._resolve_run_dir(base_dir, run_base, "run-1", None)
    assert run_dir == run_base / "run-1"


def test_scan_invalid_run_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / "kekkai_home"
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    monkeypatch.setenv("KEKKAI_HOME", str(base_dir))
    assert main(["init"]) == 0

    exit_code = main(["scan", "--repo", str(repo_dir), "--run-id", "!!"])
    assert exit_code == 1


def test_doctor_json(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    docker_ok = lambda force_check=False: (True, "Docker available")  # noqa: E731
    monkeypatch.setattr(cli, "docker_available", docker_ok)

    class _Info:
        path = "/usr/bin/tool"
        version = "1.2.3"

    monkeypatch.setattr(cli, "detect_tool", lambda tool: _Info())
    assert main(["doctor", "--json"]) == 0
    out = capsys.readouterr().out
    assert '"docker"' in out
    assert '"trivy"' in out


def test_doctor_strict_fails_when_core_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker_fail = lambda force_check=False: (False, "Docker missing")  # noqa: E731
    monkeypatch.setattr(cli, "docker_available", docker_fail)
    monkeypatch.setattr(
        cli,
        "detect_tool",
        lambda tool: (_ for _ in ()).throw(cli.ToolNotFoundError("missing")),
    )
    assert main(["doctor", "--strict"]) == 1


def test_filter_findings_new_since_baseline(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    finding_old = Finding(
        scanner="semgrep",
        title="SQLi",
        severity=Severity.HIGH,
        description="old",
        file_path="app.py",
        line=10,
        rule_id="rule.old",
    )
    finding_new = Finding(
        scanner="semgrep",
        title="XSS",
        severity=Severity.MEDIUM,
        description="new",
        file_path="app.py",
        line=20,
        rule_id="rule.new",
    )
    baseline.write_text(
        json.dumps({"findings": [{"id": finding_old.dedupe_hash()}]}),
        encoding="utf-8",
    )
    filtered = cli._filter_findings_new_since_baseline([finding_old, finding_new], baseline)
    assert len(filtered) == 1
    assert filtered[0].title == "XSS"


def test_write_run_provenance_includes_sha256(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    artifact = run_dir / "kekkai-report.json"
    artifact.write_text('{"ok": true}', encoding="utf-8")
    out = cli._write_run_provenance(
        run_dir=run_dir,
        run_id="run-1",
        repo_path=tmp_path,
        commit_sha="abc123",
        artifacts=[artifact],
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["run_id"] == "run-1"
    assert data["attestation_subjects"][0]["name"] == "kekkai-report.json"
    assert len(data["attestation_subjects"][0]["sha256"]) == 64


def test_resolve_provider_api_key_prefers_provider_specific(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KEKKAI_OPENAI_API_KEY", "provider-key")
    monkeypatch.setenv("KEKKAI_THREATFLOW_API_KEY", "generic-key")
    resolved = cli._resolve_provider_api_key(
        provider="openai",
        generic_env_key="KEKKAI_THREATFLOW_API_KEY",
        env_overlay={},
    )
    assert resolved == "provider-key"


def test_threatflow_mode_resolves_from_dotenv_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KEKKAI_THREATFLOW_MODE in repo .env must apply without exporting to the shell."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("KEKKAI_THREATFLOW_MODE=gemini\n", encoding="utf-8")
    monkeypatch.delenv("KEKKAI_THREATFLOW_MODE", raising=False)
    overlay = cli._load_kekkai_env_overlay(repo)
    assert overlay.get("KEKKAI_THREATFLOW_MODE") == "gemini"
    model_mode_raw = (
        None or os.environ.get("KEKKAI_THREATFLOW_MODE") or overlay.get("KEKKAI_THREATFLOW_MODE")
    )
    assert model_mode_raw == "gemini"
