from __future__ import annotations

from pathlib import Path

from kekkai.config import ConfigOverrides, load_config


def test_config_precedence(tmp_path: Path) -> None:
    base = tmp_path / "home"
    base.mkdir()
    config_path = base / "kekkai.toml"
    config_path.write_text(
        'repo_path = "from_file"\n'
        'run_base_dir = "runs"\n'
        "timeout_seconds = 300\n"
        'env_allowlist = ["FILE"]\n'
    )

    env = {
        "KEKKAI_REPO_PATH": "from_env",
        "KEKKAI_TIMEOUT_SECONDS": "120",
        "KEKKAI_ENV_ALLOWLIST": "ENV1,ENV2",
    }
    overrides = ConfigOverrides(repo_path=Path("from_flag"))

    cfg = load_config(config_path, env=env, overrides=overrides, base_dir=base)

    assert cfg.repo_path == Path("from_flag")
    assert cfg.timeout_seconds == 120
    assert cfg.env_allowlist == ["ENV1", "ENV2"]
    assert cfg.run_base_dir == Path("runs")


def test_load_config_pipeline(tmp_path: Path) -> None:
    config_path = tmp_path / "kekkai.toml"
    config_path.write_text(
        'repo_path = "."\n'
        'run_base_dir = "runs"\n'
        "timeout_seconds = 10\n"
        'env_allowlist = ["PATH"]\n'
        "\n"
        "[[pipeline]]\n"
        'name = "echo"\n'
        'args = ["echo", "hello"]\n'
    )

    cfg = load_config(config_path, base_dir=tmp_path)

    assert cfg.pipeline[0].name == "echo"
    assert cfg.pipeline[0].args == ["echo", "hello"]
