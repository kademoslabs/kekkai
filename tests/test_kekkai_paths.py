from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.paths import app_base_dir, is_within_base, safe_join


def test_safe_join_blocks_traversal(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(ValueError):
        safe_join(base, "..", "escape")


def test_safe_join_allows_child(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    child = safe_join(base, "runs", "run-1")
    assert child == base / "runs" / "run-1"


def test_app_base_dir_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custom = tmp_path / "custom"
    monkeypatch.setenv("KEKKAI_HOME", str(custom))
    assert app_base_dir() == custom.resolve()


def test_is_within_base(tmp_path: Path) -> None:
    base = tmp_path / "base"
    child = base / "child"
    child.mkdir(parents=True)

    assert is_within_base(base, child) is True
    assert is_within_base(base, tmp_path / "elsewhere") is False
