from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.dojo import build_compose_yaml

pytestmark = pytest.mark.regression


def test_compose_fixture_matches() -> None:
    fixture = Path(__file__).parent / "fixtures" / "dojo-compose.yml"
    assert build_compose_yaml() == fixture.read_text()
