import pathlib

import pytest

from kekkai_core import redact

pytestmark = pytest.mark.regression


def test_redaction_golden_snapshot(tmp_path: pathlib.Path) -> None:
    inp = "api_key=abcd1234\nAuthorization: Bearer abc.def.ghi\ntoken: zzzz\n"
    out = redact(inp)

    assert "abcd1234" not in out
    assert "abc.def.ghi" not in out
    assert "zzzz" not in out
    assert out.count("[REDACTED]") >= 2
