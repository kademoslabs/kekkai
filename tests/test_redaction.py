from kekkai_core import redact


def test_redact_key_value() -> None:
    s = "api_key=abcd1234 token: zzzz password=passw0rd"
    out = redact(s)
    assert "abcd1234" not in out
    assert "zzzz" not in out
    assert "passw0rd" not in out
    assert "[REDACTED]" in out


def test_redact_bearer() -> None:
    s = "Authorization: Bearer abc.def.ghi"
    out = redact(s)
    assert "abc.def.ghi" not in out
