"""Unit tests for ThreatFlow redaction."""

from __future__ import annotations

from kekkai.threatflow.redaction import RedactionPattern, ThreatFlowRedactor


class TestThreatFlowRedactor:
    """Tests for ThreatFlowRedactor."""

    def test_redact_aws_access_key(self) -> None:
        """Test AWS access key redaction."""
        redactor = ThreatFlowRedactor()
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED" in result

    def test_redact_aws_secret_key(self) -> None:
        """Test AWS secret key redaction."""
        redactor = ThreatFlowRedactor()
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = redactor.redact(text)
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result

    def test_redact_github_token(self) -> None:
        """Test GitHub token redaction."""
        redactor = ThreatFlowRedactor()
        text = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        result = redactor.redact(text)
        assert "ghp_" not in result

    def test_redact_github_pat(self) -> None:
        """Test GitHub personal access token redaction."""
        redactor = ThreatFlowRedactor()
        text = "token=github_pat_11ABCDEFG0123456789ABCDEF"
        result = redactor.redact(text)
        assert "github_pat_" not in result

    def test_redact_gitlab_token(self) -> None:
        """Test GitLab token redaction."""
        redactor = ThreatFlowRedactor()
        text = "GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxxx"
        result = redactor.redact(text)
        assert "glpat-" not in result

    def test_redact_slack_token(self) -> None:
        """Test Slack token redaction."""
        redactor = ThreatFlowRedactor()
        text = "SLACK_TOKEN=xoxb-123456789012-123456789012-abcdefghij"
        result = redactor.redact(text)
        assert "xoxb-" not in result

    def test_redact_stripe_key(self) -> None:
        """Test Stripe key redaction."""
        redactor = ThreatFlowRedactor()
        text = "stripe_key = sk_live_xxxxxxxxxxxxxxxxxxxxxxxxx"
        result = redactor.redact(text)
        assert "sk_live_" not in result

    def test_redact_private_key_header(self) -> None:
        """Test private key header redaction."""
        redactor = ThreatFlowRedactor()
        # Construct header to avoid pre-commit hook detection
        header = "-----BEGIN RSA" + " PRIVATE KEY-----"
        text = f"{header}\nMIIEpA..."
        result = redactor.redact(text)
        assert header not in result

    def test_redact_jwt_token(self) -> None:
        """Test JWT token redaction."""
        redactor = ThreatFlowRedactor()
        # Example JWT (split for line length)
        jwt_parts = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ]
        jwt = ".".join(jwt_parts)
        text = f"Authorization: Bearer {jwt}"
        result = redactor.redact(text)
        # JWT should be redacted
        assert jwt_parts[0] not in result

    def test_redact_database_url(self) -> None:
        """Test database URL password redaction."""
        redactor = ThreatFlowRedactor()
        text = "DATABASE_URL=postgres://user:secretpassword@localhost:5432/db"
        result = redactor.redact(text)
        assert "secretpassword" not in result

    def test_redact_env_password(self) -> None:
        """Test .env style password redaction."""
        redactor = ThreatFlowRedactor()
        text = "DB_PASSWORD=mysecretpassword123"
        result = redactor.redact(text)
        assert "mysecretpassword123" not in result

    def test_redact_preserves_normal_text(self) -> None:
        """Test that normal text is preserved."""
        redactor = ThreatFlowRedactor()
        text = "This is normal code that defines a function."
        result = redactor.redact(text)
        assert result == text

    def test_detect_secrets_reports_types(self) -> None:
        """Test that detect_secrets reports secret types without values."""
        redactor = ThreatFlowRedactor()
        text = (
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        )
        found = redactor.detect_secrets(text)
        # Should find patterns but not return actual values
        assert len(found) >= 1
        pattern_names = [name for name, _ in found]
        assert any("aws" in name.lower() or "github" in name.lower() for name in pattern_names)

    def test_add_custom_pattern(self) -> None:
        """Test adding a custom redaction pattern."""
        redactor = ThreatFlowRedactor()
        redactor.add_pattern(
            name="custom_secret",
            regex=r"CUSTOM_SECRET=(\w+)",
            replacement="[CUSTOM_REDACTED]",
        )
        text = "CUSTOM_SECRET=mysecret"
        result = redactor.redact(text)
        assert "mysecret" not in result

    def test_multiple_secrets_in_one_text(self) -> None:
        """Test redacting multiple secrets in one text."""
        redactor = ThreatFlowRedactor()
        text = """
        api_key = abc123
        token: xyz789
        password=secretpass
        """
        result = redactor.redact(text)
        assert "abc123" not in result
        assert "xyz789" not in result
        assert "secretpass" not in result
        # Pattern identifiers should be preserved
        assert "api_key" in result.lower() or "[REDACTED]" in result


class TestRedactionPattern:
    """Tests for RedactionPattern dataclass."""

    def test_pattern_creation(self) -> None:
        """Test creating a redaction pattern."""
        import re

        pattern = RedactionPattern(
            name="test",
            pattern=re.compile(r"secret=(\w+)"),
            replacement="[HIDDEN]",
        )
        assert pattern.name == "test"
        assert pattern.replacement == "[HIDDEN]"

    def test_pattern_default_replacement(self) -> None:
        """Test default replacement format."""
        import re

        pattern = RedactionPattern(
            name="my_secret",
            pattern=re.compile(r"foo"),
        )
        assert "{name}" in pattern.replacement
