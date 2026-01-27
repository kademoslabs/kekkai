"""Integration tests for GitHub PR API interactions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from kekkai.github.commenter import post_pr_comments
from kekkai.github.models import GitHubConfig
from kekkai.scanners.base import Finding, Severity


@pytest.mark.integration
class TestGitHubPRApi:
    """Integration tests for GitHub PR API."""

    def _make_config(self) -> GitHubConfig:
        """Create test config."""
        return GitHubConfig(
            token="test-token",
            owner="kademoslabs",
            repo="kekkai",
            pr_number=123,
        )

    def _make_findings(self, count: int) -> list[Finding]:
        """Create test findings."""
        return [
            Finding(
                scanner="trivy",
                title=f"CVE-2024-{i:04d}",
                severity=Severity.HIGH,
                description=f"Vulnerable package {i}",
                file_path=f"src/module{i}.py",
                line=i * 10,
                cve=f"CVE-2024-{i:04d}",
            )
            for i in range(count)
        ]

    @patch("kekkai.github.commenter.httpx.Client")
    def test_creates_review_with_comments(self, mock_client_class: MagicMock) -> None:
        """Creates a PR review with inline comments."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "html_url": "https://github.com/kademoslabs/kekkai/pull/123#pullrequestreview-456"
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        findings = self._make_findings(3)
        config = self._make_config()

        result = post_pr_comments(findings, config)

        assert result.success is True
        assert result.comments_posted == 3

        # Verify API call
        call_args = mock_client.post.call_args
        assert "/repos/kademoslabs/kekkai/pulls/123/reviews" in call_args[0][0]

        payload = call_args[1]["json"]
        assert payload["event"] == "COMMENT"
        assert len(payload["comments"]) == 3
        assert "Kekkai Security Scan" in payload["body"]

    @patch("kekkai.github.commenter.httpx.Client")
    def test_comment_structure(self, mock_client_class: MagicMock) -> None:
        """Comment structure matches GitHub API expectations."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"html_url": "http://test"}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        findings = [
            Finding(
                scanner="semgrep",
                title="SQL Injection",
                severity=Severity.CRITICAL,
                description="User input concatenated in SQL",
                file_path="app/db.py",
                line=42,
                rule_id="python.lang.security.audit.sqli",
                cwe="CWE-89",
            )
        ]
        config = self._make_config()

        post_pr_comments(findings, config)

        payload = mock_client.post.call_args[1]["json"]
        comment = payload["comments"][0]

        assert comment["path"] == "app/db.py"
        assert comment["line"] == 42
        assert "🔴 CRITICAL" in comment["body"]
        assert "SQL Injection" in comment["body"]
        assert "semgrep" in comment["body"]
        assert "CWE-89" in comment["body"]

    @patch("kekkai.github.commenter.httpx.Client")
    def test_authorization_header(self, mock_client_class: MagicMock) -> None:
        """Authorization header is set correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"html_url": "http://test"}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        config = GitHubConfig(
            token="ghp_secrettoken123",
            owner="test",
            repo="repo",
            pr_number=1,
        )
        findings = self._make_findings(1)

        post_pr_comments(findings, config)

        headers = mock_client.post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer ghp_secrettoken123"
        assert headers["Accept"] == "application/vnd.github.v3+json"

    @patch("kekkai.github.commenter.httpx.Client")
    def test_handles_rate_limit(self, mock_client_class: MagicMock) -> None:
        """Handles GitHub rate limiting gracefully."""
        import httpx  # type: ignore[import-not-found,unused-ignore]

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "API rate limit exceeded"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "403", request=MagicMock(), response=mock_response
        )

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        findings = self._make_findings(1)
        config = self._make_config()

        result = post_pr_comments(findings, config)

        assert result.success is False
        assert any("403" in e for e in result.errors)

    @patch("kekkai.github.commenter.httpx.Client")
    def test_handles_not_found(self, mock_client_class: MagicMock) -> None:
        """Handles PR not found error."""
        import httpx  # type: ignore[import-not-found,unused-ignore]

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=mock_response
        )

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        findings = self._make_findings(1)
        config = self._make_config()

        result = post_pr_comments(findings, config)

        assert result.success is False
        assert any("404" in e for e in result.errors)

    @patch("kekkai.github.commenter.httpx.Client")
    def test_custom_api_base(self, mock_client_class: MagicMock) -> None:
        """Supports custom API base for GitHub Enterprise."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"html_url": "http://test"}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        config = GitHubConfig(
            token="token",
            owner="corp",
            repo="app",
            pr_number=1,
            api_base="https://github.corp.example.com/api/v3",
        )
        findings = self._make_findings(1)

        post_pr_comments(findings, config)

        call_url = mock_client.post.call_args[0][0]
        assert call_url.startswith("https://github.corp.example.com/api/v3")


@pytest.mark.integration
class TestEndToEndWorkflow:
    """End-to-end workflow tests."""

    @patch("kekkai.github.commenter.httpx.Client")
    def test_full_workflow_with_mixed_findings(self, mock_client_class: MagicMock) -> None:
        """Full workflow with mixed severity findings."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "html_url": "https://github.com/test/repo/pull/1#pullrequestreview-999"
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        # Mixed findings: some will be filtered, some without file_path
        findings = [
            Finding(
                scanner="t",
                title="Critical",
                severity=Severity.CRITICAL,
                description="",
                file_path="a.py",
                line=1,
            ),
            Finding(
                scanner="t",
                title="High",
                severity=Severity.HIGH,
                description="",
                file_path="b.py",
                line=2,
            ),
            Finding(
                scanner="t",
                title="Medium",
                severity=Severity.MEDIUM,
                description="",
                file_path="c.py",
                line=3,
            ),
            Finding(
                scanner="t",
                title="Low",
                severity=Severity.LOW,
                description="",
                file_path="d.py",
                line=4,
            ),
            Finding(
                scanner="t",
                title="No Path",
                severity=Severity.HIGH,
                description="",
                file_path=None,
                line=None,
            ),
        ]

        config = GitHubConfig(
            token="token",
            owner="test",
            repo="repo",
            pr_number=1,
        )

        result = post_pr_comments(findings, config, min_severity="medium")

        assert result.success is True
        # 3 findings pass filter, 1 has no path
        assert result.comments_posted == 3
        assert result.comments_skipped == 2
        assert result.review_url is not None
