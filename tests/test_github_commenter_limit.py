"""Unit tests for GitHub PR comment rate limiting."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from kekkai.github.commenter import MAX_COMMENTS_PER_PR, post_pr_comments
from kekkai.github.models import GitHubConfig
from kekkai.scanners.base import Finding, Severity


def _make_finding(idx: int) -> Finding:
    """Helper to create a test finding."""
    return Finding(
        scanner="test",
        title=f"Finding {idx}",
        severity=Severity.HIGH,
        description=f"Description {idx}",
        file_path=f"file{idx}.py",
        line=idx,
    )


def _make_config() -> GitHubConfig:
    """Helper to create test config."""
    return GitHubConfig(
        token="test-token",
        owner="test-owner",
        repo="test-repo",
        pr_number=1,
    )


class TestRateLimiting:
    """Tests for comment rate limiting."""

    def test_max_comments_constant(self) -> None:
        """MAX_COMMENTS_PER_PR is 50."""
        assert MAX_COMMENTS_PER_PR == 50

    @patch("kekkai.github.commenter._create_review")
    def test_limits_to_max_comments(self, mock_review: MagicMock) -> None:
        """Comments are limited to max_comments."""
        mock_review.return_value = "https://github.com/test/pr/1"

        findings = [_make_finding(i) for i in range(100)]
        config = _make_config()

        result = post_pr_comments(findings, config, max_comments=50)

        assert result.success is True
        assert result.comments_posted == 50
        assert result.comments_skipped == 50

    @patch("kekkai.github.commenter._create_review")
    def test_custom_max_comments(self, mock_review: MagicMock) -> None:
        """Custom max_comments is respected."""
        mock_review.return_value = "https://github.com/test/pr/1"

        findings = [_make_finding(i) for i in range(20)]
        config = _make_config()

        result = post_pr_comments(findings, config, max_comments=10)

        assert result.comments_posted == 10
        assert result.comments_skipped == 10

    @patch("kekkai.github.commenter._create_review")
    def test_fewer_than_max_posts_all(self, mock_review: MagicMock) -> None:
        """Fewer findings than max posts all."""
        mock_review.return_value = "https://github.com/test/pr/1"

        findings = [_make_finding(i) for i in range(5)]
        config = _make_config()

        result = post_pr_comments(findings, config, max_comments=50)

        assert result.comments_posted == 5
        assert result.comments_skipped == 0

    def test_empty_findings_no_api_call(self) -> None:
        """Empty findings don't call API."""
        config = _make_config()

        result = post_pr_comments([], config)

        assert result.success is True
        assert result.comments_posted == 0

    @patch("kekkai.github.commenter._create_review")
    def test_filters_before_limiting(self, mock_review: MagicMock) -> None:
        """Filtering happens before limiting."""
        mock_review.return_value = "https://github.com/test/pr/1"

        # 60 high, 40 low findings
        findings = [
            Finding(
                scanner="t",
                title=f"F{i}",
                severity=Severity.HIGH if i < 60 else Severity.LOW,
                description="",
                file_path=f"f{i}.py",
                line=i,
            )
            for i in range(100)
        ]
        config = _make_config()

        # Filter to high only, limit to 50
        result = post_pr_comments(
            findings,
            config,
            max_comments=50,
            min_severity="high",
        )

        # Should post 50 of the 60 high findings
        assert result.comments_posted == 50

    @patch("kekkai.github.commenter._create_review")
    def test_skipped_count_includes_no_path(self, mock_review: MagicMock) -> None:
        """Findings without file_path are counted as skipped."""
        mock_review.return_value = "https://github.com/test/pr/1"

        findings = [
            Finding(
                scanner="t",
                title="1",
                severity=Severity.HIGH,
                description="",
                file_path="a.py",
                line=1,
            ),
            Finding(
                scanner="t",
                title="2",
                severity=Severity.HIGH,
                description="",
                file_path=None,
                line=None,
            ),
            Finding(
                scanner="t",
                title="3",
                severity=Severity.HIGH,
                description="",
                file_path="b.py",
                line=2,
            ),
        ]
        config = _make_config()

        result = post_pr_comments(findings, config)

        assert result.comments_posted == 2
        assert result.comments_skipped == 1


class TestApiInteraction:
    """Tests for API interaction behavior."""

    @patch("kekkai.github.commenter._create_review")
    def test_returns_review_url(self, mock_review: MagicMock) -> None:
        """Successful post returns review URL."""
        mock_review.return_value = "https://github.com/owner/repo/pull/1#pullrequestreview-123"

        findings = [_make_finding(1)]
        config = _make_config()

        result = post_pr_comments(findings, config)

        assert result.review_url == "https://github.com/owner/repo/pull/1#pullrequestreview-123"

    @patch("kekkai.github.commenter.httpx.Client")
    def test_api_error_returns_failure(self, mock_client_class: MagicMock) -> None:
        """API error returns failure result."""
        import httpx  # type: ignore[import-not-found,unused-ignore]

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Rate limited"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "403", request=MagicMock(), response=mock_response
        )

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        findings = [_make_finding(1)]
        config = _make_config()

        result = post_pr_comments(findings, config)

        assert result.success is False
        assert len(result.errors) > 0
        assert "403" in result.errors[0]

    @patch("kekkai.github.commenter.httpx.Client")
    def test_network_error_returns_failure(self, mock_client_class: MagicMock) -> None:
        """Network error returns failure result."""
        import httpx  # type: ignore[import-not-found,unused-ignore]

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = httpx.ConnectError("Connection refused")
        mock_client_class.return_value = mock_client

        findings = [_make_finding(1)]
        config = _make_config()

        result = post_pr_comments(findings, config)

        assert result.success is False
        assert len(result.errors) > 0
