"""Data models for GitHub PR commenter."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GitHubConfig:
    """Configuration for GitHub API access."""

    token: str
    owner: str
    repo: str
    pr_number: int
    api_base: str = "https://api.github.com"

    def __post_init__(self) -> None:
        if not self.token:
            raise ValueError("GitHub token is required")
        if not self.owner:
            raise ValueError("Repository owner is required")
        if not self.repo:
            raise ValueError("Repository name is required")
        if self.pr_number < 1:
            raise ValueError("PR number must be positive")


@dataclass(frozen=True)
class PRComment:
    """A comment to post on a PR."""

    path: str
    line: int
    body: str
    side: str = "RIGHT"

    def to_dict(self) -> dict[str, str | int]:
        """Convert to GitHub API format."""
        return {
            "path": self.path,
            "line": self.line,
            "body": self.body,
            "side": self.side,
        }


@dataclass
class PRCommentResult:
    """Result of posting PR comments."""

    success: bool
    comments_posted: int = 0
    comments_skipped: int = 0
    errors: list[str] = field(default_factory=list)
    review_url: str | None = None
