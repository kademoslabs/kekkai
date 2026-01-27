"""GitHub PR commenter for posting scan findings."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx  # type: ignore[import-not-found,unused-ignore]

from ..scanners.base import Finding, Severity
from .models import GitHubConfig, PRComment, PRCommentResult
from .sanitizer import escape_markdown, redact_secrets

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

MAX_COMMENTS_PER_PR = 50
SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "🔵",
    Severity.UNKNOWN: "⚪",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def post_pr_comments(
    findings: Sequence[Finding],
    config: GitHubConfig,
    max_comments: int = MAX_COMMENTS_PER_PR,
    min_severity: str = "medium",
    timeout: float = 60.0,
) -> PRCommentResult:
    """Post findings as PR review comments.

    Args:
        findings: List of findings to post.
        config: GitHub API configuration.
        max_comments: Maximum number of comments to post.
        min_severity: Minimum severity level to include.
        timeout: HTTP request timeout in seconds.

    Returns:
        Result containing success status and counts.
    """
    # Filter and prepare comments
    filtered = _filter_findings(findings, min_severity)
    deduped = _dedupe_by_location(filtered)
    limited = deduped[:max_comments]

    if not limited:
        return PRCommentResult(
            success=True,
            comments_posted=0,
            comments_skipped=len(findings) - len(limited),
        )

    # Build comments for findings with file paths
    comments = []
    skipped = 0
    for finding in limited:
        if not finding.file_path:
            skipped += 1
            continue
        comment = PRComment(
            path=finding.file_path,
            line=finding.line or 1,
            body=_format_comment(finding),
        )
        comments.append(comment)

    if not comments:
        return PRCommentResult(
            success=True,
            comments_posted=0,
            comments_skipped=len(findings),
        )

    # Post review with comments
    try:
        review_url = _create_review(config, comments, timeout)
        return PRCommentResult(
            success=True,
            comments_posted=len(comments),
            comments_skipped=len(findings) - len(comments),
            review_url=review_url,
        )
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error: %s", e.response.text)
        return PRCommentResult(
            success=False,
            errors=[f"GitHub API error: {e.response.status_code}"],
        )
    except httpx.RequestError as e:
        logger.error("Request error: %s", e)
        return PRCommentResult(
            success=False,
            errors=[f"Request failed: {e!s}"],
        )


def _create_review(
    config: GitHubConfig,
    comments: list[PRComment],
    timeout: float,
) -> str | None:
    """Create a PR review with inline comments."""
    url = f"{config.api_base}/repos/{config.owner}/{config.repo}/pulls/{config.pr_number}/reviews"

    headers = {
        "Authorization": f"Bearer {config.token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    payload = {
        "event": "COMMENT",
        "body": _format_summary(len(comments)),
        "comments": [c.to_dict() for c in comments],
    }

    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data: dict[str, str] = response.json()
        return data.get("html_url")


def _format_comment(finding: Finding) -> str:
    """Format a finding as a safe markdown comment."""
    emoji = SEVERITY_EMOJI.get(finding.severity, "⚪")
    severity_text = finding.severity.value.upper()

    # Sanitize user-controlled content
    title = escape_markdown(finding.title)
    description = redact_secrets(finding.description)
    description = escape_markdown(description[:500])

    lines = [
        f"### {emoji} {severity_text}: {title}",
        "",
        f"**Scanner:** {escape_markdown(finding.scanner)}",
    ]

    if finding.rule_id:
        # Rule IDs in code blocks don't need escaping, but sanitize backticks
        rule_id = finding.rule_id.replace("`", "'")
        lines.append(f"**Rule:** `{rule_id}`")

    if finding.cve:
        cve = finding.cve.replace("`", "'")
        lines.append(f"**CVE:** `{cve}`")

    if finding.cwe:
        cwe = finding.cwe.replace("`", "'")
        lines.append(f"**CWE:** `{cwe}`")

    lines.extend(["", description, ""])
    lines.append("---")
    lines.append("<sub>Posted by [Kekkai](https://github.com/kademoslabs/kekkai)</sub>")

    return "\n".join(lines)


def _format_summary(count: int) -> str:
    """Format the review summary body."""
    return f"🛡️ **Kekkai Security Scan** found {count} finding(s) in this PR."


def _filter_findings(
    findings: Sequence[Finding],
    min_severity: str,
) -> list[Finding]:
    """Filter findings by minimum severity level."""
    try:
        min_idx = SEVERITY_ORDER.index(min_severity.lower())
    except ValueError:
        min_idx = 2  # Default to medium

    return [f for f in findings if SEVERITY_ORDER.index(f.severity.value.lower()) <= min_idx]


def _dedupe_by_location(findings: Sequence[Finding]) -> list[Finding]:
    """Deduplicate findings by file path and line number."""
    seen: set[tuple[str | None, int | None]] = set()
    result: list[Finding] = []

    for finding in findings:
        key = (finding.file_path, finding.line)
        if key not in seen:
            seen.add(key)
            result.append(finding)

    return result
