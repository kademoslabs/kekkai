from __future__ import annotations

from urllib.parse import urlsplit

from .models import Checklist, ChecklistItem, CheckStatus


def generate_checklist(url: str, body: str | None) -> Checklist:
    parsed = urlsplit(url)
    normalized_body = (body or "").lower()

    items = [
        ChecklistItem(
            check_id="url-reachable",
            title="Target URL is reachable",
            status=CheckStatus.PASS,
            evidence="Fetch succeeded",
        ),
        ChecklistItem(
            check_id="https-enforced",
            title="HTTPS is enforced",
            status=CheckStatus.PASS if parsed.scheme == "https" else CheckStatus.FAIL,
            evidence=f"Scheme: {parsed.scheme}",
        ),
        ChecklistItem(
            check_id="support-contact",
            title="Support contact is discoverable",
            status=CheckStatus.PASS if "support" in normalized_body else CheckStatus.UNKNOWN,
            evidence="Detected keyword 'support'" if "support" in normalized_body else None,
        ),
        ChecklistItem(
            check_id="vuln-disclosure",
            title="Vulnerability disclosure information is present",
            status=(
                CheckStatus.PASS
                if "security.txt" in normalized_body
                or "vulnerability disclosure" in normalized_body
                else CheckStatus.UNKNOWN
            ),
            evidence=(
                "Detected security disclosure keywords"
                if "security.txt" in normalized_body
                or "vulnerability disclosure" in normalized_body
                else None
            ),
        ),
    ]

    return Checklist(url=url, items=items)
