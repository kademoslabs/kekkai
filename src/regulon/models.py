from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CheckStatus(str, Enum):
    PASS = "pass"  # noqa: S105  # nosec B105
    FAIL = "fail"  # noqa: S105
    UNKNOWN = "unknown"  # noqa: S105


@dataclass(frozen=True)
class ChecklistItem:
    check_id: str
    title: str
    status: CheckStatus
    evidence: str | None = None


@dataclass(frozen=True)
class Checklist:
    url: str
    items: list[ChecklistItem]
