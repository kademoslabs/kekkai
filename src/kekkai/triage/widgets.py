"""Custom Textual widgets for triage TUI.

Provides security-focused widgets with content sanitization
and consistent styling.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.widgets import Static

if TYPE_CHECKING:
    from .models import FindingEntry, Severity, TriageState

__all__ = [
    "SeverityBadge",
    "FindingCard",
    "StateBadge",
]

SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold white on red",
    "high": "bold white on dark_orange",
    "medium": "bold black on yellow",
    "low": "bold white on blue",
    "info": "dim white on grey37",
}

STATE_STYLES: dict[str, str] = {
    "pending": "dim white",
    "false_positive": "green",
    "confirmed": "red",
    "deferred": "yellow",
}

STATE_LABELS: dict[str, str] = {
    "pending": "Pending",
    "false_positive": "False Positive",
    "confirmed": "Confirmed",
    "deferred": "Deferred",
}


def sanitize_display(text: str, max_length: int = 200) -> str:
    """Sanitize text for terminal display.

    Removes ANSI escape sequences and truncates to max length.

    Args:
        text: Text to sanitize.
        max_length: Maximum length.

    Returns:
        Sanitized text.
    """
    import re

    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)
    text = text.replace("\n", " ").replace("\r", "")

    if len(text) > max_length:
        text = text[: max_length - 3] + "..."

    return text


class SeverityBadge(Static):
    """A badge displaying severity level with appropriate styling."""

    def __init__(self, severity: Severity, name: str | None = None, id: str | None = None) -> None:
        super().__init__(name=name, id=id)
        self.severity = severity

    def render(self) -> Text:
        """Render the severity badge."""
        style = SEVERITY_STYLES.get(self.severity.value, "dim")
        label = f" {self.severity.value.upper()} "
        return Text(label, style=style)


class StateBadge(Static):
    """A badge displaying triage state."""

    def __init__(self, state: TriageState, name: str | None = None, id: str | None = None) -> None:
        super().__init__(name=name, id=id)
        self.state = state

    def render(self) -> Text:
        """Render the state badge."""
        style = STATE_STYLES.get(self.state.value, "dim")
        label = STATE_LABELS.get(self.state.value, self.state.value)
        return Text(f"[{label}]", style=style)


class FindingCard(Static):
    """A card displaying a security finding summary.

    Sanitizes all content before display to prevent terminal injection.
    """

    DEFAULT_CSS = """
    FindingCard {
        padding: 1;
        margin: 0 0 1 0;
        border: solid $primary;
        background: $surface;
    }
    FindingCard:hover {
        border: solid $secondary;
    }
    FindingCard.selected {
        border: double $accent;
        background: $surface-darken-1;
    }
    """

    def __init__(
        self,
        finding: FindingEntry,
        selected: bool = False,
        name: str | None = None,
        id: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id)
        self.finding = finding
        self.selected = selected
        if selected:
            self.add_class("selected")

    def render(self) -> Text:
        """Render the finding card."""
        text = Text()

        severity_style = SEVERITY_STYLES.get(self.finding.severity.value, "dim")
        text.append(f" {self.finding.severity.value.upper()} ", style=severity_style)
        text.append(" ")

        state_style = STATE_STYLES.get(self.finding.state.value, "dim")
        state_label = STATE_LABELS.get(self.finding.state.value, "")
        text.append(f"[{state_label}]", style=state_style)
        text.append("\n")

        title = sanitize_display(self.finding.title, max_length=80)
        text.append(title, style="bold")
        text.append("\n")

        scanner = sanitize_display(self.finding.scanner)
        rule_id = sanitize_display(self.finding.rule_id)
        text.append(f"Scanner: {scanner}", style="dim")
        if rule_id:
            text.append(f" | Rule: {rule_id}", style="dim")
        text.append("\n")

        if self.finding.file_path:
            file_path = sanitize_display(self.finding.file_path, max_length=60)
            line_info = f":{self.finding.line}" if self.finding.line else ""
            text.append(f"File: {file_path}{line_info}", style="cyan")

        return text

    def set_selected(self, selected: bool) -> None:
        """Update selection state."""
        self.selected = selected
        if selected:
            self.add_class("selected")
        else:
            self.remove_class("selected")
