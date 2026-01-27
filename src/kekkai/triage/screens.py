"""Textual screens for triage TUI.

Provides screen components for finding list and detail views
with keyboard navigation and action handling.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, Static, TextArea

from .models import TriageState
from .widgets import FindingCard, sanitize_display

if TYPE_CHECKING:
    from collections.abc import Callable

    from .models import FindingEntry

__all__ = [
    "FindingListScreen",
    "FindingDetailScreen",
]


class FindingListScreen(Screen[None]):
    """Screen displaying paginated list of findings.

    Bindings:
        j/down: Move to next finding
        k/up: Move to previous finding
        enter: View finding details
        f: Mark as false positive
        c: Mark as confirmed
        d: Mark as deferred
        s: Save ignore file
        q: Quit
    """

    BINDINGS = [
        Binding("j", "cursor_down", "Next"),
        Binding("k", "cursor_up", "Previous"),
        Binding("down", "cursor_down", "Next", show=False),
        Binding("up", "cursor_up", "Previous", show=False),
        Binding("enter", "view_detail", "View"),
        Binding("f", "mark_false_positive", "False Positive"),
        Binding("c", "mark_confirmed", "Confirmed"),
        Binding("d", "mark_deferred", "Deferred"),
        Binding("ctrl+s", "save", "Save"),
        Binding("q", "quit", "Quit"),
    ]

    DEFAULT_CSS = """
    FindingListScreen {
        layout: vertical;
    }
    #finding-list {
        height: 1fr;
        padding: 1;
    }
    #status-bar {
        dock: bottom;
        height: 3;
        padding: 1;
        background: $surface;
        border-top: solid $primary;
    }
    """

    def __init__(
        self,
        findings: list[FindingEntry],
        on_state_change: Callable[[int, TriageState], None] | None = None,
        on_save: Callable[[], None] | None = None,
        name: str | None = None,
        id: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id)
        self.findings = findings
        self.selected_index = 0
        self.on_state_change = on_state_change
        self.on_save = on_save
        self._cards: list[FindingCard] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="finding-list"):
            for i, finding in enumerate(self.findings):
                card = FindingCard(finding, selected=(i == 0), id=f"card-{i}")
                self._cards.append(card)
                yield card
        yield Static(self._status_text(), id="status-bar")
        yield Footer()

    def _status_text(self) -> Text:
        """Generate status bar text."""
        total = len(self.findings)
        if total == 0:
            return Text("No findings to triage", style="dim")

        counts = {s: 0 for s in TriageState}
        for f in self.findings:
            counts[f.state] += 1

        text = Text()
        text.append(f"Total: {total} | ", style="bold")
        text.append(f"Pending: {counts[TriageState.PENDING]} | ")
        text.append(f"FP: {counts[TriageState.FALSE_POSITIVE]} | ", style="green")
        text.append(f"Confirmed: {counts[TriageState.CONFIRMED]} | ", style="red")
        text.append(f"Deferred: {counts[TriageState.DEFERRED]}", style="yellow")
        return text

    def _update_status(self) -> None:
        """Update status bar."""
        status_bar = self.query_one("#status-bar", Static)
        status_bar.update(self._status_text())

    def _update_selection(self, new_index: int) -> None:
        """Update visual selection."""
        if not self._cards:
            return

        old_index = self.selected_index
        self.selected_index = max(0, min(new_index, len(self._cards) - 1))

        if old_index < len(self._cards):
            self._cards[old_index].set_selected(False)
        if self.selected_index < len(self._cards):
            self._cards[self.selected_index].set_selected(True)
            self._cards[self.selected_index].scroll_visible()

    def action_cursor_down(self) -> None:
        """Move selection down."""
        self._update_selection(self.selected_index + 1)

    def action_cursor_up(self) -> None:
        """Move selection up."""
        self._update_selection(self.selected_index - 1)

    def action_view_detail(self) -> None:
        """Open detail view for selected finding."""
        if not self.findings:
            return
        finding = self.findings[self.selected_index]
        self.app.push_screen(
            FindingDetailScreen(
                finding,
                on_state_change=self._handle_detail_state_change,
            )
        )

    def _handle_detail_state_change(self, state: TriageState, notes: str) -> None:
        """Handle state change from detail screen."""
        if self.selected_index < len(self.findings):
            self.findings[self.selected_index].state = state
            self.findings[self.selected_index].notes = notes
            self._cards[self.selected_index].finding = self.findings[self.selected_index]
            self._cards[self.selected_index].refresh()
            self._update_status()
            if self.on_state_change:
                self.on_state_change(self.selected_index, state)

    def _mark_state(self, state: TriageState) -> None:
        """Mark selected finding with given state."""
        if not self.findings:
            return
        self.findings[self.selected_index].state = state
        self._cards[self.selected_index].finding = self.findings[self.selected_index]
        self._cards[self.selected_index].refresh()
        self._update_status()
        if self.on_state_change:
            self.on_state_change(self.selected_index, state)

    def action_mark_false_positive(self) -> None:
        """Mark as false positive."""
        self._mark_state(TriageState.FALSE_POSITIVE)

    def action_mark_confirmed(self) -> None:
        """Mark as confirmed."""
        self._mark_state(TriageState.CONFIRMED)

    def action_mark_deferred(self) -> None:
        """Mark as deferred."""
        self._mark_state(TriageState.DEFERRED)

    def action_save(self) -> None:
        """Save ignore file."""
        if self.on_save:
            self.on_save()
        self.notify("Ignore file saved", severity="information")

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()


class FindingDetailScreen(Screen[None]):
    """Screen showing full finding details with notes editing.

    Bindings:
        f: Mark as false positive
        c: Mark as confirmed
        d: Mark as deferred
        escape: Go back
    """

    BINDINGS = [
        Binding("f", "mark_false_positive", "False Positive"),
        Binding("c", "mark_confirmed", "Confirmed"),
        Binding("d", "mark_deferred", "Deferred"),
        Binding("escape", "go_back", "Back"),
    ]

    DEFAULT_CSS = """
    FindingDetailScreen {
        layout: vertical;
    }
    #detail-container {
        padding: 2;
    }
    #detail-header {
        height: auto;
        margin-bottom: 1;
    }
    #detail-content {
        height: 1fr;
        padding: 1;
        border: solid $primary;
    }
    #notes-area {
        height: 8;
        margin-top: 1;
        border: solid $secondary;
    }
    """

    def __init__(
        self,
        finding: FindingEntry,
        on_state_change: Callable[[TriageState, str], None] | None = None,
        name: str | None = None,
        id: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id)
        self.finding = finding
        self.on_state_change = on_state_change

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="detail-container"):
            yield Static(self._header_text(), id="detail-header")
            with VerticalScroll(id="detail-content"):
                yield Static(self._detail_text())
            yield Label("Notes (will be saved with decision):")
            yield TextArea(self.finding.notes, id="notes-area")
        yield Footer()

    def _header_text(self) -> Text:
        """Generate header with severity and title."""
        from .widgets import SEVERITY_STYLES, STATE_LABELS, STATE_STYLES

        text = Text()

        sev_style = SEVERITY_STYLES.get(self.finding.severity.value, "dim")
        text.append(f" {self.finding.severity.value.upper()} ", style=sev_style)
        text.append(" ")

        state_style = STATE_STYLES.get(self.finding.state.value, "dim")
        state_label = STATE_LABELS.get(self.finding.state.value, "")
        text.append(f"[{state_label}]", style=state_style)
        text.append("\n\n")

        title = sanitize_display(self.finding.title, max_length=100)
        text.append(title, style="bold")

        return text

    def _detail_text(self) -> Text:
        """Generate detail content."""
        text = Text()

        text.append("Scanner: ", style="bold")
        text.append(sanitize_display(self.finding.scanner))
        text.append("\n")

        if self.finding.rule_id:
            text.append("Rule ID: ", style="bold")
            text.append(sanitize_display(self.finding.rule_id))
            text.append("\n")

        if self.finding.file_path:
            text.append("File: ", style="bold")
            text.append(sanitize_display(self.finding.file_path))
            if self.finding.line:
                text.append(f":{self.finding.line}")
            text.append("\n")

        text.append("\n")
        text.append("Description:\n", style="bold")
        description = sanitize_display(self.finding.description, max_length=2000)
        text.append(description)

        return text

    def _get_notes(self) -> str:
        """Get notes from text area."""
        try:
            notes_area = self.query_one("#notes-area", TextArea)
            return notes_area.text
        except Exception:
            return ""

    def _mark_and_close(self, state: TriageState) -> None:
        """Mark state and close screen."""
        self.finding.state = state
        notes = self._get_notes()
        if self.on_state_change:
            self.on_state_change(state, notes)
        self.app.pop_screen()

    def action_mark_false_positive(self) -> None:
        """Mark as false positive and go back."""
        self._mark_and_close(TriageState.FALSE_POSITIVE)

    def action_mark_confirmed(self) -> None:
        """Mark as confirmed and go back."""
        self._mark_and_close(TriageState.CONFIRMED)

    def action_mark_deferred(self) -> None:
        """Mark as deferred and go back."""
        self._mark_and_close(TriageState.DEFERRED)

    def action_go_back(self) -> None:
        """Go back to list screen."""
        self.app.pop_screen()
