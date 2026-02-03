"""Textual screens for triage TUI.

Provides screen components for finding list and detail views
with keyboard navigation and action handling.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rich.syntax import Syntax
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, Static, TextArea

from .code_context import CodeContextExtractor
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
        Binding("x", "fix_with_ai", "🤖 Fix with AI"),
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
        # Get repo_path and context_lines from app if available
        repo_path = getattr(self.app, "repo_path", None)
        context_lines = getattr(self.app, "context_lines", 10)
        self.app.push_screen(
            FindingDetailScreen(
                finding,
                on_state_change=self._handle_detail_state_change,
                repo_path=repo_path,
                context_lines=context_lines,
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
        Binding("x", "fix_with_ai", "🤖 AI Fix"),
        Binding("ctrl+o", "open_in_editor", "Open in Editor"),
        Binding("e", "expand_context", "Expand Context"),
        Binding("s", "shrink_context", "Shrink Context"),
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
    #code-context-display {
        height: 20;
        border: solid $accent;
        padding: 1;
        margin: 1 0;
        overflow-y: scroll;
    }
    .error-message {
        color: $warning;
        italic: true;
    }
    #action-hints {
        height: auto;
        padding: 1;
        margin: 1 0;
        background: $panel;
        border: solid $secondary;
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
        repo_path: Path | None = None,
        context_lines: int = 10,
        name: str | None = None,
        id: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id)
        self.finding = finding
        self.on_state_change = on_state_change
        self.repo_path = repo_path or Path.cwd()
        self.context_lines = context_lines
        self._code_extractor = CodeContextExtractor(self.repo_path)

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="detail-container"):
            yield Static(self._header_text(), id="detail-header")
            with VerticalScroll(id="detail-content"):
                yield Static(self._detail_text())
            # Add code context if available
            code_widget = self._render_code_context()
            if code_widget:
                yield Label("Code Context:")
                yield code_widget
            # Add action hints to make workflow discoverable
            yield Static(self._action_hints(), id="action-hints")
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

    def _action_hints(self) -> Text:
        """Generate action hints to make workflow discoverable."""
        text = Text()
        text.append("💡 Actions: ", style="bold")
        text.append("Press ", style="dim")
        text.append("X", style="bold cyan")
        text.append(" for AI-powered fix | ", style="dim")
        text.append("Ctrl+O", style="bold cyan")
        text.append(" to open in ", style="dim")
        text.append("$EDITOR", style="italic")
        text.append(" | ", style="dim")
        text.append("E", style="bold cyan")
        text.append("/", style="dim")
        text.append("S", style="bold cyan")
        text.append(" to expand/shrink context", style="dim")
        return text

    def action_fix_with_ai(self) -> None:
        """Trigger AI-powered fix generation (workbench: step 2)."""
        # Check if file path and line exist (required for fix)
        if not self.finding.file_path or not self.finding.line:
            self.notify(
                "Cannot generate fix: no file path or line number",
                severity="warning",
            )
            return

        # Import and show fix generation screen
        try:
            from .fix_screen import FixGenerationScreen

            def on_fix_result(accepted: bool, preview: str) -> None:
                if accepted:
                    self.notify("Fix generation completed!", severity="information")
                else:
                    self.notify("Fix generation cancelled", severity="information")

            self.app.push_screen(
                FixGenerationScreen(
                    finding=self.finding,
                    on_fix_generated=on_fix_result,
                )
            )
        except ImportError:
            self.notify("AI fix feature not available", severity="error")

    def action_open_in_editor(self) -> None:
        """Open file in external $EDITOR at the vulnerable line (workbench: step 2)."""
        import logging
        import os
        import shutil
        import subprocess

        logger = logging.getLogger(__name__)

        if not self.finding.file_path or not self.finding.line:
            self.notify(
                "Cannot open editor: no file path or line number",
                severity="warning",
            )
            return

        # Get editor from environment (ASVS V5.1.3: validate before use)
        editor = os.environ.get("EDITOR", "vim")

        # Security validation: check editor exists and is executable
        editor_path = shutil.which(editor)
        if not editor_path:
            self.notify(
                f"Editor '{editor}' not found. Set $EDITOR environment variable.",
                severity="error",
            )
            return

        # Construct file path relative to repo
        file_path = self.repo_path / self.finding.file_path
        if not file_path.exists():
            self.notify(f"File not found: {self.finding.file_path}", severity="error")
            return

        # Log editor invocation (ASVS V16.7.1)
        logger.info(
            "editor_opened",
            extra={
                "editor": editor,
                "file": self.finding.file_path,
                "line": self.finding.line,
            },
        )

        # ASVS V14.2.1: Use list args (not shell=True) to prevent injection
        cmd = [editor_path, f"+{self.finding.line}", str(file_path)]

        try:
            # Suspend TUI, run editor, then resume
            with self.app.suspend():
                # S603: subprocess with validated input (editor_path checked via shutil.which)
                result = subprocess.run(cmd, check=False)  # noqa: S603
                if result.returncode != 0:
                    self.notify(
                        f"Editor exited with code {result.returncode}",
                        severity="warning",
                    )
        except Exception as e:
            logger.error("editor_failed", extra={"error": str(e)})
            self.notify(f"Failed to open editor: {e}", severity="error")

    def action_expand_context(self) -> None:
        """Expand code context by 10 lines (addresses keyhole effect)."""
        self.context_lines = min(100, self.context_lines + 10)
        self._refresh_code_context()
        self.notify(f"Context expanded to {self.context_lines} lines", severity="information")

    def action_shrink_context(self) -> None:
        """Shrink code context by 10 lines."""
        self.context_lines = max(5, self.context_lines - 10)
        self._refresh_code_context()
        self.notify(f"Context shrunk to {self.context_lines} lines", severity="information")

    def _refresh_code_context(self) -> None:
        """Refresh code context display with new context_lines setting."""
        import logging

        logger = logging.getLogger(__name__)

        try:
            # Update the prompt builder's context lines
            self._code_extractor._prompt_builder.context_lines = self.context_lines

            # Re-render code context
            code_widget = self._render_code_context()
            if code_widget:
                # Find and update the existing widget
                try:
                    old_widget = self.query_one("#code-context-display")
                    # Replace content by removing old and adding new
                    old_widget.remove()
                    # Find the label and insert after it
                    container = self.query_one("#detail-container")
                    container.mount(code_widget)
                except Exception as e:
                    # Widget not found or couldn't refresh
                    logger.debug("code_context_refresh_failed", extra={"error": str(e)})
        except Exception as e:
            # Refresh failed, log but don't crash
            logger.debug("code_context_update_failed", extra={"error": str(e)})

    def _render_code_context(self) -> Static | None:
        """Render code context with syntax highlighting.

        Returns:
            Static widget with Syntax-highlighted code, or None if unavailable.

        Security:
            - File size limit: 10MB (ASVS V10.3.3)
            - Path validation: must be within repo_path (ASVS V5.3.3)
            - Error sanitization: no full paths in errors (ASVS V7.4.1)
            - Sensitive file blocking (ASVS V8.3.4)
        """
        if not self.finding.file_path or not self.finding.line:
            return None

        context = self._code_extractor.extract(self.finding.file_path, self.finding.line)
        if not context:
            return None

        if context.error:
            return Static(f"Code unavailable: {context.error}", classes="error-message")

        # Create syntax-highlighted code display
        try:
            syntax = Syntax(
                context.code,
                context.language,
                line_numbers=False,  # We already have line numbers in the context
                theme="monokai",
                word_wrap=False,
            )
            return Static(syntax, id="code-context-display")
        except Exception:
            # Fallback to plain text if syntax highlighting fails
            return Static(context.code, id="code-context-display")
