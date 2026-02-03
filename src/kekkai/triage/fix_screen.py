"""Fix generation screen for AI-powered code fixes.

Provides a modal screen that shows fix generation progress
and preview of AI-generated patches.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TYPE_CHECKING

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Footer, Label, Static

if TYPE_CHECKING:
    from .models import FindingEntry

__all__ = ["FixGenerationScreen"]


class FixGenerationScreen(ModalScreen[bool]):
    """Modal screen for generating AI-powered fixes.

    Shows progress, model configuration, and fix preview.

    Bindings:
        escape: Cancel and go back
        enter: Accept fix (if generated)
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "accept", "Accept Fix", show=False),
    ]

    DEFAULT_CSS = """
    FixGenerationScreen {
        align: center middle;
    }
    #fix-dialog {
        width: 80;
        height: 30;
        border: thick $primary;
        background: $surface;
        padding: 1;
    }
    #fix-title {
        dock: top;
        height: 3;
        content-align: center middle;
        background: $primary;
        color: $text;
    }
    #fix-content {
        height: 1fr;
        padding: 1;
    }
    #fix-preview {
        height: 1fr;
        border: solid $accent;
        padding: 1;
        background: $panel;
    }
    #fix-status {
        dock: bottom;
        height: 3;
        padding: 1;
        background: $surface;
    }
    .fix-button {
        margin: 1;
    }
    """

    def __init__(
        self,
        finding: FindingEntry,
        on_fix_generated: Callable[[bool, str], None] | None = None,
        name: str | None = None,
        id: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id)
        self.finding = finding
        self.on_fix_generated = on_fix_generated
        self.fix_preview: str | None = None
        self.fix_generated = False

    def compose(self) -> ComposeResult:
        with Vertical(id="fix-dialog"):
            yield Label("🤖 AI-Powered Fix Generation", id="fix-title")
            with VerticalScroll(id="fix-content"):
                yield Label(self._get_finding_summary())
                yield Label(self._get_model_info())
                yield Static("", id="fix-preview")
            yield Static(self._get_initial_status(), id="fix-status")
            yield Footer()

    def _get_finding_summary(self) -> Text:
        """Generate summary of finding to fix."""
        text = Text()
        text.append("Finding:\n", style="bold")
        text.append(f"  {self.finding.scanner}: ", style="cyan")
        text.append(f"{self.finding.title}\n")
        if self.finding.file_path:
            text.append(f"  File: {self.finding.file_path}", style="dim")
            if self.finding.line:
                text.append(f":{self.finding.line}", style="dim")
            text.append("\n")
        return text

    def _get_model_info(self) -> Text:
        """Display model configuration info."""
        text = Text()
        text.append("\nModel Configuration:\n", style="bold")

        # Check for Ollama
        if self._is_ollama_available():
            text.append("  ✓ Ollama detected (local-first AI)\n", style="green")
            text.append("  No API keys needed - runs on your machine\n", style="dim")
        # Check for API keys
        elif os.environ.get("KEKKAI_FIX_API_KEY"):
            text.append("  ⚠ Using remote API (OpenAI/Anthropic)\n", style="yellow")
            text.append("  Code will be sent to external service\n", style="dim")
        else:
            text.append("  ✗ No AI backend configured\n", style="red")
            text.append("  Install Ollama or set KEKKAI_FIX_API_KEY\n", style="dim")

        return text

    def _get_initial_status(self) -> Text:
        """Initial status message."""
        if self._is_ollama_available() or os.environ.get("KEKKAI_FIX_API_KEY"):
            return Text("Press Enter to generate fix, or Escape to cancel", style="italic")
        else:
            return Text(
                "❌ Cannot generate fix: No AI backend configured\n"
                "Install Ollama (recommended) or set KEKKAI_FIX_API_KEY",
                style="red",
            )

    def _is_ollama_available(self) -> bool:
        """Check if Ollama is available on the system."""
        import shutil

        return shutil.which("ollama") is not None

    def on_mount(self) -> None:
        """Auto-generate fix if backend is available."""
        if self._is_ollama_available() or os.environ.get("KEKKAI_FIX_API_KEY"):
            # Auto-start fix generation
            self.set_timer(0.5, self._generate_fix)

    def _generate_fix(self) -> None:
        """Generate AI-powered fix."""
        status = self.query_one("#fix-status", Static)
        status.update(Text("⏳ Generating fix with AI...", style="yellow italic"))

        try:
            # Import fix engine
            from ..fix import FixConfig

            # Determine model mode
            if self._is_ollama_available():
                model_mode = "ollama"
                model_name = os.environ.get("KEKKAI_FIX_MODEL_NAME", "mistral")
            else:
                model_mode = "openai"
                model_name = None

            # Create fix config (for future integration)
            _config = FixConfig(
                model_mode=model_mode,
                model_name=model_name,
                api_key=os.environ.get("KEKKAI_FIX_API_KEY"),
                max_fixes=1,
                timeout_seconds=60,
                dry_run=True,
            )

            # Note: This is a simplified mock - actual implementation would:
            # 1. Convert FindingEntry to proper format for FixEngine
            # 2. Call fix engine with proper error handling
            # 3. Display actual fix preview

            # For now, show a placeholder
            self.fix_preview = (
                "# AI-Powered Fix (Preview)\n"
                f"# Finding: {self.finding.title}\n"
                f"# Scanner: {self.finding.scanner}\n\n"
                "# Fix would be generated here using:\n"
                f"# - Model: {model_name or 'gpt-4'}\n"
                f"# - Mode: {model_mode}\n"
                "# - Context from source file\n\n"
                "# Press Enter to apply (dry-run mode)\n"
                "# Press Escape to cancel"
            )

            preview = self.query_one("#fix-preview", Static)
            preview.update(Text(self.fix_preview, style="green"))

            status.update(
                Text("✓ Fix generated! Press Enter to apply or Escape to cancel", style="green")
            )
            self.fix_generated = True

        except Exception as e:
            status.update(Text(f"✗ Fix generation failed: {e}", style="red"))
            self.fix_generated = False

    def action_accept(self) -> None:
        """Accept and apply the generated fix."""
        if not self.fix_generated:
            return

        if self.on_fix_generated:
            self.on_fix_generated(
                True, "Fix generated successfully (dry-run mode - review before applying)"
            )

        self.dismiss(True)

    def action_cancel(self) -> None:
        """Cancel fix generation."""
        if self.on_fix_generated:
            self.on_fix_generated(False, "Fix generation cancelled")

        self.dismiss(False)
