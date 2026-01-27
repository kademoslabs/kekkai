"""Main Textual application for triage TUI.

Provides the entry point for interactive finding triage with
keyboard-driven navigation and ignore file generation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App

from .audit import TriageAuditLog
from .ignore import IgnoreFile
from .models import FindingEntry, TriageDecision, TriageState, load_findings_from_json
from .screens import FindingListScreen

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "TriageApp",
    "run_triage",
]


class TriageApp(App[None]):
    """Interactive triage application for security findings.

    Allows reviewing findings, marking false positives, and
    generating .kekkaiignore files.

    Attributes:
        findings: List of findings to triage.
        ignore_file: IgnoreFile manager for output.
        audit_log: Audit log for recording decisions.
    """

    TITLE = "Kekkai Triage"
    CSS = """
    Screen {
        background: $background;
    }
    """

    def __init__(
        self,
        findings: Sequence[FindingEntry] | None = None,
        input_path: Path | None = None,
        output_path: Path | None = None,
        audit_path: Path | None = None,
    ) -> None:
        """Initialize triage application.

        Args:
            findings: Pre-loaded findings to triage.
            input_path: Path to findings JSON file.
            output_path: Path for .kekkaiignore output.
            audit_path: Path for audit log.
        """
        super().__init__()
        self._input_path = input_path
        self._findings_list: list[FindingEntry] = list(findings) if findings else []
        self.ignore_file = IgnoreFile(output_path)
        self.audit_log = TriageAuditLog(audit_path)
        self._decisions: dict[str, TriageDecision] = {}

    @property
    def findings(self) -> list[FindingEntry]:
        """Get findings list, loading from file if needed."""
        if not self._findings_list and self._input_path:
            self._load_findings()
        return self._findings_list

    def _load_findings(self) -> None:
        """Load findings from input file."""
        if not self._input_path or not self._input_path.exists():
            return

        try:
            content = self._input_path.read_text(encoding="utf-8")
            data = json.loads(content)

            if isinstance(data, list):
                self._findings_list = load_findings_from_json(data)
            elif isinstance(data, dict) and "findings" in data:
                self._findings_list = load_findings_from_json(data["findings"])
        except (json.JSONDecodeError, KeyError, TypeError):
            self._findings_list = []

    def on_mount(self) -> None:
        """Handle app mount."""
        self.push_screen(
            FindingListScreen(
                findings=self.findings,
                on_state_change=self._handle_state_change,
                on_save=self._handle_save,
            )
        )

    def _handle_state_change(self, index: int, state: TriageState) -> None:
        """Handle finding state change.

        Args:
            index: Finding index.
            state: New triage state.
        """
        if index >= len(self.findings):
            return

        finding = self.findings[index]
        ignore_pattern = None

        if state == TriageState.FALSE_POSITIVE:
            ignore_pattern = finding.generate_ignore_pattern()

        decision = TriageDecision(
            finding_id=finding.id,
            state=state,
            reason=finding.notes,
            ignore_pattern=ignore_pattern,
        )

        self._decisions[finding.id] = decision
        self.audit_log.log_decision(decision)

    def _handle_save(self) -> None:
        """Handle save action."""
        self.ignore_file.load()

        for finding in self.findings:
            if finding.state == TriageState.FALSE_POSITIVE:
                pattern = finding.generate_ignore_pattern()
                if not self.ignore_file.has_pattern(pattern):
                    self.ignore_file.add_entry(
                        pattern=pattern,
                        comment=finding.notes[:100] if finding.notes else finding.title[:100],
                        finding_id=finding.id,
                    )

        self.ignore_file.save()
        self.audit_log.log_action("save_ignore_file", finding_id="*")


def run_triage(
    input_path: Path | None = None,
    output_path: Path | None = None,
    findings: Sequence[FindingEntry] | None = None,
) -> int:
    """Run the triage TUI.

    Args:
        input_path: Path to findings JSON file.
        output_path: Path for .kekkaiignore output.
        findings: Pre-loaded findings (alternative to input_path).

    Returns:
        Exit code (0 for success).
    """
    app = TriageApp(
        findings=findings,
        input_path=input_path,
        output_path=output_path,
    )
    app.run()
    return 0
