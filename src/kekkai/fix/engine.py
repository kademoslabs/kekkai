"""Core fix engine for AI-powered code remediation.

Orchestrates the finding → prompt → LLM → diff → apply workflow.

Security considerations:
- All inputs sanitized before LLM processing
- Preview mode default (no auto-apply)
- Audit logging for all operations
- Rate limiting on API calls
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..scanners.base import Finding, Severity
from ..threatflow.model_adapter import (
    ModelAdapter,
    ModelConfig,
    create_adapter,
)
from ..threatflow.sanitizer import SanitizeConfig, TieredSanitizer
from .audit import FixAuditLog, create_session_id
from .differ import ApplyResult, DiffApplier, DiffParser, ParsedDiff
from .prompts import FixPromptBuilder

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class FixConfig:
    """Configuration for the fix engine."""

    model_mode: str = "local"  # local, openai, anthropic, mock
    model_path: str | None = None
    api_key: str | None = None
    model_name: str | None = None
    timeout_seconds: int = 120
    max_fixes: int = 10
    context_lines: int = 10
    dry_run: bool = True
    create_backups: bool = True
    sanitize_input: bool = True
    rate_limit_seconds: float = 1.0


@dataclass
class FixSuggestion:
    """A fix suggestion from the LLM."""

    finding: Finding
    diff: ParsedDiff
    raw_response: str
    preview: str
    success: bool
    error: str | None = None


@dataclass
class FixResult:
    """Result of a fix operation."""

    success: bool
    findings_processed: int = 0
    fixes_generated: int = 0
    fixes_applied: int = 0
    suggestions: list[FixSuggestion] = field(default_factory=list)
    apply_results: list[ApplyResult] = field(default_factory=list)
    audit_log_path: Path | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


class FixEngine:
    """AI-powered code remediation engine.

    Workflow:
    1. Load findings from scan results
    2. For each finding:
       a. Extract code context from source file
       b. Build fix prompt with sanitized content
       c. Query LLM for fix suggestion
       d. Parse diff from LLM response
       e. Validate and optionally apply diff
    3. Generate audit log
    """

    def __init__(self, config: FixConfig | None = None) -> None:
        self.config = config or FixConfig()
        self._prompt_builder = FixPromptBuilder(context_lines=self.config.context_lines)
        self._diff_parser = DiffParser()
        self._diff_applier = DiffApplier()
        self._sanitizer = TieredSanitizer(SanitizeConfig(strict_mode=False))
        self._model: ModelAdapter | None = None

    def _get_model(self) -> ModelAdapter:
        """Get or create the model adapter."""
        if self._model is None:
            self._model = create_adapter(
                mode=self.config.model_mode,
                config=ModelConfig(
                    timeout_seconds=self.config.timeout_seconds,
                    model_path=self.config.model_path,
                    api_key=self.config.api_key,
                    model_name=self.config.model_name,
                ),
            )
        return self._model

    def fix(
        self,
        findings: list[Finding],
        repo_path: Path,
        output_dir: Path | None = None,
    ) -> FixResult:
        """Generate and optionally apply fixes for findings.

        Args:
            findings: List of findings from scan results
            repo_path: Path to the repository root
            output_dir: Optional output directory for diffs and audit log

        Returns:
            FixResult with details of all operations
        """
        if not findings:
            return FixResult(success=True, warnings=["No findings to fix"])

        # Filter to fixable findings (Semgrep only for now)
        fixable = [f for f in findings if f.scanner == "semgrep" and f.file_path]
        if not fixable:
            return FixResult(
                success=True,
                warnings=["No Semgrep findings with file paths found"],
            )

        # Limit to max_fixes
        to_fix = fixable[: self.config.max_fixes]
        if len(fixable) > self.config.max_fixes:
            logger.warning(
                "fix_limit_reached",
                extra={"total": len(fixable), "limit": self.config.max_fixes},
            )

        # Initialize audit log
        audit_log = FixAuditLog(
            session_id=create_session_id(),
            repo_path=str(repo_path),
            model_mode=self.config.model_mode,
        )

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            audit_log.set_output_path(output_dir / "fix-audit.json")

        # Process findings
        suggestions: list[FixSuggestion] = []
        apply_results: list[ApplyResult] = []
        warnings: list[str] = []

        model = self._get_model()

        for finding in to_fix:
            # Record attempt
            attempt = audit_log.record_attempt(
                finding_id=finding.dedupe_hash(),
                rule_id=finding.rule_id or "unknown",
                file_path=finding.file_path or "",
                line_number=finding.line or 0,
                severity=finding.severity.value,
                model_used=model.name,
            )

            # Generate fix
            suggestion = self._generate_fix(finding, repo_path, model)
            suggestions.append(suggestion)

            if not suggestion.success:
                audit_log.mark_failed(attempt, suggestion.error or "Unknown error")
                err_msg = f"Failed to fix {finding.file_path}:{finding.line}: {suggestion.error}"
                warnings.append(err_msg)
                continue

            # Update attempt with diff preview
            audit_log.update_attempt(
                attempt,
                status="approved" if not self.config.dry_run else "pending",
                diff_preview=suggestion.preview,
            )

            # Apply if not dry run
            if not self.config.dry_run:
                result = self._diff_applier.apply(
                    suggestion.diff,
                    repo_path,
                    dry_run=False,
                    create_backup=self.config.create_backups,
                )
                apply_results.append(result)

                if result.success:
                    audit_log.mark_applied(
                        attempt,
                        lines_added=result.lines_added,
                        lines_removed=result.lines_removed,
                        backup_path=result.backup_path,
                    )
                else:
                    audit_log.mark_failed(attempt, result.error or "Apply failed")
                    warnings.append(f"Failed to apply fix: {result.error}")

        # Save audit log
        audit_log_path = None
        if output_dir:
            audit_log_path = output_dir / "fix-audit.json"
            audit_log.save(audit_log_path)

        return FixResult(
            success=True,
            findings_processed=len(to_fix),
            fixes_generated=len([s for s in suggestions if s.success]),
            fixes_applied=len([r for r in apply_results if r.success]),
            suggestions=suggestions,
            apply_results=apply_results,
            audit_log_path=audit_log_path,
            warnings=warnings,
        )

    def _generate_fix(
        self,
        finding: Finding,
        repo_path: Path,
        model: ModelAdapter,
    ) -> FixSuggestion:
        """Generate a fix suggestion for a single finding."""
        file_path = finding.file_path
        if not file_path:
            return FixSuggestion(
                finding=finding,
                diff=ParsedDiff("", ""),
                raw_response="",
                preview="",
                success=False,
                error="No file path in finding",
            )

        # Resolve full path
        full_path = (repo_path / file_path).resolve()
        if not full_path.exists():
            return FixSuggestion(
                finding=finding,
                diff=ParsedDiff("", ""),
                raw_response="",
                preview="",
                success=False,
                error=f"File not found: {file_path}",
            )

        # Read file content
        try:
            file_content = full_path.read_text()
        except (OSError, UnicodeDecodeError) as e:
            return FixSuggestion(
                finding=finding,
                diff=ParsedDiff("", ""),
                raw_response="",
                preview="",
                success=False,
                error=f"Cannot read file: {e}",
            )

        # Extract code context
        line_num = finding.line or 1
        code_context, vulnerable_line = self._prompt_builder.extract_code_context(
            file_content, line_num
        )

        # Sanitize content if enabled
        if self.config.sanitize_input:
            sanitize_result = self._sanitizer.sanitize_input(code_context, file_path)
            if sanitize_result.blocked:
                return FixSuggestion(
                    finding=finding,
                    diff=ParsedDiff("", ""),
                    raw_response="",
                    preview="",
                    success=False,
                    error=f"Content blocked by sanitizer: {sanitize_result.block_reason}",
                )
            code_context = sanitize_result.sanitized

        # Build CWE context if available
        additional_context = ""
        if finding.cwe:
            additional_context = f"CWE: {finding.cwe}"

        # Build prompt
        system_prompt = self._prompt_builder.build_system_prompt()
        user_prompt = self._prompt_builder.build_fix_prompt(
            rule_id=finding.rule_id or "",
            severity=finding.severity.value,
            title=finding.title,
            description=finding.description,
            file_path=file_path,
            line_number=line_num,
            code_context=code_context,
            vulnerable_line=vulnerable_line,
            additional_context=additional_context,
        )

        # Query LLM
        try:
            response = model.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                config=ModelConfig(
                    timeout_seconds=self.config.timeout_seconds,
                    max_tokens=2048,
                ),
            )
        except Exception as e:
            return FixSuggestion(
                finding=finding,
                diff=ParsedDiff("", ""),
                raw_response="",
                preview="",
                success=False,
                error=f"LLM error: {e}",
            )

        if not response.success:
            return FixSuggestion(
                finding=finding,
                diff=ParsedDiff("", ""),
                raw_response=response.content,
                preview="",
                success=False,
                error="LLM returned empty response",
            )

        # Parse diff from response
        diff = self._diff_parser.parse(response.content)

        # If no diff parsed, try to use the content as-is
        if not diff.is_valid:
            return FixSuggestion(
                finding=finding,
                diff=diff,
                raw_response=response.content,
                preview=response.content[:500],
                success=False,
                error="Could not parse valid diff from LLM response",
            )

        # Generate preview
        preview = self._diff_applier.preview(diff, repo_path)

        return FixSuggestion(
            finding=finding,
            diff=diff,
            raw_response=response.content,
            preview=preview,
            success=True,
        )

    def fix_from_scan_results(
        self,
        scan_results_path: Path,
        repo_path: Path,
        output_dir: Path | None = None,
    ) -> FixResult:
        """Generate fixes from a scan results JSON file.

        Args:
            scan_results_path: Path to scan results JSON
            repo_path: Path to the repository root
            output_dir: Optional output directory for diffs and audit log

        Returns:
            FixResult with details of all operations
        """
        # Parse scan results
        try:
            findings = self._load_findings(scan_results_path)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            return FixResult(
                success=False,
                error=f"Failed to load scan results: {e}",
            )

        return self.fix(findings, repo_path, output_dir)

    def _load_findings(self, path: Path) -> list[Finding]:
        """Load findings from a scan results JSON file."""
        data = json.loads(path.read_text())

        # Handle different JSON formats
        findings: list[Finding] = []

        # Try Semgrep format
        if "results" in data:
            for result in data["results"]:
                findings.append(self._parse_semgrep_result(result))
        # Try Kekkai unified format
        elif "findings" in data:
            for f in data["findings"]:
                findings.append(self._parse_unified_finding(f))

        return findings

    def _parse_semgrep_result(self, result: dict[str, object]) -> Finding:
        """Parse a Semgrep result into a Finding."""
        extra = result.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}
        metadata = extra.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        severity_str = extra.get("severity", "warning")
        if severity_str == "ERROR":
            severity = Severity.HIGH
        elif severity_str == "WARNING":
            severity = Severity.MEDIUM
        else:
            severity = Severity.from_string(str(severity_str))

        cwe_list = metadata.get("cwe", [])
        if not isinstance(cwe_list, list):
            cwe_list = []
        cwe = str(cwe_list[0]) if cwe_list else None

        start = result.get("start", {})
        if not isinstance(start, dict):
            start = {}

        return Finding(
            scanner="semgrep",
            title=str(metadata.get("message") or result.get("check_id", "Semgrep finding")),
            severity=severity,
            description=str(extra.get("message", "")),
            file_path=str(result.get("path", "")),
            line=int(start.get("line", 0)) if start.get("line") else None,
            rule_id=str(result.get("check_id", "")),
            cwe=cwe,
        )

    def _parse_unified_finding(self, data: dict[str, object]) -> Finding:
        """Parse a unified format finding."""
        line_val = data.get("line")
        return Finding(
            scanner=str(data.get("scanner", "unknown")),
            title=str(data.get("title", "")),
            severity=Severity.from_string(str(data.get("severity", "unknown"))),
            description=str(data.get("description", "")),
            file_path=str(data.get("file_path")) if data.get("file_path") else None,
            line=int(str(line_val)) if line_val else None,
            rule_id=str(data.get("rule_id")) if data.get("rule_id") else None,
            cwe=str(data.get("cwe")) if data.get("cwe") else None,
        )


def create_fix_engine(
    model_mode: str = "local",
    dry_run: bool = True,
    **kwargs: object,
) -> FixEngine:
    """Create a configured fix engine.

    Args:
        model_mode: LLM backend (local, openai, anthropic, mock)
        dry_run: If True, don't apply fixes
        **kwargs: Additional config options

    Returns:
        Configured FixEngine instance
    """
    timeout = kwargs.get("timeout_seconds", 120)
    max_fixes_val = kwargs.get("max_fixes", 10)
    context_val = kwargs.get("context_lines", 10)
    config = FixConfig(
        model_mode=model_mode,
        dry_run=dry_run,
        model_path=str(kwargs.get("model_path")) if kwargs.get("model_path") else None,
        api_key=str(kwargs.get("api_key")) if kwargs.get("api_key") else None,
        model_name=str(kwargs.get("model_name")) if kwargs.get("model_name") else None,
        timeout_seconds=int(str(timeout)) if timeout is not None else 120,
        max_fixes=int(str(max_fixes_val)) if max_fixes_val is not None else 10,
        context_lines=int(str(context_val)) if context_val is not None else 10,
        create_backups=bool(kwargs.get("create_backups", True)),
        sanitize_input=bool(kwargs.get("sanitize_input", True)),
    )
    return FixEngine(config)
