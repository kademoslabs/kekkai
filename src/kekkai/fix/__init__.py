"""AI-powered code remediation engine.

Provides `kekkai fix` functionality to generate and apply code fixes
for security findings using LLM-based suggestions.

Security considerations:
- All inputs sanitized before LLM processing (reuses TieredSanitizer)
- Preview mode default (no auto-apply without explicit --apply)
- Audit logging for all operations (ASVS V8.3.1)
- Supports local LLM for sensitive codebases

ASVS Requirements:
- V5.2.5: Sanitize before LLM
- V5.3.3: Diff format preserves code intent
- V6.4.1: API keys in env vars only
- V8.3.1: Audit log for fix applications
- V13.1.1: HTTPS for remote API calls
"""

from __future__ import annotations

from .audit import FixAttempt, FixAuditLog, create_session_id
from .differ import ApplyResult, DiffApplier, DiffHunk, DiffParser, ParsedDiff, generate_diff
from .engine import FixConfig, FixEngine, FixResult, FixSuggestion, create_fix_engine
from .prompts import FixPromptBuilder

__all__ = [
    # Engine
    "FixEngine",
    "FixConfig",
    "FixResult",
    "FixSuggestion",
    "create_fix_engine",
    # Prompts
    "FixPromptBuilder",
    # Differ
    "DiffParser",
    "DiffApplier",
    "DiffHunk",
    "ParsedDiff",
    "ApplyResult",
    "generate_diff",
    # Audit
    "FixAuditLog",
    "FixAttempt",
    "create_session_id",
]
