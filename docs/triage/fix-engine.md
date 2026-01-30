# Fix Engine - AI-Powered Remediation

The `kekkai fix` command generates AI-powered code fixes for security findings detected by Semgrep.

## Overview

The fix engine transforms Kekkai from "find problems" to "solve problems" by:

1. Parsing findings from scan results
2. Extracting vulnerable code context
3. Generating fix prompts for LLM
4. Producing unified diffs
5. Optionally applying fixes with backups

## Quick Start

```bash
# 1. Run a scan first
kekkai scan --repo ./my-app --scanners semgrep

# 2. Generate fix suggestions (dry run by default)
kekkai fix --input ~/.kekkai/runs/run-xxx/semgrep-results.json --repo ./my-app

# 3. Review the suggested diffs, then apply
kekkai fix --input ./results.json --repo ./my-app --apply
```

## Command Reference

```
kekkai fix [OPTIONS]

Options:
  --input PATH          Path to scan results JSON (Semgrep format) [required]
  --repo PATH           Repository path (default: current directory)
  --output-dir PATH     Output directory for diffs and audit log
  --dry-run             Preview fixes without applying (default: True)
  --apply               Apply fixes to files (requires explicit flag)
  --model-mode MODE     LLM backend: local, openai, anthropic, mock
  --api-key KEY         API key for remote LLM (prefer env var)
  --model-name NAME     Specific model name to use
  --max-fixes N         Maximum fixes per run (default: 10)
  --timeout SECONDS     LLM call timeout (default: 120)
  --no-backup           Disable backup creation when applying
```

## LLM Backends

### Local Mode (Default)

Uses a local LLM via llama-cpp-python. Code never leaves your machine.

```bash
# Set model path
export KEKKAI_THREATFLOW_MODEL_PATH=/path/to/model.gguf

kekkai fix --input results.json --model-mode local
```

### OpenAI Mode

```bash
# Set API key via environment variable (recommended)
export KEKKAI_FIX_API_KEY=sk-...

kekkai fix --input results.json --model-mode openai --model-name gpt-4o
```

### Anthropic Mode

```bash
export KEKKAI_FIX_API_KEY=sk-ant-...

kekkai fix --input results.json --model-mode anthropic --model-name claude-3-haiku-20240307
```

### Mock Mode (Testing)

```bash
kekkai fix --input results.json --model-mode mock
```

## Security Considerations

### Data Privacy

- **Local mode** (default): Code never leaves your machine
- **Remote modes**: Code is sent to external APIs
- A warning is displayed when using remote APIs

### Input Sanitization

All code content is sanitized before being sent to the LLM to prevent prompt injection attacks. The fix engine reuses the TieredSanitizer from ThreatFlow.

### Preview by Default

The `--dry-run` flag is enabled by default. You must explicitly use `--apply` to modify files.

### Backup Creation

When applying fixes, backups are created in a temporary directory by default. Disable with `--no-backup` (not recommended).

### Audit Logging

All fix operations are logged to `fix-audit.json` in the output directory:

```json
{
  "session_id": "fix-20260130-123456-abc12345",
  "repo_path": "/path/to/repo",
  "model_mode": "local",
  "summary": {
    "total": 5,
    "applied": 3,
    "failed": 1,
    "rejected": 1
  },
  "attempts": [...]
}
```

## Supported Finding Formats

Currently supports:

- **Semgrep JSON** (`--json` output from Semgrep)
- **Kekkai unified format** (findings from scan run)

## Example Workflow

### 1. Scan for Vulnerabilities

```bash
kekkai scan --repo ./my-app --scanners semgrep
# Output: ~/.kekkai/runs/run-20260130-123456/semgrep-results.json
```

### 2. Preview Fixes

```bash
kekkai fix \
  --input ~/.kekkai/runs/run-20260130-123456/semgrep-results.json \
  --repo ./my-app \
  --output-dir ./fix-output
```

Output:
```
Kekkai Fix - AI-Powered Remediation
==================================================
Repository: /home/user/my-app
Input: /home/user/.kekkai/runs/.../semgrep-results.json
Model mode: local
Dry run: True

Analyzing findings...

Fix generation complete
  Findings processed: 5
  Fixes generated: 4

Fix Previews:

--- Fix 1: app.py:42 ---
Rule: python.lang.security.audit.dangerous-system-call
File: /home/user/my-app/app.py
------------------------------------------------------------
--- a/app.py
+++ b/app.py
@@ -40,5 +40,6 @@
 import os
+import subprocess

 def run_command(cmd):
-    os.system(cmd)
+    subprocess.run(cmd, shell=False, check=True)
     return True
------------------------------------------------------------

To apply fixes, run with --apply flag

Audit log: ./fix-output/fix-audit.json
```

### 3. Apply Fixes

```bash
kekkai fix \
  --input ~/.kekkai/runs/run-20260130-123456/semgrep-results.json \
  --repo ./my-app \
  --apply
```

### 4. Review Changes

```bash
cd ./my-app
git diff
```

## Threat Model

| Threat | Mitigation |
|--------|------------|
| Prompt injection via finding content | Input sanitization (TieredSanitizer) |
| Code exfiltration via remote API | Warning + explicit opt-in |
| Malicious fix injection | Preview mode default |
| LLM hallucination | Human review required |
| API key exposure | Environment variables only |

## ASVS Compliance

| Requirement | Implementation |
|-------------|---------------|
| V5.2.5 | Input sanitization before LLM |
| V5.3.3 | Unified diff preserves code intent |
| V6.4.1 | API keys via environment variables |
| V8.3.1 | Audit logging for all operations |
| V13.1.1 | HTTPS for remote API calls |

## Troubleshooting

### "No Semgrep findings with file paths found"

Ensure your scan results contain Semgrep findings with `path` fields:
```json
{
  "results": [
    {
      "check_id": "rule.id",
      "path": "app.py",
      "start": {"line": 10}
    }
  ]
}
```

### "LLM returned empty response"

- Check your model path/API key
- Increase timeout with `--timeout`
- Try a different model

### "Could not parse valid diff from LLM response"

The LLM may have returned invalid output. Check the audit log for the raw response and try:
- Using a more capable model
- Reducing context with simpler findings

## API Reference

For programmatic use:

```python
from kekkai.fix import FixEngine, FixConfig, create_fix_engine

# Create engine
engine = create_fix_engine(
    model_mode="local",
    dry_run=True,
    max_fixes=10,
)

# Fix from scan results file
result = engine.fix_from_scan_results(
    scan_results_path=Path("results.json"),
    repo_path=Path("./my-app"),
    output_dir=Path("./output"),
)

# Or fix from Finding objects
from kekkai.scanners.base import Finding, Severity

findings = [
    Finding(
        scanner="semgrep",
        title="Dangerous call",
        severity=Severity.HIGH,
        description="os.system is dangerous",
        file_path="app.py",
        line=10,
        rule_id="dangerous-call",
    )
]

result = engine.fix(findings, repo_path=Path("./my-app"))

print(f"Fixed: {result.fixes_generated}/{result.findings_processed}")
for suggestion in result.suggestions:
    if suggestion.success:
        print(suggestion.preview)
```
