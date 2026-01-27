# ThreatFlow - AI-Assisted Threat Modeling

ThreatFlow is an agentic threat modeling tool that uses repository-based analysis with a local Large Language Model (LLM) by default to produce STRIDE-aligned threat model artifacts.

## Overview

ThreatFlow analyzes your codebase and generates:
- **THREATS.md** - Identified threats with STRIDE categorization
- **DATAFLOWS.md** - Data flow diagram description
- **ASSUMPTIONS.md** - Analysis assumptions and limitations
- **threat-model.json** - Machine-readable threat model

## Quick Start

```bash
# Analyze current directory with mock mode (for testing)
kekkai threatflow --model-mode mock

# Analyze a specific repository
kekkai threatflow --repo /path/to/repo --output-dir ./threat-model

# Use a local LLM model
kekkai threatflow --repo . --model-path /path/to/model.gguf

# Use OpenAI API (requires API key)
kekkai threatflow --repo . --model-mode openai --api-key $OPENAI_API_KEY
```

## Security Features

### Local-First Design

By default, ThreatFlow uses a local LLM model, ensuring your code never leaves your machine:

```bash
# Set local model path via environment
export KEKKAI_THREATFLOW_MODEL_PATH=/path/to/model.gguf
kekkai threatflow --repo .
```

### Secret Redaction

ThreatFlow automatically redacts secrets before processing:
- AWS access keys and secrets
- GitHub, GitLab, Slack tokens
- Stripe API keys
- Private keys (RSA, EC)
- JWT tokens
- Database URLs with passwords
- Environment file credentials

### Prompt Injection Defense

ThreatFlow detects and neutralizes prompt injection attempts:
- Instruction override attempts
- Role manipulation
- Special token injection
- Data exfiltration attempts

When injection patterns are found, ThreatFlow:
1. Logs a warning
2. Sanitizes the content
3. Wraps code in clear delimiters
4. Continues analysis safely

## Configuration

### CLI Options

```
--repo PATH          Repository to analyze (default: current directory)
--output-dir PATH    Output directory for artifacts
--model-mode MODE    LLM backend: local, openai, anthropic, mock
--model-path PATH    Path to local model file
--api-key KEY        API key for remote LLM (prefer env var)
--model-name NAME    Specific model name
--max-files N        Maximum files to analyze (default: 500)
--timeout SECONDS    Timeout for model calls (default: 300)
--no-redact          Disable secret redaction (NOT RECOMMENDED)
--no-sanitize        Disable injection sanitization (NOT RECOMMENDED)
```

### Environment Variables

```bash
KEKKAI_THREATFLOW_MODE=local        # Model mode
KEKKAI_THREATFLOW_MODEL_PATH=/path  # Local model path
KEKKAI_THREATFLOW_API_KEY=sk-xxx    # API key for remote mode
KEKKAI_THREATFLOW_MODEL_NAME=gpt-4  # Model name
```

### Config File

Add to `~/.kekkai/kekkai.toml`:

```toml
[threatflow]
enabled = true
model_mode = "local"
model_path = "/path/to/model.gguf"
max_files = 500
timeout_seconds = 300
redact_secrets = true
sanitize_content = true
warn_on_injection = true
```

## Output Format

### THREATS.md

```markdown
# Threat Model: Identified Threats

## Summary
| Risk Level | Count |
|------------|-------|
| Critical   | 2     |
| High       | 5     |
| Medium     | 3     |

## Detailed Threats

### T001: SQL Injection
- **Category**: Tampering
- **Affected Component**: Database layer
- **Risk Level**: Critical
- **Mitigation**: Use parameterized queries
```

### DATAFLOWS.md

```markdown
# Threat Model: Data Flow Diagram

## External Entities
- User: End user of the application

## Processes
- Web Server: Handles HTTP requests

## Data Stores
- Database: User data storage

## Data Flows
- User -> Web Server: HTTP Request [CROSSES TRUST BOUNDARY]

## Trust Boundaries
- Internet -> Application boundary
```

## STRIDE Categories

ThreatFlow uses STRIDE methodology:

| Category | Description |
|----------|-------------|
| **S**poofing | Impersonating something or someone else |
| **T**ampering | Modifying data or code without authorization |
| **R**epudiation | Denying having performed an action |
| **I**nformation Disclosure | Exposing information to unauthorized entities |
| **D**enial of Service | Making a system unavailable or degraded |
| **E**levation of Privilege | Gaining capabilities without authorization |

## Limitations

- **Automated First-Pass**: ThreatFlow provides a starting point; human review is essential
- **Static Analysis**: Runtime behavior is not analyzed
- **LLM Variability**: Output quality depends on the model used
- **No Code Execution**: ThreatFlow never executes your code

## Troubleshooting

### "LOCAL MODEL UNAVAILABLE"

Install llama-cpp-python and provide a model:

```bash
pip install llama-cpp-python
kekkai threatflow --model-path /path/to/model.gguf
```

### "API key required for remote mode"

Set the API key:

```bash
export KEKKAI_THREATFLOW_API_KEY=sk-xxx
kekkai threatflow --model-mode openai
```

### High Memory Usage

Reduce the files analyzed:

```bash
kekkai threatflow --max-files 100
```
