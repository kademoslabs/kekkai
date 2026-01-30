<p align="center">
  <img src="https://raw.githubusercontent.com/kademoslabs/assets/main/logos/kekkai-slim.png" alt="Kekkai CLI Logo" width="250"/>
</p>

<p align="center"><i>One command. Clean AppSec reports.</i></p>
<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/kademoslabs/kekkai/docker-publish.yml?logo=github"/>
  <img src ="https://img.shields.io/circleci/build/github/kademoslabs/kekkai?logo=circleci"/>
  <img src="https://img.shields.io/pypi/v/kekkai-cli?pypiBaseUrl=https%3A%2F%2Fpypi.org&logo=pypi"/>
</p>

# Kekkai

**Security that moves at developer speed.**

*Local-first orchestration for Trivy, Semgrep, and DefectDojo.*

![Hero GIF](https://raw.githubusercontent.com/kademoslabs/assets/main/screenshots/kekkai-demo.gif)

---

## ⚡ Quick Start

Stop fighting with Docker Compose. Start scanning in 30 seconds.

### Installation

**Option 1: pipx (Recommended - Isolated Environment)**

```bash
pipx install kekkai-cli
```

**Option 2: Docker (No Python Required)**

```bash
# Build image
docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .

# Run via wrapper script
./scripts/kekkai-docker --help

# Or set up alias
alias kekkai="$(pwd)/scripts/kekkai-docker"
```

**Option 3: pip (Traditional)**

```bash
pip install kekkai-cli
```


### 1. Scan your project (Local)

Run industry-standard scanners (Trivy, Semgrep, Gitleaks) in unified Docker containers without installing them individually.

```bash
cd your-repo
kekkai scan

```

### 2. Spin up DefectDojo

Launch a full local vulnerability management platform (Nginx, Postgres, Redis, Celery) with one command.

```bash
kekkai dojo up --wait --open

```

### 3. Generate a Threat Model (AI)

Generate a STRIDE threat model and Data Flow Diagram using your local LLM.

```bash
kekkai threatflow --repo . --model-mode local

```

---

## 🛑 The Problem vs. Kekkai

| Feature | The Old Way | The Kekkai Way |
| --- | --- | --- |
| **Tooling** | Manually install/update 5+ tools (Trivy, Semgrep, etc.) | **One Binary.** `kekkai scan` auto-pulls and runs the latest scanner containers. |
| **Reporting** | Parse 5 different JSON formats manually. | **Unified Output.** One deduplicated `kekkai-report.json` for all findings. |
| **DefectDojo** | Write a 200-line `docker-compose.yml` and debug networking. | **One Command.** `kekkai dojo up` automates the entire stack setup. |
| **Threat Modeling** | Expensive consultants or manual whiteboarding. | **AI Agent.** `kekkai threatflow` generates `THREATS.md` locally. |
| **CI/CD** | Write complex bash scripts to break builds. | **Policy Engine.** `kekkai scan --ci --fail-on high`. |

---

## 🤖 ThreatFlow Configuration

ThreatFlow generates AI-powered threat models and data flow diagrams. It supports multiple backends:

### Local LLM (Privacy-Preserving)

Run threat analysis entirely on your machine using a local model:

1. **Install the inference library:**
   ```bash
   pip install llama-cpp-python
   ```

2. **Download a GGUF model** (e.g., [Mistral-7B-Instruct](https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF)):
   ```bash
   # Example: Download Q4_K_M quantized model (~4.4GB)
   wget https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf
   ```

3. **Run ThreatFlow:**
   ```bash
   kekkai threatflow \
     --repo . \
     --model-mode local \
     --model-path /path/to/mistral-7b-instruct.gguf \
     --output-dir ./threats
   ```

### Remote API (OpenAI / Anthropic)

For faster results without local GPU requirements:

```bash
# Using environment variable
export KEKKAI_THREATFLOW_API_KEY="sk-..."
kekkai threatflow --repo . --model-mode openai

# Or pass directly
kekkai threatflow --repo . --model-mode anthropic --api-key "sk-ant-..."
```

### Mock Mode (Testing)

The `--model-mode mock` option returns stub responses for testing pipelines. It does **not** perform actual analysis.

### Output Formatting

ThreatFlow uses the `rich` library for colored terminal output. If you see raw ANSI codes (`[3m`, `[36m`), ensure you're running in a standard terminal (VSCode integrated terminal, iTerm2, or native Bash/Zsh).

---

## 🔒 Enterprise Features (Portal)

For teams that need centralized management, **Kekkai Portal** offers:

* **SAML 2.0 SSO** with Replay Protection
* **Role-Based Access Control (RBAC)**
* **Cryptographically Signed Audit Logs**

*Built by Kademos Labs.*

---

## 📚 Documentation

- **[Automated Distribution Updates](docs/ci/automated-distributions.md)** - CI/CD distribution triggers
- **[CI Architecture](/.docs/development/ci-architecture.md)** - Developer guide for distribution automation
- **[Homebrew Maintenance](docs/ci/homebrew-maintenance.md)** - Homebrew tap management
---

## CI/CD Status

[![Kekkai Security Scan](https://github.com/kademoslabs/kekkai/actions/workflows/kekkai-pr-scan.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/kekkai-pr-scan.yml)
[![Docker Image Publish](https://github.com/kademoslabs/kekkai/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/docker-publish.yml)
[![Docker Security Scan](https://github.com/kademoslabs/kekkai/actions/workflows/docker-security-scan.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/docker-security-scan.yml)
[![Cross‑Platform Tests](https://github.com/kademoslabs/kekkai/actions/workflows/test-cross-platform.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/test-cross-platform.yml)
[![Release with SLSA Provenance](https://github.com/kademoslabs/kekkai/actions/workflows/release-slsa.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/release-slsa.yml)
-
