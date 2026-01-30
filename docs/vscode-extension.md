# Kekkai VS Code Extension

The Kekkai VS Code extension brings security scanning directly into your editor, providing real-time feedback on vulnerabilities, code issues, and secrets as you develop.

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "Kekkai Security Scanner"
4. Click Install

### From VSIX Package

1. Download the `.vsix` file from the releases page
2. In VS Code: Extensions > ... > Install from VSIX
3. Select the downloaded file

## Getting Started

### Prerequisites

The extension requires the Kekkai CLI to be installed:

```bash
# Using pipx (recommended)
pipx install kekkai-cli

# Using pip
pip install kekkai-cli

# Verify installation
kekkai --version
```

### Your First Scan

1. Open a project folder in VS Code
2. Press **Ctrl+Shift+K** (Cmd+Shift+K on Mac)
3. View results in the Problems panel

## Features

### Inline Diagnostics

Security findings appear directly in your code:

- **Red underline** - Critical/High severity
- **Yellow underline** - Medium severity
- **Blue underline** - Low severity
- **Gray underline** - Informational

### Hover Information

Hover over any underlined code to see:

- Issue title and severity
- Scanner that detected it (Trivy/Semgrep/Gitleaks)
- CWE ID with link to MITRE database
- CVE ID with link to NVD
- Full description

### Quick Fixes

For Semgrep findings, AI-powered fixes are available:

1. Position cursor on the finding
2. Press **Ctrl+.** (Cmd+. on Mac)
3. Select "Fix: [issue description]"
4. Review the suggested change
5. Click "Apply" to fix

### Status Bar

The status bar shows scan status:

- **$(shield) Kekkai** - Ready to scan
- **$(sync~spin) Scanning...** - Scan in progress
- **$(check) 0 issues** - No findings
- **$(warning) N issues** - Findings detected

Click the status bar item to trigger a scan.

## Configuration

### Settings

Access settings via File > Preferences > Settings > Extensions > Kekkai.

| Setting | Description |
|---------|-------------|
| **CLI Path** | Path to `kekkai` executable (default: `kekkai`) |
| **Auto Scan on Save** | Run scan when files are saved |
| **Scan Debounce** | Minimum time between scans |
| **Scan Timeout** | Maximum scan duration |
| **Native Mode** | Use local binaries instead of Docker |
| **Enabled Scanners** | Toggle individual scanners |
| **Show Hover Details** | Enable/disable hover information |
| **Enable Quick Fix** | Enable/disable AI fix suggestions |

### Scanner Configuration

Enable or disable specific scanners:

```json
{
  "kekkai.enabledScanners": {
    "trivy": true,
    "semgrep": true,
    "gitleaks": true
  }
}
```

### Native Mode

If Docker is unavailable, use native scanner binaries:

```json
{
  "kekkai.nativeMode": true
}
```

This requires Trivy, Semgrep, and Gitleaks to be installed locally.

## Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| **Kekkai: Run Security Scan** | Ctrl+Shift+K | Run full security scan |
| **Kekkai: Clear Diagnostics** | - | Clear all findings |
| **Kekkai: Apply Quick Fix** | Ctrl+. | Apply AI-generated fix |

## Security Considerations

### Workspace Trust

The extension respects VS Code's workspace trust feature:

- In **untrusted** workspaces, a warning is shown before scanning
- User must explicitly approve scanning untrusted code
- Auto-scan-on-save is disabled in untrusted workspaces

### Rate Limiting

Built-in rate limiting prevents resource exhaustion:

- Default: 30 seconds between scans
- Configurable via `kekkai.scanDebounceMs`
- Scan-in-progress prevents duplicate scans

### Local Processing

- **No telemetry** - All processing happens locally
- **No cloud sync** - Findings stay on your machine
- **No external calls** - Except when using remote LLM for fixes

### Docker Sandbox

When using Docker mode (default):

- Scanners run in isolated containers
- Read-only access to your code
- No network access during scanning
- Memory and CPU limits enforced

## Troubleshooting

### "kekkai command not found"

The CLI is not in your PATH. Either:

1. Add it to PATH:
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```

2. Or set a custom path in settings:
   ```json
   {
     "kekkai.cliPath": "/home/user/.local/bin/kekkai"
   }
   ```

### Scan Times Out

Increase the timeout:

```json
{
  "kekkai.scanTimeoutMs": 600000
}
```

### Docker Not Available

Switch to native mode:

```json
{
  "kekkai.nativeMode": true
}
```

Install scanners locally:

```bash
# Trivy
brew install trivy  # macOS
# Or: https://trivy.dev/latest/getting-started/installation/

# Semgrep
pipx install semgrep

# Gitleaks
brew install gitleaks  # macOS
# Or: https://github.com/gitleaks/gitleaks#installing
```

### Quick Fix Not Working

Quick fixes are only available for:

- Semgrep findings (not Trivy or Gitleaks)
- Findings with a rule_id
- When `kekkai.enableQuickFix` is enabled

Ensure the Kekkai CLI has fix support:

```bash
kekkai fix --help
```

### High CPU Usage

If scans consume too many resources:

1. Increase debounce time:
   ```json
   {
     "kekkai.scanDebounceMs": 60000
   }
   ```

2. Disable auto-scan:
   ```json
   {
     "kekkai.autoScanOnSave": false
   }
   ```

3. Disable some scanners:
   ```json
   {
     "kekkai.enabledScanners": {
       "trivy": false,
       "semgrep": true,
       "gitleaks": true
     }
   }
   ```

## Development

### Building from Source

```bash
cd apps/vscode-kekkai
npm install
npm run compile
```

### Running Tests

```bash
npm test
```

### Packaging

```bash
npm install -g @vscode/vsce
vsce package
```

## Version History

### 0.2.0

- Added hover provider with detailed finding information
- Added code action provider with AI-powered quick fixes
- Added scanner configuration settings
- Added native mode support
- Added keyboard shortcut (Ctrl+Shift+K)
- Improved status bar with findings count

### 0.1.0

- Initial release
- Basic scan command
- Diagnostics display
- Rate limiting
- Workspace trust support
