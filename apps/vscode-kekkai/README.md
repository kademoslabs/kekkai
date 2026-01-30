# Kekkai Security Scanner for VS Code

**Local-first security scanning integrated into VS Code** with real-time diagnostics, hover details, and AI-powered quick fixes.

## Features

### Real-Time Security Scanning

- Run security scans with **Ctrl+Shift+K** (Cmd+Shift+K on Mac)
- Automatic scanning on file save (opt-in)
- Results displayed in the Problems panel

### Integrated Diagnostics

- Security findings appear as inline warnings/errors
- Red underlines for critical/high severity issues
- Yellow underlines for medium severity issues
- Blue underlines for low severity issues

### Hover Details

Hover over any finding to see:
- Severity level with visual indicator
- Scanner that detected the issue
- CWE/CVE links when available
- Full description
- Quick fix availability hint

### AI-Powered Quick Fixes

For Semgrep findings:
- Press **Ctrl+.** (Cmd+. on Mac) to see available fixes
- Preview the suggested fix before applying
- One-click remediation using the `kekkai fix` engine

### Scanner Configuration

Enable/disable individual scanners:
- **Trivy** - Vulnerability scanning (SCA)
- **Semgrep** - Static analysis (SAST)
- **Gitleaks** - Secret detection

## Requirements

- [Kekkai CLI](https://github.com/kademoslabs/kekkai) installed and available in PATH
- Docker (for containerized scanning) or native scanner binaries

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `kekkai.cliPath` | `kekkai` | Path to kekkai CLI executable |
| `kekkai.autoScanOnSave` | `false` | Automatically scan when files are saved |
| `kekkai.scanDebounceMs` | `30000` | Minimum time between scans (ms) |
| `kekkai.scanTimeoutMs` | `300000` | Maximum scan duration (ms) |
| `kekkai.nativeMode` | `false` | Use native scanner binaries instead of Docker |
| `kekkai.enabledScanners.trivy` | `true` | Enable Trivy vulnerability scanner |
| `kekkai.enabledScanners.semgrep` | `true` | Enable Semgrep SAST scanner |
| `kekkai.enabledScanners.gitleaks` | `true` | Enable Gitleaks secret scanner |
| `kekkai.showHoverDetails` | `true` | Show detailed finding information on hover |
| `kekkai.enableQuickFix` | `true` | Enable AI-powered quick fix suggestions |

## Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| `Kekkai: Run Security Scan` | Ctrl+Shift+K | Run a full security scan |
| `Kekkai: Clear Diagnostics` | - | Clear all security findings |
| `Kekkai: Apply Quick Fix` | Ctrl+. | Apply an AI-generated fix |

## Security

- **Workspace Trust**: Scans only run in trusted workspaces by default
- **Rate Limiting**: Built-in protection against excessive scanning
- **Local-First**: No telemetry, all processing happens locally
- **Sandboxed**: Docker containers provide isolation

## Troubleshooting

### Kekkai CLI not found

Ensure `kekkai` is installed and in your PATH:
```bash
pipx install kekkai-cli
kekkai --version
```

Or configure a custom path in settings:
```json
{
  "kekkai.cliPath": "/path/to/kekkai"
}
```

### Scan timeout

Increase the timeout in settings:
```json
{
  "kekkai.scanTimeoutMs": 600000
}
```

### Docker issues

If Docker is unavailable, enable native mode:
```json
{
  "kekkai.nativeMode": true
}
```

Note: Native mode requires Trivy, Semgrep, and Gitleaks to be installed locally.

## License

MIT - See [LICENSE](https://github.com/kademoslabs/kekkai/blob/main/LICENSE)

## Links

- [Kekkai CLI](https://github.com/kademoslabs/kekkai)
- [Documentation](https://github.com/kademoslabs/kekkai/tree/main/docs)
- [Report Issues](https://github.com/kademoslabs/kekkai/issues)
