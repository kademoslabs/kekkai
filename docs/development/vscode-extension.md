# VS Code Extension Development

The Kekkai VS Code extension integrates security scanning directly into VS Code, displaying findings in the Problems panel.

## Features

- **Manual Scanning**: Run `Kekkai: Run Security Scan` command
- **Problem Panel Integration**: Findings appear as VS Code diagnostics
- **Rate Limiting**: Prevents scan spam (30s minimum between scans)
- **Workspace Trust**: Prompts for confirmation in untrusted workspaces

## Prerequisites

- Node.js 20+
- VS Code 1.85+
- Kekkai CLI installed and available in PATH

## Development Setup

```bash
# Install dependencies
make vscode-setup

# Build the extension
make vscode-build

# Run tests
make vscode-test

# Lint TypeScript code
make vscode-lint
```

## Project Structure

```
apps/vscode-kekkai/
├── package.json        # Extension manifest
├── tsconfig.json       # TypeScript configuration
├── src/
│   ├── extension.ts    # Main entry point, activation
│   ├── diagnostics.ts  # Finding → Diagnostic mapping
│   ├── sanitize.ts     # XSS/injection prevention
│   └── types.ts        # TypeScript type definitions
└── test/
    ├── extension.test.ts
    ├── diagnostics.test.ts
    ├── sanitize.test.ts
    └── runTests.ts
```

## Security Considerations

### Rate Limiting
- Configurable debounce (default: 30 seconds)
- Prevents resource exhaustion from repeated scans

### Workspace Trust
- Scans in untrusted workspaces require explicit confirmation
- Auto-scan on save is disabled for untrusted workspaces

### Output Sanitization
- All finding content is HTML-escaped before display
- Error messages redact file paths to prevent information disclosure
- Maximum string lengths enforced to prevent buffer issues

## Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `kekkai.scanDebounceMs` | 30000 | Minimum time between scans (ms) |
| `kekkai.autoScanOnSave` | false | Auto-scan when files are saved |
| `kekkai.cliPath` | "kekkai" | Path to kekkai CLI executable |
| `kekkai.scanTimeoutMs` | 300000 | Maximum scan duration (5 min) |

## Building for Release

```bash
# Package as .vsix
make vscode-package
```

The resulting `.vsix` file can be installed via VS Code's "Install from VSIX" command.

## Testing

Tests use the `@vscode/test-electron` framework:

```bash
# Run all extension tests
make vscode-test
```

Test coverage includes:
- Sanitization functions (XSS prevention)
- Diagnostic mapping (severity conversion, range calculation)
- Rate limiting logic
- Configuration handling

## Threat Model

| Threat | Mitigation |
|--------|------------|
| XSS via finding content | HTML-encode all displayed text |
| Resource exhaustion | Rate limiting, timeout protection |
| Arbitrary code execution | Workspace trust checks |
| Path disclosure in errors | Error message sanitization |
