# Chocolatey Integration Guide

Technical guide for Kekkai's Chocolatey package integration and enterprise Windows distribution.

---

## Overview

Kekkai is distributed on Windows via **Chocolatey**, a command-line package manager designed for enterprise environments. This guide covers the technical implementation, nuspec structure, PowerShell scripts, and automation workflow.

---

## Architecture

```
GitHub Release (v0.0.1)
         ↓
Trigger Distribution Workflow
         ↓
    Extract Metadata
    - Version: 0.0.1
    - SHA256 of .whl file
    - Wheel URL
         ↓
    Dispatch to Chocolatey Packages
    (kademoslabs/chocolatey-packages)
         ↓
    Generate Package Structure
    - kekkai.nuspec (NuGet spec)
    - tools/chocolateyinstall.ps1
    - tools/chocolateyuninstall.ps1
    - VERIFICATION.txt
         ↓
    Build NuGet Package
    $ choco pack
         ↓
    Publish to Chocolatey Community
    $ choco push kekkai.{version}.nupkg
         ↓
    Chocolatey Users Can Install
    $ choco install kekkai
```

---

## Chocolatey Package Structure

### NuGet Package Specification (kekkai.nuspec)

The nuspec defines metadata and package behavior.

```xml
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>kekkai</id>
    <version>0.0.1</version>
    <title>Kekkai</title>
    <authors>Kademos Labs</authors>
    <owners>Kademos Labs</owners>
    <licenseUrl>https://github.com/kademoslabs/kekkai/blob/main/LICENSE</licenseUrl>
    <projectUrl>https://github.com/kademoslabs/kekkai</projectUrl>
    <iconUrl>https://raw.githubusercontent.com/kademoslabs/kekkai/main/docs/assets/icon.png</iconUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>
      Kekkai - Local-first AppSec orchestration and compliance checker.
      Integrates security scanning tools (Semgrep, Trivy, Gitleaks, OWASP ZAP)
      with DefectDojo for centralized vulnerability management.
    </description>
    <summary>Local-first AppSec orchestration and compliance checker</summary>
    <tags>security appsec cli devsecops vulnerability-scanner compliance</tags>
    <copyright>2024-2026 Kademos Labs</copyright>
    <dependencies>
      <dependency id="python" version="[3.12,)" />
    </dependencies>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
```

**Key Fields**:
- **id**: Package identifier (lowercase, no spaces)
- **version**: Semantic version (e.g., 0.0.1, 1.0.0-rc1)
- **dependencies**: Python 3.12+ required via Chocolatey
- **files**: PowerShell scripts in `tools/` directory

---

### Installation Script (chocolateyinstall.ps1)

PowerShell script that handles installation logic.

```powershell
# Kekkai Chocolatey Installation Script
$ErrorActionPreference = 'Stop'

$packageName = 'kekkai'
$version = '0.0.1'
$url = 'https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl'
$checksum = 'abc123...'  # SHA256 checksum
$checksumType = 'sha256'

Write-Host "Installing $packageName version $version..."

# Validate Python availability
try {
    $pythonCmd = Get-Command python -ErrorAction Stop
    Write-Host "Found Python: $($pythonCmd.Source)"
} catch {
    throw "Python not found in PATH. Please install Python 3.12+ first."
}

# Validate Python version
$pythonVersionOutput = python --version 2>&1 | Out-String
if ($pythonVersionOutput -match "Python (\d+\.\d+)") {
    $installedVersion = [version]$matches[1]
    $requiredVersion = [version]"3.12"

    if ($installedVersion -lt $requiredVersion) {
        throw "Python 3.12+ required, found $installedVersion"
    }

    Write-Host "Python version check passed: $installedVersion"
} else {
    throw "Could not parse Python version"
}

# Download wheel file to temp location
$tempDir = Join-Path $env:TEMP "kekkai-$version"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$whlFile = Join-Path $tempDir "kekkai-$version-py3-none-any.whl"

Write-Host "Downloading wheel from: $url"
try {
    Invoke-WebRequest -Uri $url -OutFile $whlFile -UseBasicParsing
} catch {
    throw "Failed to download wheel: $_"
}

# Verify checksum
Write-Host "Verifying checksum..."
$actualChecksum = (Get-FileHash -Path $whlFile -Algorithm SHA256).Hash
if ($actualChecksum -ne $checksum) {
    throw "Checksum mismatch! Expected: $checksum, Got: $actualChecksum"
}
Write-Host "Checksum verified: $actualChecksum"

# Install via pip
Write-Host "Installing via pip..."
python -m pip install --force-reinstall --no-deps $whlFile

if ($LASTEXITCODE -ne 0) {
    throw "pip install failed"
}

# Cleanup
Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue

Write-Host "✅ $packageName installed successfully!"
Write-Host "Run 'kekkai --help' to get started."
```

**Security Features**:
- ✅ HTTPS-only downloads
- ✅ SHA256 checksum verification
- ✅ Python version validation
- ✅ No `Invoke-Expression` or remote code execution
- ✅ Minimal script logic
- ✅ `--no-deps` flag prevents dependency confusion attacks

---

### Uninstallation Script (chocolateyuninstall.ps1)

PowerShell script for clean removal.

```powershell
# Kekkai Chocolatey Uninstallation Script
$ErrorActionPreference = 'Continue'

$packageName = 'kekkai'

Write-Host "Uninstalling $packageName..."

try {
    python -m pip uninstall -y kekkai

    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ $packageName uninstalled successfully"
    } else {
        Write-Warning "$packageName may not have been installed or was already removed"
    }
} catch {
    Write-Warning "Uninstall encountered an issue: $_"
}
```

**Design Principles**:
- ✅ Graceful failure handling (`ErrorActionPreference = 'Continue'`)
- ✅ No hard failures on uninstall errors
- ✅ Clear user feedback

---

## Package Generation API

### Python API

Kekkai includes utilities to generate Chocolatey packages programmatically.

```python
from kekkai_core.windows.chocolatey import (
    generate_nuspec,
    format_nuspec_xml,
    generate_chocolatey_package_structure,
    generate_verification_file,
)

# Generate nuspec
nuspec = generate_nuspec(
    version="0.0.1",
    sha256="abc123...",  # 64-char hex
    whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
    python_version="3.12",
)

# Convert to XML
nuspec_xml = format_nuspec_xml(nuspec)

# Generate complete package structure
structure = generate_chocolatey_package_structure(
    version="0.0.1",
    sha256="abc123...",
)

# structure = {
#     "kekkai.nuspec": "<?xml version...",
#     "tools/chocolateyinstall.ps1": "# Kekkai...",
#     "tools/chocolateyuninstall.ps1": "# Kekkai...",
# }

# Generate VERIFICATION.txt for moderation
verification = generate_verification_file(
    version="0.0.1",
    sha256="abc123...",
)
```

### Validation

```python
from kekkai_core.windows.chocolatey import validate_nuspec
from kekkai_core.windows.validators import validate_chocolatey_nuspec

# Validate nuspec dictionary
validate_nuspec(nuspec)  # Returns True or raises ValueError

# Validate nuspec XML file
from pathlib import Path
is_valid, errors = validate_chocolatey_nuspec(Path("kekkai.nuspec"))

if not is_valid:
    for error in errors:
        print(f"Error: {error}")
```

---

## Automation Workflow

### GitHub Actions Trigger

The `trigger-distributions.yml` workflow automatically triggers Chocolatey updates on release.

```yaml
trigger-chocolatey:
  name: Trigger Chocolatey Package Update
  runs-on: ubuntu-latest
  needs: [extract-metadata, validate-metadata]

  steps:
    - name: Send repository_dispatch to chocolatey-packages
      run: |
        VERSION="${{ needs.extract-metadata.outputs.version }}"
        SHA256="${{ needs.extract-metadata.outputs.sha256 }}"

        curl -X POST \
          -H "Accept: application/vnd.github+json" \
          -H "Authorization: Bearer ${{ secrets.CHOCO_REPO_TOKEN }}" \
          https://api.github.com/repos/kademoslabs/chocolatey-packages/dispatches \
          -d "{
            \"event_type\": \"kekkai-release\",
            \"client_payload\": {
              \"version\": \"$VERSION\",
              \"sha256\": \"$SHA256\"
            }
          }"
```

### Chocolatey Package Repository Workflow

In the `kademoslabs/chocolatey-packages` repository:

```yaml
name: Update Chocolatey Package

on:
  repository_dispatch:
    types: [kekkai-release]

jobs:
  update-package:
    runs-on: windows-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Generate package structure
        run: |
          $VERSION = "${{ github.event.client_payload.version }}"
          $SHA256 = "${{ github.event.client_payload.sha256 }}"

          # Use Python to generate package
          python -c "
          from kekkai_core.windows.chocolatey import generate_chocolatey_package_structure
          structure = generate_chocolatey_package_structure('$VERSION', '$SHA256')

          for path, content in structure.items():
              import os
              os.makedirs(os.path.dirname(path), exist_ok=True)
              with open(path, 'w') as f:
                  f.write(content)
          "

      - name: Build package
        run: choco pack

      - name: Push to Chocolatey
        env:
          CHOCO_API_KEY: ${{ secrets.CHOCO_API_KEY }}
        run: |
          choco push kekkai.${{ github.event.client_payload.version }}.nupkg --source https://push.chocolatey.org/ --api-key $env:CHOCO_API_KEY
```

---

## Publishing Workflow

### Local Testing

```powershell
# 1. Generate package structure
python -c "from kekkai_core.windows.chocolatey import generate_chocolatey_package_structure; ..."

# 2. Build package
choco pack

# 3. Test locally
choco install kekkai -s . -y

# 4. Verify installation
kekkai --version
kekkai --help

# 5. Uninstall
choco uninstall kekkai -y
```

### Publishing to Chocolatey Community

```powershell
# 1. Build package
choco pack

# 2. Push to Chocolatey (requires API key)
choco push kekkai.0.0.1.nupkg --source https://push.chocolatey.org/ --api-key YOUR_API_KEY
```

### Chocolatey Moderation Process

1. **Submit Package**: Push `.nupkg` to Chocolatey community
2. **Automated Tests**: Chocolatey runs automated scans
3. **Manual Review**: Moderators review scripts and metadata
4. **Approval/Rejection**: Package approved or feedback provided
5. **Published**: Available via `choco install kekkai`

**Typical Timeline**: 24-48 hours for initial submission, faster for updates.

---

## Enterprise Deployment

### Silent Installation

```powershell
# Install without user interaction
choco install kekkai -y --force

# Install specific version
choco install kekkai --version 0.0.1 -y

# Install with logging
choco install kekkai -y --log-file="C:\Logs\kekkai-install.log"
```

### Offline Installation

```powershell
# 1. Download package on internet-connected machine
choco download kekkai

# 2. Transfer .nupkg file to offline machine

# 3. Install from local file
choco install kekkai -s . -y
```

### Group Policy / SCCM Deployment

Chocolatey packages can be deployed via:
- **Group Policy**: Use startup scripts
- **SCCM**: Create application package
- **Ansible**: Use `win_chocolatey` module

---

## Troubleshooting

### Common Issues

#### Issue: "Python not found in PATH"

**Cause**: Python not installed or not in PATH

**Solution**:
```powershell
# Install Python via Chocolatey
choco install python -y

# Verify
python --version
```

---

#### Issue: "Checksum mismatch"

**Cause**: Downloaded file corrupted or URL changed

**Solution**:
```powershell
# Clear cache and retry
choco uninstall kekkai
choco install kekkai -y --force
```

---

#### Issue: "pip install failed"

**Cause**: pip not available or network issues

**Solution**:
```powershell
# Verify pip
python -m pip --version

# Upgrade pip
python -m pip install --upgrade pip

# Retry installation
choco install kekkai -y --force
```

---

#### Issue: "Package under moderation"

**Cause**: New version submitted but not yet approved

**Solution**: Wait for moderation (24-48 hours), or install previous version:
```powershell
choco install kekkai --version 0.0.1
```

---

## Security Considerations

### Threat Model

**Abuse Scenario 1: Arbitrary PowerShell Execution**
- ✅ **Mitigated**: Minimal script logic, no `Invoke-Expression`
- ✅ **Mitigated**: Code review required for script changes
- 🔄 **Future**: PowerShell script signing with code signing certificate

**Abuse Scenario 2: Backdoored Python Package**
- ✅ **Mitigated**: SHA256 checksum verification before install
- ✅ **Mitigated**: `--no-deps` flag prevents dependency confusion
- ✅ **Mitigated**: Download from GitHub releases only (HTTPS)

**Abuse Scenario 3: Privilege Escalation**
- ✅ **Mitigated**: Minimal privileged operations
- ✅ **Mitigated**: Input validation on all user-provided data
- ✅ **Mitigated**: Follow principle of least privilege

**Abuse Scenario 4: Package Tampering**
- ✅ **Mitigated**: HTTPS-only downloads
- ✅ **Mitigated**: Checksum verification (download + verify before install)
- 🔄 **Future**: Package signing with Authenticode certificate

---

## Testing

### Unit Tests

```bash
# Test Chocolatey module
pytest tests/windows/test_chocolatey_*.py -v

# Test installer scripts
pytest tests/windows/test_chocolatey_scripts.py -v
```

### Integration Tests

```bash
# Test package structure generation
pytest tests/integration/test_chocolatey_*.py -v
```

### Regression Tests

```bash
# Test backwards compatibility
pytest tests/regression/test_chocolatey_*.py -v
```

---

## Related Documentation

- [Windows Installation Guide](../installation/windows.md) - User-facing installation instructions
- [Scoop Integration](./scoop-integration.md) - Alternative Windows package manager
- [Automated Distributions](./automated-distributions.md) - CI/CD trigger workflow
- [Chocolatey Official Docs](https://docs.chocolatey.org/en-us/create/create-packages)

---

## Support

For issues with Chocolatey packages:
- **GitHub Issues**: https://github.com/kademoslabs/chocolatey-packages/issues
- **Chocolatey Package Page**: https://community.chocolatey.org/packages/kekkai

---

**Last Updated**: 2026-01-27
