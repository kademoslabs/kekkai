# Scoop Integration Guide

Technical guide for Kekkai's Scoop bucket integration and Windows distribution.

---

## Overview

Kekkai is distributed on Windows via **Scoop**, a command-line package manager that doesn't require administrator privileges. This guide covers the technical implementation, manifest structure, and automation workflow.

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
    Dispatch to Scoop Bucket
    (kademoslabs/scoop-bucket)
         ↓
    Update kekkai.json Manifest
    - Version
    - URL to .whl
    - SHA256 hash
    - Installer script
    - Uninstaller script
         ↓
    Scoop Users Can Install
    $ scoop install kademoslabs/kekkai
```

---

## Scoop Manifest Structure

### kekkai.json

The Scoop manifest defines how Kekkai is installed on Windows.

```json
{
  "version": "0.0.1",
  "description": "Kekkai - Local-first AppSec orchestration and compliance checker",
  "homepage": "https://github.com/kademoslabs/kekkai",
  "license": "MIT",
  "depends": "python",
  "url": "https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
  "hash": "SHA256_CHECKSUM_HERE",
  "installer": {
    "script": [
      "# Python version validation",
      "$pythonVersion = python --version 2>&1 | Select-String -Pattern \"Python (\\d+\\.\\d+)\"",
      "$version = [version]$pythonVersion.Matches.Groups[1].Value",
      "if ($version -lt [version]\"3.12\") {",
      "    Write-Error \"Python 3.12+ required, found $version\"",
      "    exit 1",
      "}",
      "",
      "# Install wheel via pip",
      "python -m pip install --force-reinstall --no-deps \"https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl\"",
      "if ($LASTEXITCODE -ne 0) {",
      "    Write-Error \"pip install failed\"",
      "    exit 1",
      "}"
    ]
  },
  "uninstaller": {
    "script": [
      "python -m pip uninstall -y kekkai"
    ]
  },
  "checkver": {
    "github": "https://github.com/kademoslabs/kekkai"
  },
  "autoupdate": {
    "url": "https://github.com/kademoslabs/kekkai/releases/download/v$version/kekkai-$version-py3-none-any.whl"
  },
  "notes": [
    "Kekkai has been installed successfully!",
    "Run 'kekkai --help' to get started.",
    "For documentation, visit: https://github.com/kademoslabs/kekkai"
  ]
}
```

---

## Manifest Generation

### Python API

Kekkai includes utilities to generate and validate Scoop manifests programmatically.

```python
from kekkai_core.windows.scoop import generate_scoop_manifest, validate_scoop_manifest

# Generate manifest
manifest = generate_scoop_manifest(
    version="0.0.1",
    sha256="abcd1234...",
    whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
    python_version="3.12"
)

# Validate manifest
is_valid = validate_scoop_manifest(manifest)
```

### CLI Usage

```bash
# Generate manifest for new release
python -c "
from kekkai_core.windows.scoop import generate_scoop_manifest, format_scoop_manifest_json
import hashlib

version = '0.0.1'
whl_url = f'https://github.com/kademoslabs/kekkai/releases/download/v{version}/kekkai-{version}-py3-none-any.whl'

# Calculate SHA256 (in real scenario, download the file first)
sha256 = 'YOUR_CHECKSUM_HERE'

manifest = generate_scoop_manifest(version, sha256, whl_url)
print(format_scoop_manifest_json(manifest))
" > kekkai.json
```

---

## Installer Script

### PowerShell Implementation

The installer script performs:

1. **Python Version Validation**
   ```powershell
   $pythonVersion = python --version 2>&1 | Select-String -Pattern "Python (\d+\.\d+)"
   $version = [version]$pythonVersion.Matches.Groups[1].Value
   if ($version -lt [version]"3.12") {
       Write-Error "Python 3.12+ required, found $version"
       exit 1
   }
   ```

2. **Wheel Installation via pip**
   ```powershell
   python -m pip install --force-reinstall --no-deps "WHEEL_URL"
   ```

### Security Considerations

- **No `Invoke-Expression`** - Prevents arbitrary code execution
- **HTTPS-only URLs** - Prevents man-in-the-middle attacks
- **SHA256 verification** - Scoop verifies checksum before running installer
- **Minimal logic** - Reduces attack surface
- **Explicit error handling** - Clear error messages, fails fast

---

## Uninstaller Script

```powershell
python -m pip uninstall -y kekkai
```

**Features:**
- Silent uninstall (`-y` flag)
- Graceful failure handling
- No leftover files (pip handles cleanup)

---

## Automation Workflow

### Trigger on Release

When a GitHub release is published:

1. **GitHub Actions** runs `trigger-distributions.yml`
2. **Metadata extracted**:
   - Version from tag
   - SHA256 from .whl file
   - Wheel URL from GitHub release
3. **Repository dispatch** sent to `kademoslabs/scoop-bucket`
4. **Scoop bucket workflow** updates `kekkai.json`
5. **Users can install** via `scoop install kademoslabs/kekkai`

### Manual Update

For emergency updates or hotfixes:

```bash
# In scoop-bucket repository
cd bucket

# Edit kekkai.json
# Update version, url, hash

git add kekkai.json
git commit -m "kekkai: Update to version X.Y.Z"
git push origin main
```

---

## Excavator Workaround

**Issue**: ScoopInstaller/Excavator is read-only and has no public releases.

**Solution**: Custom auto-update workflow in `scoop-bucket` repository.

### Custom Update Workflow

`.github/workflows/auto-update.yml` in `scoop-bucket` repository:

```yaml
name: Auto-update Kekkai Manifest

on:
  repository_dispatch:
    types: [kekkai-release]
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to update to'
        required: true
      sha256:
        description: 'SHA256 of wheel file'
        required: true

jobs:
  update-manifest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Update kekkai.json
        run: |
          VERSION="${{ github.event.client_payload.version || inputs.version }}"
          SHA256="${{ github.event.client_payload.sha256 || inputs.sha256 }}"

          # Update manifest
          jq --arg v "$VERSION" \
             --arg s "$SHA256" \
             --arg u "https://github.com/kademoslabs/kekkai/releases/download/v$VERSION/kekkai-$VERSION-py3-none-any.whl" \
             '.version = $v | .hash = $s | .url = $u' \
             bucket/kekkai.json > bucket/kekkai.json.tmp

          mv bucket/kekkai.json.tmp bucket/kekkai.json

      - name: Commit changes
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add bucket/kekkai.json
          git commit -m "kekkai: Update to version ${VERSION}"
          git push
```

---

## Testing

### Local Testing

```powershell
# Generate test manifest
python -c "from kekkai_core.windows.scoop import generate_scoop_manifest, format_scoop_manifest_json; print(format_scoop_manifest_json(generate_scoop_manifest('0.0.1', 'a'*64, 'https://test.com/test.whl')))" > test-kekkai.json

# Test installation locally
scoop install test-kekkai.json
```

### Validation Tests

```bash
# Run Windows unit tests
make windows-unit

# Run Windows integration tests
make windows-integration

# Run all Windows tests
make windows-test
```

---

## Troubleshooting

### Issue: SHA256 Mismatch

**Symptom:**
```
ERROR The hash of kekkai-0.0.1-py3-none-any.whl does not match
```

**Cause:** Incorrect SHA256 in manifest

**Solution:**
1. Download wheel from GitHub release
2. Calculate correct SHA256:
   ```powershell
   Get-FileHash -Algorithm SHA256 kekkai-0.0.1-py3-none-any.whl
   ```
3. Update manifest with correct hash

---

### Issue: Python Not Found

**Symptom:**
```
ERROR 'python' is not recognized
```

**Cause:** Python not in PATH or not installed

**Solution:**
```powershell
# Install Python via Scoop
scoop install python

# Or point to existing Python
# Add to PATH manually
```

---

### Issue: pip Install Failed

**Symptom:**
```
ERROR pip install failed
```

**Cause:** Network issues, pip not available, or dependency conflicts

**Solution:**
```powershell
# Ensure pip is available
python -m pip --version

# Upgrade pip
python -m pip install --upgrade pip

# Check network connectivity
Test-NetConnection pypi.org -Port 443
```

---

### Issue: Manifest Validation Failed

**Symptom:** Scoop rejects manifest

**Cause:** Invalid JSON or missing required fields

**Solution:**
```bash
# Validate manifest programmatically
python -c "
from kekkai_core.windows.scoop import validate_scoop_manifest
import json

with open('kekkai.json') as f:
    manifest = json.load(f)

try:
    validate_scoop_manifest(manifest)
    print('✅ Manifest is valid')
except ValueError as e:
    print(f'❌ Validation failed: {e}')
"
```

---

## Security

### Threat Model

1. **Malicious Package Replacement**
   - **Risk**: Attacker replaces wheel file
   - **Mitigation**: SHA256 checksum verified by Scoop before installation

2. **Arbitrary Code Execution**
   - **Risk**: Malicious code in installer script
   - **Mitigation**: Minimal script logic, no `Invoke-Expression`, code review

3. **Man-in-the-Middle**
   - **Risk**: MITM during download
   - **Mitigation**: HTTPS-only URLs, SHA256 verification

4. **Dependency Confusion**
   - **Risk**: pip installs wrong package
   - **Mitigation**: Direct URL installation, `--no-deps` flag

### Security Checklist

- ✅ All URLs use HTTPS
- ✅ SHA256 checksums verified
- ✅ No `Invoke-Expression` in scripts
- ✅ Minimal installer logic
- ✅ Python version validated
- ✅ Error handling prevents silent failures
- ✅ Scoop bucket repository has branch protection

---

## Best Practices

### Manifest Updates

1. **Always verify SHA256** before updating manifest
2. **Test locally** before pushing to main
3. **Use semantic versioning** for consistency
4. **Document changes** in commit messages
5. **Monitor installations** for issues

### Release Coordination

1. **GitHub release first** (creates artifacts)
2. **Wait for artifact propagation** (CDN delays)
3. **Trigger distribution** (automated or manual)
4. **Verify Scoop update** within 5 minutes
5. **Test installation** on clean Windows VM

---

## Monitoring

### Scoop Bucket Analytics

Monitor installations via GitHub API:

```powershell
# Check manifest commit history
Invoke-RestMethod -Uri "https://api.github.com/repos/kademoslabs/scoop-bucket/commits?path=bucket/kekkai.json" | Select-Object -First 5
```

### User Feedback

Monitor GitHub issues for:
- Installation failures
- SHA256 mismatch errors
- Python compatibility issues
- Network/proxy problems

---

## Related Documentation

- [Windows Installation Guide](../installation/windows.md)
- [Automated Distribution Updates](./automated-distributions.md)
- [Chocolatey Integration](./chocolatey-integration.md) (Future milestone)
- [Release Process](../../.docs/development/release.md)

---

## References

- [Scoop Documentation](https://scoop.sh/)
- [Scoop Manifest Reference](https://github.com/ScoopInstaller/Scoop/wiki/App-Manifests)
- [Python Packaging](https://packaging.python.org/en/latest/)
- [Semantic Versioning](https://semver.org/)

---

## Support

**For Scoop installation issues:**
- GitHub: [kademoslabs/scoop-bucket/issues](https://github.com/kademoslabs/scoop-bucket/issues)

**For Kekkai issues:**
- GitHub: [kademoslabs/kekkai/issues](https://github.com/kademoslabs/kekkai/issues)

**For security issues:**
- Email: security@kademos.org
- Security Policy: [SECURITY.md](../../.github/SECURITY.md)
