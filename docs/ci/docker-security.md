# Docker Security Guide

Comprehensive security scanning, signing, and SBOM generation for Kekkai Docker images.

---

## Overview

Kekkai implements enterprise-grade Docker security with:

- **Trivy Vulnerability Scanning** - Detect vulnerabilities before publication
- **Cosign Image Signing** - Cryptographically sign images for supply chain security
- **SBOM Generation** - Software Bill of Materials in SPDX format
- **GitHub Security Integration** - Upload scan results to GitHub Security tab
- **Automated PR Scanning** - Block merges with HIGH/CRITICAL vulnerabilities

---

## Security Scanning with Trivy

### Local Scanning

Scan Docker images locally before pushing:

```bash
# Build image
make docker-image

# Run security scan
make docker-scan
```

Expected output:

```
kademoslabs/kekkai:scan (alpine 3.18.4)
===================================
Total: 0 (CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0)
```

### Scan Results

Trivy scans for:
- **OS vulnerabilities** (Alpine packages)
- **Language vulnerabilities** (Python packages)
- **Configuration issues** (Dockerfile best practices)

### Vulnerability Severity Levels

| Severity | Description | Action |
|----------|-------------|--------|
| **CRITICAL** | Immediate security risk | ❌ Block release |
| **HIGH** | Significant security risk | ❌ Block release |
| **MEDIUM** | Moderate security risk | ⚠️ Review required |
| **LOW** | Minor security risk | ✅ Acceptable |
| **UNKNOWN** | Severity not determined | ⚠️ Review required |

### Threshold Enforcement

The CI workflow fails if **HIGH** or **CRITICAL** vulnerabilities are detected:

```yaml
- name: Check for HIGH/CRITICAL vulnerabilities
  run: |
    CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' trivy-results.json)
    HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' trivy-results.json)

    if [[ "$CRITICAL" -gt 0 ]] || [[ "$HIGH" -gt 0 ]]; then
      echo "❌ Found $CRITICAL CRITICAL and $HIGH HIGH vulnerabilities"
      exit 1
    fi
```

---

## Image Signing with Cosign

### Why Sign Images?

Image signing provides:
- **Authenticity** - Verify images are from Kademoslabs
- **Integrity** - Detect tampering or modification
- **Non-repudiation** - Cryptographic proof of origin
- **Supply chain security** - Trust from build to deployment

### Key Management

**Secrets Required** (stored in GitHub Secrets):

```bash
COSIGN_PRIVATE_KEY  # Private key for signing
COSIGN_PASSWORD     # Password protecting private key
```

**Key Generation** (one-time setup):

```bash
# Generate keypair
cosign generate-key-pair

# Outputs:
# - cosign.key (private key - store in GitHub Secrets)
# - cosign.pub (public key - share with users)
```

### Local Signing

Sign images locally:

```bash
# Set environment variables
export COSIGN_PRIVATE_KEY="$(cat cosign.key)"
export COSIGN_PASSWORD="your-password"

# Sign image
make docker-sign
```

### Automated Signing

Images are automatically signed in GitHub Actions on release:

```yaml
- name: Sign Docker image with Cosign
  env:
    COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
    COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}
  run: |
    for tag in $(echo "${{ steps.meta.outputs.tags }}" | tr ',' ' '); do
      echo "Signing image: $tag"
      cosign sign --yes --key cosign.key "$tag"
    done
```

---

## SBOM Generation

### What is SBOM?

A Software Bill of Materials (SBOM) lists all components in the Docker image:

- **Python packages** with versions
- **OS packages** with versions
- **Dependencies** and their relationships
- **Licenses** for each component

### Generate SBOM Locally

```bash
# Generate SBOM in SPDX JSON format
make docker-sbom

# Output: dist/sbom.spdx.json
```

### SBOM Format (SPDX)

Example SBOM structure:

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "name": "kekkai",
  "documentNamespace": "https://github.com/kademoslabs/kekkai",
  "packages": [
    {
      "name": "python",
      "versionInfo": "3.12.2",
      "licenseConcluded": "PSF-2.0"
    },
    {
      "name": "pytest",
      "versionInfo": "7.4.0",
      "licenseConcluded": "MIT"
    }
  ]
}
```

### Automated SBOM

SBOMs are automatically generated and uploaded as artifacts:

```yaml
- name: Generate SBOM
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: kademoslabs/kekkai:scan
    format: spdx-json
    output: sbom.spdx.json

- name: Upload SBOM artifact
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.spdx.json
    retention-days: 90
```

---

## GitHub Security Integration

### SARIF Upload

Scan results are uploaded to GitHub Security tab:

```yaml
- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trivy-results.sarif
    category: trivy-container-scan
```

### View Results

1. Navigate to **Security** tab in GitHub
2. Click **Code scanning alerts**
3. Filter by **trivy-container-scan**

### Security Alerts

GitHub creates alerts for:
- HIGH and CRITICAL vulnerabilities
- Configuration issues
- Dependency vulnerabilities

---

## Pull Request Scanning

### Automated PR Checks

Every PR modifying Docker-related files triggers security scanning:

**Trigger Paths**:
- `apps/kekkai/Dockerfile`
- `requirements/**`
- `pyproject.toml`
- `src/**`

### PR Comments

The workflow comments scan results:

```markdown
## ✅ Docker Security Scan Results

**Status**: No vulnerabilities detected

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 2 |
| 🟢 LOW | 5 |
| **Total** | **7** |
```

### Merge Blocking

PRs with HIGH or CRITICAL vulnerabilities **cannot be merged** until resolved.

---

## Makefile Commands

### Docker Security Commands

```bash
# Scan Docker image for vulnerabilities
make docker-scan

# Sign Docker image with Cosign
make docker-sign

# Verify Docker image signature
make docker-verify

# Generate SBOM for Docker image
make docker-sbom

# Run Docker security unit tests
make docker-security-test
```

### Prerequisites

Install required tools:

```bash
# Trivy (vulnerability scanner)
# macOS
brew install trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Cosign (image signing)
# macOS
brew install cosign

# Linux
wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign
```

---

## Threat Model

### Abuser Stories & Mitigations

| Abuser Story | Mitigation |
|--------------|------------|
| **AS-1**: Attacker publishes backdoored image | ✅ Cosign signing, signature verification required |
| **AS-2**: Attacker exploits known CVE in dependency | ✅ Trivy scanning, fail on HIGH/CRITICAL |
| **AS-3**: Attacker replaces legitimate image on Docker Hub | ✅ Cosign signatures prevent undetected tampering |
| **AS-4**: Attacker exploits supply chain via compromised dependency | ✅ SBOM tracks all dependencies, pin versions |
| **AS-5**: Insider threat: malicious code in PR | ✅ Automated PR scanning blocks vulnerable code |

### Outstanding Risks

1. **Cosign Key Compromise**
   - **Risk**: If private key is compromised, attacker can sign malicious images
   - **Mitigation**: Key stored in GitHub Secrets (encrypted), implement key rotation
   - **Follow-up**: Document key rotation procedure

2. **False Negatives in Trivy**
   - **Risk**: CVE not yet in vulnerability database
   - **Mitigation**: Keep Trivy database updated, supplement with additional scanners
   - **Follow-up**: Consider adding Grype or Snyk

3. **Zero-Day Vulnerabilities**
   - **Risk**: Vulnerabilities not yet disclosed
   - **Mitigation**: Monitor security advisories, rapid patching process
   - **Follow-up**: Implement daily rescans of published images

---

## Best Practices

### For Developers

1. **Run local scans** before pushing Docker changes
2. **Review scan results** in PRs before requesting review
3. **Update base images** regularly (python:3.12-slim)
4. **Pin dependencies** to specific versions
5. **Minimize image layers** to reduce attack surface

### For Maintainers

1. **Rotate Cosign keys** annually or after suspected compromise
2. **Monitor GitHub Security alerts** weekly
3. **Rescan published images** monthly for new CVEs
4. **Document security incidents** in `.docs/operations/security-incidents.md`
5. **Review SBOM** before each release

### For Users

1. **Verify image signatures** before deployment (see [Verification Guide](docker-verification.md))
2. **Review SBOM** to understand dependencies
3. **Pull specific versions** (not `:latest` in production)
4. **Monitor for security updates** from Kademoslabs
5. **Report vulnerabilities** to security@kademos.org

---

## Troubleshooting

### Trivy Scan Fails

**Problem**: `trivy: command not found`

**Solution**: Install Trivy (see [Prerequisites](#prerequisites))

---

**Problem**: Scan times out after 10 minutes

**Solution**: Increase timeout in workflow:

```yaml
timeout: 15m
```

---

### Cosign Signing Fails

**Problem**: `COSIGN_PRIVATE_KEY not set`

**Solution**: Set environment variable:

```bash
export COSIGN_PRIVATE_KEY="$(cat cosign.key)"
export COSIGN_PASSWORD="your-password"
```

---

**Problem**: `signing failed: unauthorized`

**Solution**: Ensure you're logged in to Docker Hub:

```bash
docker login
```

---

### SBOM Generation Fails

**Problem**: `invalid SPDX format`

**Solution**: Ensure Trivy version is up to date:

```bash
trivy --version  # Should be >= 0.45.0
```

---

## Related Documentation

- [Docker Verification Guide](docker-verification.md) - How to verify image signatures
- [Docker Usage Guide](docker-usage.md) - Running Kekkai in Docker
- [CI Architecture](./.docs/development/ci-architecture.md) - CI/CD overview
- [Security Incident Response](./.docs/operations/security-incidents.md) - Handling vulnerabilities

---

## Support

For security issues:

1. **Vulnerabilities**: Email security@kademos.org (do NOT file public issue)
2. **Questions**: [GitHub Discussions](https://github.com/kademoslabs/kekkai/discussions)
3. **Bugs**: [GitHub Issues](https://github.com/kademoslabs/kekkai/issues)
