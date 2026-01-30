# CLI-to-Portal Sync Guide

This guide covers syncing scan results from the Kekkai CLI to your Portal instance for centralized visibility and collaboration.

---

## Overview

Kekkai CLI operates locally by default, storing results in `~/.kekkai/`. For teams requiring centralized visibility, results can be synced to Kekkai Portal:

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Developer 1   │         │   Developer 2   │         │   Developer N   │
│   kekkai scan   │         │   kekkai scan   │         │   kekkai scan   │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         │        kekkai upload      │                           │
         └───────────────────────────┼───────────────────────────┘
                                     │
                                     v
                          ┌─────────────────────┐
                          │    Kekkai Portal    │
                          │  Centralized View   │
                          │  Historical Data    │
                          │  Team Collaboration │
                          └─────────────────────┘
```

---

## Prerequisites

- Kekkai CLI installed (`pipx install kekkai-cli`)
- Access to Kekkai Portal (self-hosted or managed)
- Portal API key for your tenant

---

## Authentication Setup

### Obtain API Key

1. Log into Kekkai Portal
2. Navigate to **Settings** → **API Keys**
3. Click **Generate New Key**
4. Copy the key (shown only once)

### Configure CLI

#### Option 1: Environment Variable (Recommended for CI)

```bash
export KEKKAI_PORTAL_API_KEY="kek_your_api_key_here"
export KEKKAI_PORTAL_URL="https://portal.example.com"
```

#### Option 2: Configuration File

Create `~/.kekkairc`:

```yaml
portal:
  url: "https://portal.example.com"
  api_key: "kek_your_api_key_here"
```

**Note**: Protect this file with appropriate permissions:

```bash
chmod 600 ~/.kekkairc
```

#### Option 3: CLI Flag (Not Recommended)

```bash
kekkai upload --portal-key "kek_xxx" --portal-url "https://portal.example.com"
```

**Warning**: Avoid passing keys as CLI arguments in shared environments (visible in process lists).

---

## Uploading Scan Results

### Basic Upload

After running a scan, upload results to Portal:

```bash
# Run scan (creates kekkai-report.json)
kekkai scan

# Upload to Portal
kekkai upload
```

### Upload Specific File

```bash
kekkai upload --file path/to/scan-results.json
```

### Upload with Metadata

```bash
kekkai upload \
  --file kekkai-report.json \
  --project "my-app" \
  --branch "main" \
  --commit "abc123"
```

### Verify Upload

```bash
kekkai upload --dry-run
# Shows what would be uploaded without sending
```

---

## API Reference

### Upload Endpoint

```
POST /api/v1/upload
Authorization: Bearer kek_your_api_key
Content-Type: multipart/form-data
```

#### Request

```bash
curl -X POST "https://portal.example.com/api/v1/upload" \
  -H "Authorization: Bearer kek_your_api_key" \
  -F "file=@kekkai-report.json"
```

#### Response

```json
{
  "success": true,
  "upload_id": "abc123def456",
  "file_hash": "sha256:...",
  "tenant_id": "acme-corp",
  "dojo_product_id": 1,
  "dojo_engagement_id": 10,
  "findings_count": 42
}
```

### List Uploads

```
GET /api/v1/uploads?limit=50
Authorization: Bearer kek_your_api_key
```

#### Response

```json
{
  "uploads": [
    {
      "upload_id": "abc123",
      "filename": "kekkai-report.json",
      "timestamp": "2026-01-30T10:15:30Z",
      "size_bytes": 15234,
      "findings_count": 42
    }
  ]
}
```

### Get Statistics

```
GET /api/v1/stats
Authorization: Bearer kek_your_api_key
```

#### Response

```json
{
  "total_uploads": 156,
  "total_findings": 1247,
  "total_size_bytes": 2456789,
  "last_upload_time": "2026-01-30T10:15:30Z",
  "findings_by_severity": {
    "critical": 12,
    "high": 45,
    "medium": 234,
    "low": 956
  }
}
```

### Get Tenant Info

```
GET /api/v1/tenant/info
Authorization: Bearer kek_your_api_key
```

#### Response

```json
{
  "id": "acme-corp",
  "name": "ACME Corporation",
  "dojo_product_id": 1,
  "dojo_engagement_id": 10,
  "enabled": true,
  "max_upload_size_mb": 50
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Kekkai
        run: pipx install kekkai-cli

      - name: Run Security Scan
        run: kekkai scan --ci --fail-on high

      - name: Upload to Portal
        if: github.ref == 'refs/heads/main'
        env:
          KEKKAI_PORTAL_API_KEY: ${{ secrets.KEKKAI_PORTAL_API_KEY }}
          KEKKAI_PORTAL_URL: ${{ secrets.KEKKAI_PORTAL_URL }}
        run: |
          kekkai upload \
            --project "${{ github.repository }}" \
            --branch "${{ github.ref_name }}" \
            --commit "${{ github.sha }}"
```

### GitLab CI

```yaml
security-scan:
  image: python:3.12
  script:
    - pipx install kekkai-cli
    - kekkai scan --ci --fail-on high
    - |
      if [ "$CI_COMMIT_BRANCH" = "main" ]; then
        kekkai upload \
          --project "$CI_PROJECT_NAME" \
          --branch "$CI_COMMIT_BRANCH" \
          --commit "$CI_COMMIT_SHA"
      fi
  variables:
    KEKKAI_PORTAL_API_KEY: $KEKKAI_PORTAL_API_KEY
    KEKKAI_PORTAL_URL: $KEKKAI_PORTAL_URL
```

### CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Install Kekkai
          command: pipx install kekkai-cli
      - run:
          name: Security Scan
          command: kekkai scan --ci --fail-on high
      - run:
          name: Upload to Portal
          command: |
            if [ "$CIRCLE_BRANCH" = "main" ]; then
              kekkai upload \
                --project "$CIRCLE_PROJECT_REPONAME" \
                --branch "$CIRCLE_BRANCH" \
                --commit "$CIRCLE_SHA1"
            fi
```

---

## Offline Workflow

For air-gapped or restricted environments:

### 1. Scan Locally

```bash
kekkai scan --output scan-results.json
```

### 2. Transfer Results

Copy `scan-results.json` to a system with Portal access.

### 3. Upload Manually

```bash
curl -X POST "https://portal.example.com/api/v1/upload" \
  -H "Authorization: Bearer kek_your_api_key" \
  -F "file=@scan-results.json"
```

---

## Supported File Formats

Portal accepts the following file formats:

| Format | Extension | Description |
|--------|-----------|-------------|
| Kekkai Report | `.json` | Native `kekkai-report.json` format |
| SARIF | `.sarif` | Static Analysis Results Interchange Format |
| Trivy JSON | `.json` | Raw Trivy vulnerability output |
| Semgrep JSON | `.json` | Raw Semgrep findings output |
| Gitleaks JSON | `.json` | Raw Gitleaks secrets output |

The Portal auto-detects format based on content structure.

---

## Migration from CLI-Only

### Step 1: Set Up Portal Access

```bash
export KEKKAI_PORTAL_API_KEY="kek_xxx"
export KEKKAI_PORTAL_URL="https://portal.example.com"
```

### Step 2: Upload Historical Scans

If you have existing scan results:

```bash
# Find all historical scans
find ~/.kekkai/runs -name "*.json" -type f

# Upload each scan
for scan in ~/.kekkai/runs/*/*.json; do
  kekkai upload --file "$scan"
done
```

### Step 3: Update CI Pipeline

Add upload step after scans (see CI/CD Integration above).

### Step 4: Verify in Portal

1. Log into Portal
2. Navigate to **Dashboard**
3. Verify findings appear from uploaded scans

---

## Troubleshooting

### "Missing Authorization header"

**Cause**: API key not configured

**Solution**:
```bash
export KEKKAI_PORTAL_API_KEY="kek_your_key"
```

### "Invalid API key"

**Cause**: API key is incorrect or rotated

**Solution**:
1. Verify key in Portal settings
2. Regenerate if needed
3. Update environment/config

### "File too large"

**Cause**: Upload exceeds tenant limit

**Solution**:
1. Check your tenant's `max_upload_size_mb`
2. Contact admin to increase limit
3. Or split large reports

### "Invalid file type"

**Cause**: Unsupported file format

**Solution**:
- Ensure file is `.json` or `.sarif`
- Verify content is valid JSON

### "Connection refused"

**Cause**: Portal URL incorrect or Portal down

**Solution**:
1. Verify `KEKKAI_PORTAL_URL` is correct
2. Check Portal is accessible
3. Verify no firewall blocking

### Upload Succeeds but No Findings in Portal

**Cause**: File format not recognized

**Solution**:
1. Use native `kekkai-report.json` format
2. Or use SARIF format
3. Check Portal logs for parse errors

---

## Security Considerations

### API Key Protection

- Store API keys in secrets managers
- Never commit keys to version control
- Rotate keys periodically
- Use environment variables in CI

### Network Security

- Always use HTTPS for Portal URL
- Consider VPN for on-premises Portal
- Validate Portal TLS certificate

### Data Sensitivity

- Scan results may contain sensitive paths
- Gitleaks findings include secret locations
- Consider data classification requirements

---

## Related Documentation

- [SAML 2.0 Setup](saml-setup.md) - Configure SSO for Portal access
- [RBAC Configuration](rbac.md) - Permission levels for uploads
- [Multi-Tenant Architecture](multi-tenant.md) - Understanding tenant isolation
- [Deployment Guide](deployment.md) - Deploy your own Portal
- [CI Mode Guide](../ci/ci-mode.md) - CI/CD policy enforcement
