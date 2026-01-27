# Docker Image Verification Guide

How to verify Kekkai Docker image signatures and integrity before deployment.

---

## Overview

All Kekkai Docker images published to Docker Hub are:

- ✅ **Cryptographically signed** with Cosign
- ✅ **Scanned for vulnerabilities** with Trivy (zero HIGH/CRITICAL)
- ✅ **Accompanied by SBOM** in SPDX format
- ✅ **Multi-architecture** (linux/amd64, linux/arm64)

This guide shows you how to **verify image authenticity** before use.

---

## Why Verify Images?

**Threats Mitigated**:

1. **Man-in-the-Middle Attacks** - Ensure image wasn't tampered during download
2. **Registry Compromise** - Detect if Docker Hub was compromised
3. **Supply Chain Attacks** - Verify image comes from Kademoslabs
4. **Malicious Actors** - Prevent running backdoored images

**Trust Model**:

```
Kademoslabs CI → Signs with Cosign → Pushes to Docker Hub
                        ↓
                  You verify signature
                        ↓
               Deploy with confidence
```

---

## Prerequisites

### Install Cosign

**macOS**:

```bash
brew install cosign
```

**Linux**:

```bash
# Download latest release
wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64

# Install
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign

# Verify installation
cosign version
```

**Windows**:

```powershell
# Using Scoop
scoop bucket add sigstore https://github.com/sigstore/sigstore-scoop-bucket
scoop install cosign

# Or download from GitHub Releases
```

---

## Verification Methods

### Method 1: Keyless Verification (Recommended)

Kekkai uses Sigstore's keyless signing with fulcio and rekor:

```bash
# Verify latest image
cosign verify kademoslabs/kekkai:latest
```

**Expected Output**:

```json
Verification for kademoslabs/kekkai:latest --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### Method 2: Public Key Verification

If Kademoslabs provides a public key (cosign.pub):

```bash
# Download public key
curl -O https://raw.githubusercontent.com/kademoslabs/kekkai/main/cosign.pub

# Verify with public key
cosign verify --key cosign.pub kademoslabs/kekkai:latest
```

### Method 3: Certificate-Based Verification

Verify using certificate identity:

```bash
# Verify certificate matches GitHub Actions
cosign verify kademoslabs/kekkai:latest \
  --certificate-identity="https://github.com/kademoslabs/kekkai/.github/workflows/docker-publish.yml@refs/tags/v*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

---

## Verify Specific Versions

### Verify Tagged Version

```bash
# Verify v0.0.1 release
cosign verify kademoslabs/kekkai:v0.0.1

# Verify v0.0.2-rc1
cosign verify kademoslabs/kekkai:v0.0.2-rc1
```

### Verify by Digest

Most secure - verify specific image digest:

```bash
# Get image digest
docker pull kademoslabs/kekkai:latest
docker inspect kademoslabs/kekkai:latest --format='{{.RepoDigests}}'

# Example output: [kademoslabs/kekkai@sha256:abc123...]

# Verify digest
cosign verify kademoslabs/kekkai@sha256:abc123...
```

---

## Automated Verification in CI/CD

### GitHub Actions

```yaml
name: Deploy Kekkai

on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Verify Kekkai image
        run: |
          cosign verify kademoslabs/kekkai:latest

      - name: Deploy Kekkai
        run: |
          kubectl apply -f kekkai-deployment.yaml
```

### GitLab CI

```yaml
verify_and_deploy:
  image: alpine:latest
  before_script:
    - apk add --no-cache curl
    - wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -O /usr/local/bin/cosign
    - chmod +x /usr/local/bin/cosign
  script:
    - cosign verify kademoslabs/kekkai:latest
    - docker run kademoslabs/kekkai:latest scan
```

### CircleCI

```yaml
version: 2.1

jobs:
  verify:
    docker:
      - image: cimg/base:stable
    steps:
      - run:
          name: Install Cosign
          command: |
            wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
            sudo mv cosign-linux-amd64 /usr/local/bin/cosign
            sudo chmod +x /usr/local/bin/cosign

      - run:
          name: Verify Image
          command: cosign verify kademoslabs/kekkai:latest
```

---

## Verify SBOM

### Download SBOM

SBOMs are attached to images:

```bash
# Download SBOM
cosign download sbom kademoslabs/kekkai:latest > sbom.spdx.json

# View SBOM
cat sbom.spdx.json | jq .
```

### Verify SBOM Signature

```bash
# Verify SBOM is signed
cosign verify-attestation kademoslabs/kekkai:latest
```

### Parse SBOM for Specific Packages

```bash
# Check if specific package is present
cat sbom.spdx.json | jq '.packages[] | select(.name=="pytest")'

# List all Python packages
cat sbom.spdx.json | jq '.packages[] | select(.name | startswith("python")) | .name'

# Check for known vulnerable packages
cat sbom.spdx.json | jq '.packages[] | select(.name=="pillow" and .versionInfo=="9.0.0")'
```

---

## Docker Content Trust (DCT)

### Enable DCT

Docker Content Trust provides additional layer of verification:

```bash
# Enable DCT
export DOCKER_CONTENT_TRUST=1

# Pull image (will verify signature)
docker pull kademoslabs/kekkai:latest
```

**Note**: DCT uses Notary (different from Cosign). Kekkai primarily uses Cosign.

---

## Verification Policies

### Policy 1: Require Signature Verification

Always verify signatures before deployment:

```bash
#!/bin/bash
set -e

IMAGE="kademoslabs/kekkai:latest"

echo "Verifying image signature..."
cosign verify "$IMAGE"

if [ $? -eq 0 ]; then
  echo "✅ Signature verified. Proceeding with deployment..."
  docker run "$IMAGE" scan
else
  echo "❌ Signature verification failed. Aborting."
  exit 1
fi
```

### Policy 2: Block Unsigned Images

Kubernetes admission controller (using OPA Gatekeeper):

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: VerifyImages
metadata:
  name: require-cosign-signature
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    images:
      - "kademoslabs/kekkai:*"
    publicKeys:
      - key: |
          -----BEGIN PUBLIC KEY-----
          ...
          -----END PUBLIC KEY-----
```

### Policy 3: Verify in Docker Compose

Add verification step to startup:

```yaml
version: '3.8'

services:
  kekkai:
    image: kademoslabs/kekkai:latest
    entrypoint: /bin/sh
    command:
      - -c
      - |
        echo "Verifying image..."
        cosign verify kademoslabs/kekkai:latest || exit 1
        kekkai scan
```

---

## Troubleshooting

### Verification Fails: No Signatures Found

**Problem**:

```
Error: no matching signatures: crypto/rsa: verification error
```

**Possible Causes**:

1. **Image not signed** - Old image before signing was implemented
2. **Wrong image name** - Typo in image name
3. **Network issues** - Cannot reach Sigstore infrastructure

**Solution**:

```bash
# Check image exists
docker pull kademoslabs/kekkai:latest

# Verify image name is correct
docker images | grep kekkai

# Test Sigstore connectivity
curl -I https://rekor.sigstore.dev
```

---

### Verification Fails: Certificate Error

**Problem**:

```
Error: certificate verification failed
```

**Solution**:

Ensure Cosign version is up to date:

```bash
cosign version  # Should be >= 2.0.0
```

Update if needed:

```bash
brew upgrade cosign  # macOS
```

---

### Keyless Verification Not Working

**Problem**:

```
Error: verifying image: fetching OIDC token
```

**Cause**: Keyless signing requires GitHub Actions OIDC

**Solution**: Use public key verification instead (Method 2)

---

### SBOM Download Fails

**Problem**:

```
Error: downloading SBOM: no attestations found
```

**Cause**: SBOM may not be attached to all images

**Solution**: Download from GitHub Artifacts:

1. Go to https://github.com/kademoslabs/kekkai/actions
2. Find release workflow run
3. Download SBOM artifact

---

## Security Best Practices

### For Production Deployments

1. **Always verify signatures** before deploying
2. **Use specific versions** (not `:latest`) in production
3. **Pin image digests** for maximum security
4. **Verify SBOM** to understand dependencies
5. **Implement admission controllers** to enforce policies

### For CI/CD Pipelines

1. **Verify in pipeline** before deploying
2. **Cache verification results** to avoid rate limits
3. **Fail fast** if verification fails
4. **Log verification status** for audit trail
5. **Rotate keys** if compromise suspected

### For Development

1. **Verify signatures** even in development
2. **Use signed images** for testing
3. **Report unsigned images** to security team
4. **Document verification** in README
5. **Educate team** on importance of verification

---

## Verification Checklist

Before deploying Kekkai to production:

- [ ] Cosign installed and working
- [ ] Image signature verified
- [ ] SBOM downloaded and reviewed
- [ ] No HIGH or CRITICAL vulnerabilities (check GitHub Security)
- [ ] Image version matches release notes
- [ ] Multi-arch support confirmed (if deploying to ARM)
- [ ] Verification automated in CI/CD
- [ ] Team trained on verification process

---

## Related Documentation

- [Docker Security Guide](docker-security.md) - Comprehensive security overview
- [Docker Usage Guide](docker-usage.md) - Running Kekkai in Docker
- [Security Incident Response](./.docs/operations/security-incidents.md) - What to do if verification fails
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/) - Official Cosign docs

---

## Support

### Verification Issues

If you encounter issues verifying images:

1. **Check GitHub Issues**: https://github.com/kademoslabs/kekkai/issues
2. **Security Contact**: security@kademos.org (for urgent security matters)
3. **Community Support**: [GitHub Discussions](https://github.com/kademoslabs/kekkai/discussions)

### Report Unsigned Images

If you find an unsigned Kekkai image:

1. **Do NOT use the image**
2. **Report immediately** to security@kademos.org
3. **Include**: Image name, tag, digest, and where you found it

---

## Public Key Distribution

Kademoslabs' Cosign public keys are available at:

- **GitHub Repository**: https://github.com/kademoslabs/kekkai/blob/main/cosign.pub
- **Keybase**: https://keybase.io/kademoslabs
- **Website**: https://kademos.org/.well-known/cosign.pub

**Fingerprint** (example):

```
SHA256: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99
```

---

**Last Updated**: 2026-01-27
**Next Review**: After key rotation or security incident
