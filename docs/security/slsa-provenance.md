# SLSA Level 3 Provenance

Kekkai releases are built with [SLSA Level 3](https://slsa.dev/spec/v1.0/levels) compliant provenance, providing cryptographic proof of the build process.

## What is SLSA?

SLSA (Supply-chain Levels for Software Artifacts) is a security framework that provides guarantees about software supply chain integrity. Level 3 ensures:

- **Source Integrity**: Code comes from the expected repository
- **Build Integrity**: Artifacts are built in an isolated, tamper-resistant environment
- **Provenance**: Non-forgeable attestation of the build process

## Verifying Kekkai Releases

### Prerequisites

Install the [slsa-verifier](https://github.com/slsa-framework/slsa-verifier):

```bash
# macOS
brew install slsa-verifier

# Linux
curl -sSfL https://github.com/slsa-framework/slsa-verifier/releases/latest/download/slsa-verifier-linux-amd64 -o slsa-verifier
chmod +x slsa-verifier
sudo mv slsa-verifier /usr/local/bin/
```

### Verify a Release

1. Download the release artifact and provenance:

```bash
VERSION=1.0.0
curl -LO https://github.com/kademoslabs/kekkai/releases/download/v${VERSION}/kekkai-${VERSION}-py3-none-any.whl
curl -LO https://github.com/kademoslabs/kekkai/releases/download/v${VERSION}/multiple.intoto.jsonl
```

2. Verify the provenance:

```bash
slsa-verifier verify-artifact kekkai-${VERSION}-py3-none-any.whl \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/kademoslabs/kekkai
```

3. Expected output on success:

```
Verified signature against tlog entry index X at URL: https://rekor.sigstore.dev/api/v1/log/entries/...
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
Verifying artifact kekkai-X.X.X-py3-none-any.whl: PASSED
```

### Using Make Target

```bash
make slsa-verify ARTIFACT=dist/kekkai-1.0.0-py3-none-any.whl
```

## Cosign Signatures

In addition to SLSA provenance, release artifacts are signed with [Cosign](https://docs.sigstore.dev/cosign/overview/):

```bash
# Verify signature (requires cosign)
cosign verify-blob \
  --signature kekkai-${VERSION}-py3-none-any.whl.sig \
  --certificate-identity-regexp ".*github.com/kademoslabs/kekkai.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  kekkai-${VERSION}-py3-none-any.whl
```

## Security Guarantees

| SLSA Level | Guarantee | Implementation |
|------------|-----------|----------------|
| L1 | Build script exists | GitHub Actions workflow |
| L2 | Hosted build platform | GitHub-hosted runners |
| L3 | Non-forgeable provenance | slsa-github-generator |
| L3 | Isolated build | Ephemeral runners, no persistent credentials |

## Troubleshooting

### "slsa-verifier not found"

Install slsa-verifier as shown in Prerequisites.

### "source URI mismatch"

Ensure you're verifying an official kekkai release from `github.com/kademoslabs/kekkai`.

### "verification failed"

The artifact may have been tampered with. Do not use it. Report the issue at https://github.com/kademoslabs/kekkai/security/advisories.

## Further Reading

- [SLSA Specification](https://slsa.dev/spec/v1.0/)
- [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)
- [Sigstore](https://www.sigstore.dev/)
