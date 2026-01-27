# Automated Distribution Updates

Comprehensive guide for Kekkai's automated distribution trigger system.

---

## Overview

When a new Kekkai release is published (tag `v*.*.*`), the automated distribution system triggers updates across all distribution channels:

- **Homebrew tap** - Updates formula with new version/SHA256
- **Docker Hub** - Publishes new container images
- **Scoop bucket** - Updates manifest (with Excavator workaround)
- **Chocolatey** - Publishes new package

This is achieved through GitHub Actions workflow that orchestrates repository_dispatch events.

---

## Architecture

```
GitHub Release (v0.0.1)
         ↓
Trigger Distribution Workflow (.github/workflows/trigger-distributions.yml)
         ↓
    Extract Metadata
    - Version: 0.0.1
    - SHA256: abc123...
    - Tarball URL
         ↓
    Validate Metadata
    - Semver format
    - SHA256 format
    - Tarball accessible
         ↓
    ┌────────────────────────────────────┐
    │    Parallel Distribution Triggers   │
    ├────────────────────────────────────┤
    │  ✅ Homebrew Tap                   │
    │  ✅ Docker Hub                     │
    │  ✅ Scoop Bucket                   │
    │  ✅ Chocolatey                     │
    └────────────────────────────────────┘
         ↓
    Notify Success/Failure
```

---

## Automatic Triggers

### On Release Publication

When you publish a GitHub release with tag `v*.*.*`:

1. **Workflow automatically starts** (`.github/workflows/trigger-distributions.yml`)
2. **Metadata extracted** from tag and release tarball
3. **Version validated** (semantic versioning)
4. **SHA256 calculated** from release tarball
5. **Distribution channels triggered** via repository_dispatch
6. **Notifications sent** on success or failure

**Example:**
```bash
# Create and push tag
git tag v0.0.1
git push origin v0.0.1

# Publish release on GitHub UI
# → Workflow automatically triggers all distributions
```

---

## Manual Triggers

### Via GitHub Actions UI

For hotfixes or re-triggering failed distributions:

1. Go to **Actions** tab in GitHub
2. Select **Trigger Distribution Updates** workflow
3. Click **Run workflow**
4. Fill inputs:
   - **version**: `0.0.1` (without 'v' prefix)
   - **sha256**: Leave empty to auto-calculate, or provide checksum
   - **dry_run**: `true` for testing (skips actual triggers)
5. Click **Run workflow**

### Via GitHub CLI

```bash
gh workflow run trigger-distributions.yml \
  --field version=0.0.1 \
  --field sha256= \
  --field dry_run=false
```

### Dry Run Mode

Test the workflow without triggering actual distribution updates:

```bash
gh workflow run trigger-distributions.yml \
  --field version=0.0.1-test \
  --field dry_run=true
```

This validates metadata extraction and version format without sending repository_dispatch events.

---

## Distribution Channels

### 1. Homebrew Tap

**Repository**: `kademoslabs/homebrew-tap`
**Trigger**: `repository_dispatch` event with `event_type: kekkai-release`
**Payload**:
```json
{
  "version": "0.0.1",
  "sha256": "abc123..."
}
```

**Manual Update**:
```bash
# In homebrew-tap repository
# Edit Formula/kekkai.rb
class Kekkai < Formula
  url "https://github.com/kademoslabs/kekkai/archive/refs/tags/v0.0.1.tar.gz"
  sha256 "abc123..."
end

git commit -am "chore: bump kekkai to v0.0.1"
git push origin main
```

### 2. Docker Hub

**Repository**: `kademoslabs/kekkai` (Docker Hub)
**Trigger**: `workflow_dispatch` to `.github/workflows/docker-publish.yml`
**Input**:
```yaml
tag: "0.0.1"
```

**Manual Update**:
```bash
# In kekkai repository
gh workflow run docker-publish.yml --field tag=0.0.1
```

### 3. Scoop Bucket

**Repository**: `kademoslabs/scoop-bucket`
**Trigger**: `repository_dispatch` event with `event_type: kekkai-release`
**Payload**:
```json
{
  "version": "0.0.1",
  "sha256": "abc123..."
}
```

**Known Issue**: Excavator auto-update has issues (read-only repository). Manual verification may be required.

**Manual Update**:
```bash
# In scoop-bucket repository
# Edit bucket/kekkai.json
{
  "version": "0.0.1",
  "url": "https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
  "hash": "abc123..."
}

git commit -am "kekkai: Update to version 0.0.1"
git push origin main
```

### 4. Chocolatey

**Repository**: `kademoslabs/chocolatey-packages`
**Trigger**: `repository_dispatch` event with `event_type: kekkai-release`
**Payload**:
```json
{
  "version": "0.0.1",
  "sha256": "abc123..."
}
```

**Manual Update**:
```bash
# In chocolatey-packages repository
# Edit kekkai/kekkai.nuspec
<?xml version="1.0"?>
<package>
  <metadata>
    <version>0.0.1</version>
  </metadata>
</package>

# Edit kekkai/tools/chocolateyinstall.ps1 with new SHA256

choco pack
choco push kekkai.0.0.1.nupkg --source https://push.chocolatey.org/
```

---

## Troubleshooting

### Workflow Fails with "Invalid version format"

**Cause**: Tag doesn't match semantic versioning (e.g., `v1.2` instead of `v1.2.0`)

**Solution**:
```bash
# Use full semver format
git tag v0.0.1  # ✅ Correct
git tag v0.0    # ❌ Invalid
```

### Workflow Fails with "SHA256 mismatch"

**Cause**: Provided SHA256 doesn't match calculated checksum

**Solution**:
1. Leave `sha256` input empty to auto-calculate
2. Or verify SHA256 manually:
   ```bash
   wget https://github.com/kademoslabs/kekkai/archive/refs/tags/v0.0.1.tar.gz
   sha256sum v0.0.1.tar.gz
   ```

### Workflow Fails with "Tarball not accessible"

**Cause**: GitHub release or tag doesn't exist

**Solution**:
1. Verify tag exists: `git tag -l v0.0.1`
2. Verify release published on GitHub
3. Wait a few minutes for GitHub to process release

### Distribution Trigger Sent but No Update

**Cause**: Target repository may not have `repository_dispatch` workflow configured

**Solution**:
1. Check target repository's `.github/workflows/` for dispatch handler
2. Verify GitHub token has `repo` and `workflow` permissions
3. Manually trigger update in target repository

### "Unauthorized" Error

**Cause**: GitHub token missing or expired

**Solution**:
1. Verify secrets configured:
   - `TAP_REPO_TOKEN`
   - `SCOOP_REPO_TOKEN`
   - `CHOCO_REPO_TOKEN`
2. Rotate tokens if expired
3. Verify token has `repo` scope

---

## Rollback Procedures

### Rollback Homebrew

```bash
# In homebrew-tap repository
git revert HEAD
git push origin main

# Users can rollback
brew uninstall kekkai
brew install kademoslabs/tap/kekkai@OLD_VERSION
```

### Rollback Docker Hub

```bash
# Tags cannot be deleted from Docker Hub
# Users can use previous tag
docker pull kademoslabs/kekkai:OLD_VERSION
```

### Rollback Scoop

```bash
# In scoop-bucket repository
git revert HEAD
git push origin main

# Users can rollback
scoop reset kekkai@OLD_VERSION
```

### Rollback Chocolatey

**Note**: Chocolatey packages cannot be deleted once published.

**Options**:
1. **Publish new version** with fixes
2. **Unlist package** (contact Chocolatey support)
3. **Notify users** to pin previous version:
   ```powershell
   choco install kekkai --version OLD_VERSION
   ```

---

## Monitoring

### Check Workflow Status

```bash
# List recent workflow runs
gh run list --workflow=trigger-distributions.yml

# View specific run
gh run view RUN_ID

# View logs
gh run view RUN_ID --log
```

### Check Distribution Updates

**Homebrew**:
```bash
brew info kademoslabs/tap/kekkai
```

**Docker Hub**:
```bash
docker pull kademoslabs/kekkai:latest
docker inspect kademoslabs/kekkai:latest | grep -A5 Labels
```

**Scoop**:
```bash
scoop info kekkai
```

**Chocolatey**:
```powershell
choco info kekkai
```

---

## Notifications

### Automatic Failure Notifications

When distribution triggers fail, a GitHub issue is automatically created with:

- **Title**: `Distribution update failed for vX.Y.Z`
- **Labels**: `distribution`, `automation`, `ci-failure`
- **Body**: Workflow run link, version, and manual recovery commands

### Manual Notification Setup (Optional)

Add Slack webhook for real-time notifications:

1. Create Slack webhook URL
2. Add `SLACK_WEBHOOK` secret to repository
3. Uncomment Slack notification in workflow (see workflow file)

---

## Security Considerations

### Token Management

- **Use fine-grained PATs** with minimal scopes (`repo`, `workflow`)
- **Rotate tokens regularly** (every 90 days)
- **Monitor token usage** in GitHub security logs
- **Never commit tokens** to repository

### Input Validation

- All version inputs validated against semantic versioning
- SHA256 checksums verified before distribution
- Repository names validated against GitHub format
- Network failures handled with graceful errors

### Rate Limiting

- GitHub API rate limit: 5,000 requests/hour (authenticated)
- Workflow implements retry logic with exponential backoff
- Manual triggers should be used sparingly

---

## Best Practices

### 1. Test with Dry Run First

```bash
gh workflow run trigger-distributions.yml \
  --field version=0.0.1-test \
  --field dry_run=true
```

### 2. Verify Release Artifacts Before Triggering

```bash
# Check release exists
gh release view v0.0.1

# Verify tarball accessible
curl -I https://github.com/kademoslabs/kekkai/archive/refs/tags/v0.0.1.tar.gz
```

### 3. Monitor Distribution Updates

After triggering, verify each distribution:
- Homebrew: Check `Formula/kekkai.rb` updated
- Docker Hub: Verify new tag appears
- Scoop: Check `bucket/kekkai.json` updated
- Chocolatey: Verify package published

### 4. Document Pre-release Versions

Use semver pre-release for testing:
```bash
git tag v0.0.1-rc1    # Release candidate
git tag v0.0.1-alpha  # Alpha release
git tag v0.0.1-beta   # Beta release
```

---

## FAQ

**Q: How long does it take for distributions to update?**
A: Typically 2-5 minutes for triggers to complete. Chocolatey moderation may take 24-48 hours.

**Q: Can I trigger specific distributions only?**
A: No, the workflow triggers all distributions. For selective updates, use manual update procedures.

**Q: What if I made a mistake in the release?**
A: Create a new patch version (e.g., v0.0.2) with fixes. Don't attempt to reuse version numbers.

**Q: Do I need to trigger distributions manually for every release?**
A: No, distributions are triggered automatically on release publication.

**Q: What's the difference between release and workflow_dispatch trigger?**
A: `release` trigger is automatic (on tag push + GitHub release), `workflow_dispatch` is manual (via Actions UI or CLI).

---

## Related Documentation

- [CI Architecture](../../.docs/development/ci-architecture.md)
- [Homebrew Maintenance](./homebrew-maintenance.md)
- [Docker Usage](./docker-usage.md)
- [Release Process](../../.docs/development/release.md)

---

## Support

**For distribution automation issues**:
- GitHub: [kademoslabs/kekkai/issues](https://github.com/kademoslabs/kekkai/issues)
- Label: `distribution`, `automation`

**For security issues**:
- Email: security@kademos.org
- Security Policy: [SECURITY.md](../../.github/SECURITY.md)
