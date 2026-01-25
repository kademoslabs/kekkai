# Homebrew Tap Maintenance Guide

Guide for maintaining the Kekkai Homebrew formula in `kademoslabs/homebrew-tap`.

## Overview

Kekkai is distributed via a Homebrew tap for easy installation on macOS and Linux:

```bash
brew tap kademoslabs/tap
brew install kekkai
```

This guide covers how to update the formula after each release.

---

## Repository Structure

The Homebrew tap is a separate repository: `kademoslabs/homebrew-tap`

```
homebrew-tap/
├── Formula/
│   └── kekkai.rb        # Formula definition
└── README.md
```

---

## Release Workflow

### 1. Create Release in kekkai-cli Repository

The release script (`scripts/release.sh`) generates:

- Wheel: `dist/kekkai-{version}-py3-none-any.whl`
- Source tarball: `dist/kekkai-{version}.tar.gz`
- SBOM: `dist/requirements-frozen.txt`
- **Checksums**: `dist/checksums.txt` (sha256 for .tar.gz)

### 2. Extract SHA256 from Release

After running `make release`:

```bash
# View checksums
cat dist/checksums.txt

# Example output:
# a1b2c3d4e5f6... dist/kekkai-0.0.1.tar.gz
```

### 3. Update Formula in homebrew-tap

Edit `Formula/kekkai.rb`:

```ruby
class Kekkai < Formula
  desc "Security that moves at developer speed"
  homepage "https://github.com/kademoslabs/kekkai-cli"
  url "https://github.com/kademoslabs/kekkai-cli/archive/refs/tags/v0.0.1.tar.gz"
  sha256 "a1b2c3d4e5f6..."  # <-- Update this with sha256 from checksums.txt
  license "Apache-2.0"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/kekkai", "--version"
  end
end
```

### 4. Test Formula Locally

```bash
# Tap local formula
brew tap kademoslabs/tap /path/to/homebrew-tap

# Install
brew install kademoslabs/tap/kekkai

# Test
kekkai --version

# Uninstall for testing reinstall
brew uninstall kekkai
```

### 5. Commit and Push

```bash
cd homebrew-tap
git add Formula/kekkai.rb
git commit -m "chore: bump kekkai to v0.0.1"
git push origin main
```

### 6. Verify Installation

```bash
# Fresh install test
brew untap kademoslabs/tap
brew tap kademoslabs/tap
brew install kekkai
kekkai --version
```

---

## Formula Template

Complete formula template for reference:

```ruby
class Kekkai < Formula
  include Language::Python::Virtualenv

  desc "Local-first AppSec orchestration for Trivy, Semgrep, and DefectDojo"
  homepage "https://github.com/kademoslabs/kekkai-cli"
  url "https://github.com/kademoslabs/kekkai-cli/archive/refs/tags/v{VERSION}.tar.gz"
  sha256 "{SHA256}"
  license "Apache-2.0"

  depends_on "python@3.12"

  # Define Python dependencies here if needed
  # resource "some-dependency" do
  #   url "https://files.pythonhosted.org/..."
  #   sha256 "..."
  # end

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/kekkai", "--version"
    system "#{bin}/kekkai", "--help"
  end
end
```

---

## Automation (Future)

### Automated Formula Updates

For automated updates, add to `.github/workflows/release.yml` in kekkai-cli:

```yaml
- name: Update Homebrew Formula
  env:
    HOMEBREW_TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
  run: |
    VERSION="${GITHUB_REF#refs/tags/v}"
    SHA256=$(sha256sum dist/kekkai-${VERSION}.tar.gz | cut -d' ' -f1)

    # Clone tap repo
    git clone https://${HOMEBREW_TAP_TOKEN}@github.com/kademoslabs/homebrew-tap.git
    cd homebrew-tap

    # Update formula
    sed -i "s|url \".*\"|url \"https://github.com/kademoslabs/kekkai-cli/archive/refs/tags/v${VERSION}.tar.gz\"|" Formula/kekkai.rb
    sed -i "s|sha256 \".*\"|sha256 \"${SHA256}\"|" Formula/kekkai.rb

    # Commit and push
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add Formula/kekkai.rb
    git commit -m "chore: bump kekkai to v${VERSION}"
    git push origin main
```

---

## Troubleshooting

### Formula Audit Fails

Run Homebrew's audit:

```bash
brew audit --strict Formula/kekkai.rb
```

Common issues:
- Invalid URL (404)
- SHA256 mismatch
- Missing license
- Incorrect Python version

### Installation Fails for Users

Check formula syntax:

```bash
brew install --verbose --debug kademoslabs/tap/kekkai
```

### Version Mismatch

Ensure `--version` output matches formula version:

```bash
kekkai --version  # Should show: 0.0.1 (or current version)
```

Update version in `pyproject.toml` before release.

---

## Best Practices

### 1. Follow Homebrew Python Guidelines

- Use `virtualenv_install_with_resources` for Python apps
- Specify Python version dependency: `depends_on "python@3.12"`
- Isolate dependencies in formula virtualenv

Reference: [Homebrew Python for Formula Authors](https://docs.brew.sh/Python-for-Formula-Authors)

### 2. Test on Multiple Platforms

Test formula on:
- macOS (ARM64)
- macOS (x86_64)
- Linux (if applicable)

### 3. Keep Formula Simple

- Avoid complex install logic
- Use standard Homebrew DSL
- Document non-standard configurations

### 4. Verify SHA256 Integrity

Always verify checksums match:

```bash
# In kekkai-cli repo
sha256sum dist/kekkai-{version}.tar.gz

# Should match sha256 in Formula/kekkai.rb
```

---

## Release Checklist

- [ ] Run `make release` in kekkai-cli
- [ ] Extract SHA256 from `dist/checksums.txt`
- [ ] Update `Formula/kekkai.rb` with new version and SHA256
- [ ] Test formula locally (`brew install --build-from-source`)
- [ ] Run `brew audit --strict Formula/kekkai.rb`
- [ ] Commit and push to homebrew-tap
- [ ] Verify fresh install from tap works
- [ ] Test `kekkai --version` shows correct version
- [ ] Update tap README if needed

---

## Related Links

- [Homebrew Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Homebrew Python Guidelines](https://docs.brew.sh/Python-for-Formula-Authors)
- [Homebrew Tap Documentation](https://docs.brew.sh/Taps)
- [kademoslabs/homebrew-tap](https://github.com/kademoslabs/homebrew-tap)

---

## Support

For tap maintenance issues:

- **GitHub**: Open issue in [homebrew-tap repository](https://github.com/kademoslabs/homebrew-tap/issues)
- **Homebrew Help**: `brew doctor` for diagnostics
- **Security**: [security@kademos.org](mailto:security@kademos.org)
