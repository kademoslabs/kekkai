# 🛡️ Kekkai v1.1.1 - Bug Fixes and Report Generation

**Improved triage workflow and DefectDojo upload reliability.**

This is a maintenance release that fixes critical issues with scanner result parsing, DefectDojo uploads, and adds unified report generation capabilities.

## ⚡ Highlights

- **Fixed Triage Blank Screen** - Raw scanner outputs (Semgrep/Trivy/Gitleaks JSON) now load correctly
- **Fixed DefectDojo Uploads** - Eliminated "Unknown scanner" errors for `*-results.json` files
- **Unified Report Generation** - New command to generate consolidated scan reports
- **Improved Security** - Added file size limits (200MB) and enhanced error message sanitization

## 🐛 Bug Fixes

### Triage Improvements
- Fixed blank screen when loading raw scanner outputs (Semgrep/Trivy/Gitleaks JSON)
- Automatic default to latest run directory when `--input` is omitted
- Findings now deduplicated by `scanner:rule_id:file_path:line`

### DefectDojo Upload Fixes
- Fixed "Unknown scanner" errors for `*-results.json` files (gitleaks-results, trivy-results, semgrep-results)
- Now uses canonical scanner parsers (eliminates duplicate parsing logic)
- Fixed scanner name mapping for DefectDojo imports (correct scan types now sent)
- Fixed potential crash on empty/204 responses (proper response.read() handling)

### Code Quality
- Triage models now importable without Textual dependency (lazy import for TUI)

## ✨ New Features

### Enhanced Triage Loader
New `load_findings_from_path()` loader supporting multiple input formats:
- Native triage JSON (list or `{"findings": [...]}`)
- Raw scanner outputs (Semgrep, Trivy, Gitleaks)
- Run directories (aggregates all `*-results.json` files)

### Unified Report Generation
- Added command for generating consolidated scan reports
- Streamlined reporting workflow

### Security Enhancements
- Added file size limits (200MB max) to prevent DoS attacks (ASVS V10.3.3)
- Enhanced error message sanitization to prevent path disclosure (ASVS V7.4.1)

## 🔄 Changes

- **Upload:** Scanner file discovery now prefers `*-results.json` over generic `*.json`
- **Upload:** Scanner name normalization: `gitleaks-results` → `gitleaks`

## 📦 Installation

```bash
# Install via pipx (recommended)
pipx install kekkai-cli==1.1.1

# Or upgrade from previous version
pipx upgrade kekkai-cli

# Or via pip
pip install kekkai-cli==1.1.1
```

## 🔧 Upgrade Notes

This is a drop-in replacement for v1.1.0 with no breaking changes. Simply upgrade to benefit from the bug fixes and improvements.

## 📚 Documentation

- [Full Changelog](https://github.com/kademoslabs/kekkai/blob/v1.1.1/CHANGELOG.md)
- [Installation Guide](https://github.com/kademoslabs/kekkai#installation)
- [DefectDojo Quick Start](https://github.com/kademoslabs/kekkai/blob/v1.1.1/docs/dojo/dojo-quickstart.md)

## 🙏 Acknowledgments

Thank you to everyone who reported issues and helped improve Kekkai!

---

**Full Changelog**: https://github.com/kademoslabs/kekkai/compare/v1.1.0...v1.1.1
