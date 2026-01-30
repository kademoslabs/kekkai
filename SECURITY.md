# Security Policy

## Supported Versions

We actively maintain security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email us at: **security@kademos.org**

Include the following information:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

| Timeline | Action |
|----------|--------|
| **24 hours** | Initial acknowledgment of your report |
| **72 hours** | Preliminary assessment and severity classification |
| **7 days** | Detailed response with remediation plan |
| **90 days** | Public disclosure (coordinated with reporter) |

### Severity Classification

We use CVSS v3.1 for severity assessment:

| Severity | CVSS Score | Response Time |
|----------|------------|---------------|
| Critical | 9.0 - 10.0 | Immediate patch |
| High | 7.0 - 8.9 | Patch within 7 days |
| Medium | 4.0 - 6.9 | Patch within 30 days |
| Low | 0.1 - 3.9 | Next scheduled release |

## Security Measures

Kekkai implements the following security controls:

### Container Isolation
- All scanners run in isolated Docker containers
- Read-only root filesystem (`--read-only`)
- No new privileges (`--security-opt=no-new-privileges`)
- Network isolation (`--network=none`)
- Memory limits (2GB default)

### Input Validation
- Repository paths validated before mounting
- Shell metacharacters rejected
- Output paths explicitly controlled

### Secrets Protection
- API keys only accepted via environment variables
- No secrets logged or persisted
- ThreatFlow local mode keeps code on-device

### Supply Chain Security
- SLSA Level 3 provenance for releases
- Cosign signatures on Docker images
- Automated dependency scanning via Dependabot

## Security Best Practices

When using Kekkai:

1. **Keep Updated**: Always use the latest version
2. **Use pipx**: Isolate Kekkai from other Python packages
3. **Review Findings**: Don't auto-apply fixes without review
4. **Secure API Keys**: Use environment variables, not CLI arguments
5. **Local LLM**: Use `--model-mode local` for sensitive codebases

## Acknowledgments

We thank the following researchers for responsible disclosure:

*No vulnerabilities reported yet.*

---

## Contact

- **Security Issues**: security@kademos.org
- **General Support**: https://github.com/kademoslabs/kekkai/issues
- **Website**: https://kademos.org/kekkai
