# Kekkai Documentation

User-facing documentation for Kekkai CLI and related features.

---

## Quick Links

### Kekkai Dojo (DefectDojo Orchestration)

Run a local DefectDojo vulnerability management platform with one command.

- **[Quick Start Guide](dojo/dojo-quickstart.md)** — Get started in 5 minutes
- **[Complete Guide](dojo/dojo.md)** — Full command reference and configuration
- **[Security Guide](dojo/dojo-security.md)** — Threat model and best practices
- **[Troubleshooting](dojo/dojo-troubleshooting.md)** — Common issues and solutions

### CI Mode (Policy Enforcement)

Use Kekkai in CI/CD pipelines to fail builds on security findings.

- **[CI Mode Guide](ci-mode.md)** — Policy enforcement with exit codes

### Portal (Hosted Dashboard)

Multi-tenant hosted security dashboard with authenticated uploads.

- **[Portal Guide](portal/README.md)** — Setup, API reference, and configuration

### Getting Started

New to Kekkai? Start here:

1. Read the [main README](../README.md) for project overview
2. Follow the [Dojo Quick Start](dojo/dojo-quickstart.md) to run DefectDojo locally
3. Check the [Dojo Guide](dojo/dojo.md) for advanced usage
4. Set up CI with the [CI Mode Guide](ci-mode.md)

---

## Documentation Structure

```
docs/
├── README.md                    # This file
├── ci-mode.md                   # CI policy enforcement guide
├── dojo/                        # DefectDojo Docs
├   ├── dojo-quickstart.md           # 5-minute quick start
├   ├── dojo.md                      # Complete Dojo guide
├   ├── dojo-security.md             # Security considerations
├   └── dojo-troubleshooting.md      # Common issues and solutions
```

---

## Contributing to Docs

To improve these docs:

1. Fork the repository
2. Edit markdown files in `docs/`
3. Test locally by reading in a markdown viewer
4. Submit a pull request

Keep documentation:
- **Concise** — Get to the point quickly
- **Actionable** — Provide clear commands and examples
- **Up-to-date** — Reflect current implementation
- **Accessible** — Assume minimal background knowledge

---

## Support

- **Issues:** [GitHub Issues](https://github.com/kademoslabs/kekkai-cli/issues)
- **Security:** [security@kademos.org](mailto:security@kademos.org)
- **Website:** [kademos.org/kekkai](https://kademos.org/kekkai)

---

## License

Documentation is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Code is licensed under Apache-2.0 (see [LICENSE](../LICENSE)).
