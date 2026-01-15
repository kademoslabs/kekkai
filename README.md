# Kekkai
**One command. Clean AppSec reports.**

Kekkai orchestrates common open-source scanners locally, deduplicates noise, and produces a single actionable report for your repo.

- Website: https://kademos.org/kekkai
- Docs: https://kademos.org/kekkai#docs

---

## Quickstart

### Install
> Add your actual install method(s) here (brew, curl, pipx, go install, etc.)

```bash
kekkai --version
```

### Scan a project

```bash
cd your-repo
kekkai scan
```

### Output

- `kekkai-report.json`
    
- `kekkai-report.sarif` (optional)
    
- `kekkai-report.md` (optional)
    

---

## What Kekkai runs (local-first)

Kekkai is **bring-your-own-compute** by default: scanners run on your machine or CI runner.

Supported scanners (configurable):

- Trivy (containers & deps)
    
- Semgrep (SAST)
    
- Gitleaks (secrets)
    
- ZAP (DAST)    

> Replace with your exact scanner set and add links.

---

## Enterprise Edition (ThreatFlow)

Kekkai Enterprise adds:

- **ThreatFlow**: generates `THREATS.md` from your architecture and code context
    
- Hosted portal upload + team dashboards
    
- RBAC/SSO and audit trails
    
- Policy packs for regulated teams    

Contact: [enterprise@kademos.org](mailto:enterprise@kademos.org)

---

## Configuration

- `kekkai.yml` supports enabling/disabling scanners, thresholds, and output formats.   

```yaml
scanners:
  semgrep: true
  gitleaks: true
  trivy: true
outputs:
  sarif: true
  markdown: true
```
---

## Security

Please report vulnerabilities privately: **[security@kademos.org](mailto:security@kademos.org)**  
See `SECURITY.md`.

---

## Contributing

- Good first issues are tagged.
    
- Run `make test` before opening a PR.  
    See `CONTRIBUTING.md`.
    
---

## License

Apache-2.0.
