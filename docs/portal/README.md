# Kekkai Enterprise Features

> **Note**: Enterprise features are available in a separately for licensed customers.

## Overview

Kekkai's enterprise offering extends the open-source CLI with advanced features designed for organizations that need:
- Multi-tenant management
- Enterprise-grade authentication
- Advanced operational tooling
- Compliance and audit capabilities

## Enterprise Features

### 🏢 Multi-Tenant Portal
- Web-based dashboard for managing multiple teams/projects
- Centralized scan result aggregation
- Team-based access control
- Custom branding support

### 🔐 Advanced Authentication
- **SAML 2.0 SSO**: Integrate with Okta, Azure AD, Google Workspace
- **RBAC**: Fine-grained role-based access control
- **Audit Logging**: Cryptographically signed compliance trails
- **Session Management**: Secure session handling with configurable policies

### 📊 Operations & Monitoring
- **Automated Backup/Restore**: Scheduled backups with encryption
- **Monitoring & Alerting**: Real-time metrics and alert routing
- **Zero-Downtime Upgrades**: Rolling updates with health checks
- **Log Shipping**: Centralized log aggregation and analysis
- **Secrets Management**: Vault integration for credential management

### 📋 Compliance & Reporting
- **Compliance Matrix**: Map findings to OWASP, PCI-DSS, HIPAA, SOC 2
- **Executive Reports**: PDF/HTML reports for stakeholders
- **Trend Analysis**: Historical vulnerability tracking
- **SLA Monitoring**: Track remediation SLAs

## Access

Enterprise features are available to licensed customers only.

**For Sales Inquiries:**
- Email: [sales@kademos.org](mailto:sales@kademos.org)
- Website: [https://kademos.org](https://kademos.org)

**For Enterprise Customers:**
- If you have enterprise access, Contact your account manager for onboarding assistance

## Architecture

The enterprise features are designed to complement the open-source CLI:

```
┌─────────────────────────────────────┐
│   Kekkai CLI (Open Source)          │
│   - Scanning (Trivy/Semgrep/etc)    │
│   - Triage UI                        │
│   - CI/CD Integration                │
│   - ThreatFlow                       │
└─────────────────┬───────────────────┘
                  │
                  │ Optional Integration
                  ↓
┌─────────────────────────────────────┐
│   Kekkai Enterprise (Licensed)      │
│   - Multi-Tenant Portal              │
│   - SAML SSO & RBAC                  │
│   - Advanced Operations              │
│   - Compliance Reporting             │
└─────────────────────────────────────┘
```

## Integration

Enterprise customers can:
1. Use the open-source CLI standalone
2. Sync CLI scan results to the enterprise portal: `kekkai upload`
3. Manage teams, access control, and compliance from the web UI

The integration is optional and non-invasive - the CLI remains fully functional without enterprise features.

## Licensing

Kekkai CLI is open-source under Apache-2.0 license.

Enterprise features require a separate commercial license with:
- Per-seat or enterprise-wide licensing options
- Self-hosted or SaaS deployment
- Professional support and SLAs
- Custom integrations and feature development

Contact sales for pricing and licensing options.

---

**Note**: This documentation describes features not available in the open-source repository. All enterprise code is maintained in a separate private repository to protect intellectual property and prevent unauthorized access to premium features.
