# Multi-Tenant Architecture

This guide explains Kekkai Portal's multi-tenant architecture, data isolation, and scaling considerations.

---

## Overview

Kekkai Portal implements a multi-tenant architecture where:

- **Each tenant is completely isolated** from other tenants
- **Data segregation** is enforced at the application and database level
- **DefectDojo integration** provides per-tenant products and engagements
- **No shared resources** exist between tenants

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           KEKKAI PORTAL                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │  Tenant A   │  │  Tenant B   │  │  Tenant C   │  │  Tenant N   │   │
│  │             │  │             │  │             │  │             │   │
│  │ Users       │  │ Users       │  │ Users       │  │ Users       │   │
│  │ Uploads     │  │ Uploads     │  │ Uploads     │  │ Uploads     │   │
│  │ Findings    │  │ Findings    │  │ Findings    │  │ Findings    │   │
│  │ API Key     │  │ API Key     │  │ API Key     │  │ API Key     │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│         │                │                │                │          │
│         └────────────────┼────────────────┼────────────────┘          │
│                          │                │                           │
│                          v                v                           │
│                   ┌─────────────────────────────┐                     │
│                   │      TENANT STORE           │                     │
│                   │   (Isolated Metadata)       │                     │
│                   └─────────────────────────────┘                     │
│                                                                        │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 v
┌─────────────────────────────────────────────────────────────────────────┐
│                          DEFECTDOJO                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ Product A   │  │ Product B   │  │ Product C   │  │ Product N   │   │
│  │ Engagement  │  │ Engagement  │  │ Engagement  │  │ Engagement  │   │
│  │ Findings    │  │ Findings    │  │ Findings    │  │ Findings    │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Tenant Isolation Model

### Logical Isolation

Each tenant has:

| Component | Isolation Method |
|-----------|-----------------|
| **API Keys** | Unique per tenant, SHA-256 hashed |
| **Upload Storage** | Separate directory per tenant |
| **DefectDojo Product** | Dedicated product ID |
| **DefectDojo Engagement** | Dedicated engagement ID |
| **SAML Configuration** | Independent IdP settings |
| **Audit Logs** | Tenant-scoped log entries |

### Data Segregation

All data access includes tenant verification:

```python
# Every query includes tenant_id
findings = db.query(Finding).filter(
    Finding.tenant_id == current_user.tenant_id
)

# Cross-tenant access is blocked at application level
if resource.tenant_id != current_user.tenant_id:
    raise AuthorizationError("Cross-tenant access denied")
```

### Storage Isolation

Upload files are stored in tenant-specific directories:

```
/var/lib/kekkai-portal/uploads/
├── tenant-acme-corp/
│   ├── scan-001.json
│   └── scan-002.json
├── tenant-globex/
│   ├── scan-001.json
│   └── scan-002.json
└── tenant-initech/
    └── scan-001.json
```

File permissions prevent cross-tenant access at OS level.

---

## Tenant Management

### Tenant Data Model

```python
@dataclass
class Tenant:
    id: str                    # Unique identifier (e.g., "acme-corp")
    name: str                  # Display name
    api_key_hash: str          # SHA-256 hash of API key
    dojo_product_id: int       # DefectDojo product
    dojo_engagement_id: int    # DefectDojo engagement
    enabled: bool              # Active status
    max_upload_size_mb: int    # Upload limit
    auth_method: str           # "api_key" or "saml"
    default_role: str          # Default RBAC role
    saml_config: SAMLConfig    # SSO configuration (optional)
    created_at: datetime
    updated_at: datetime
```

### Creating a Tenant

```python
from portal.tenants import TenantStore

store = TenantStore(Path("/var/lib/kekkai-portal/tenants.json"))

# Create tenant with auto-generated API key
tenant, api_key = store.create(
    tenant_id="acme-corp",
    name="ACME Corporation",
    dojo_product_id=1,
    dojo_engagement_id=10,
)

print(f"Tenant created: {tenant.id}")
print(f"API Key (save securely): {api_key}")
```

### Tenant Configuration

```yaml
# Example tenant configuration
tenant:
  id: "acme-corp"
  name: "ACME Corporation"

  # DefectDojo integration
  dojo_product_id: 1
  dojo_engagement_id: 10

  # Limits
  max_upload_size_mb: 50
  max_users: 100

  # Authentication
  auth_method: "saml"  # or "api_key"
  default_role: "viewer"

  # SAML (if enabled)
  saml:
    entity_id: "https://idp.acme-corp.com/saml"
    sso_url: "https://idp.acme-corp.com/sso"
```

---

## DefectDojo Integration

### Per-Tenant Products

Each tenant maps to a DefectDojo Product:

```
Tenant: acme-corp → Product ID: 1
Tenant: globex    → Product ID: 2
Tenant: initech   → Product ID: 3
```

### Per-Tenant Engagements

Each tenant has a dedicated Engagement for scan imports:

```
Tenant: acme-corp → Engagement ID: 10
Tenant: globex    → Engagement ID: 20
Tenant: initech   → Engagement ID: 30
```

### Upload Flow

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  CLI Upload  │───>│    Portal    │───>│  DefectDojo  │
│ kekkai sync  │    │  Validates   │    │   Product &  │
│              │    │  Tenant ID   │    │  Engagement  │
└──────────────┘    └──────────────┘    └──────────────┘
                           │
                           v
                    ┌──────────────┐
                    │ Tenant Store │
                    │  Lookup ID   │
                    └──────────────┘
```

### Automatic Product/Engagement Creation

When creating a tenant, Portal can auto-create DefectDojo resources:

```bash
kekkai-portal tenant create \
  --id acme-corp \
  --name "ACME Corporation" \
  --auto-create-dojo
```

This creates:
1. DefectDojo Product named "ACME Corporation"
2. DefectDojo Engagement for Kekkai imports
3. Links tenant to created resources

---

## Security Controls

### Tenant ID Validation

All requests validate tenant ownership:

```python
def validate_tenant_access(request, resource):
    # Extract tenant from authentication
    auth_tenant = get_tenant_from_auth(request)

    # Compare with resource tenant
    if resource.tenant_id != auth_tenant.id:
        logger.warning(
            "cross_tenant_access_attempt",
            auth_tenant=auth_tenant.id,
            resource_tenant=resource.tenant_id,
        )
        raise HTTPForbidden("Access denied")
```

### API Key Isolation

API keys are tenant-scoped:

```
kek_acme_xxxxx → Tenant: acme-corp
kek_glob_xxxxx → Tenant: globex
```

Keys cannot access other tenants' data, even if known.

### Audit Trail

All cross-tenant access attempts are logged:

```json
{
  "event": "security.cross_tenant_access_blocked",
  "source_tenant": "acme-corp",
  "target_tenant": "globex",
  "user_id": "[REDACTED]",
  "resource_type": "finding",
  "timestamp": "2026-01-30T10:15:30Z"
}
```

---

## Scaling Considerations

### Horizontal Scaling

Portal supports horizontal scaling:

```
                    ┌─────────────┐
                    │   Nginx     │
                    │   (LB)      │
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         v                 v                 v
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Portal 1   │  │  Portal 2   │  │  Portal 3   │
│  Instance   │  │  Instance   │  │  Instance   │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
                        v
               ┌─────────────────┐
               │   Shared State  │
               │   (PostgreSQL)  │
               └─────────────────┘
```

### Shared State

For multi-instance deployments, use shared state:

```yaml
# Production configuration
storage:
  type: "postgresql"  # Instead of file-based
  connection: "postgresql://user:pass@db:5432/kekkai"

uploads:
  type: "s3"  # Instead of local filesystem
  bucket: "kekkai-uploads"
  region: "us-east-1"
```

### Tenant Resource Limits

Prevent resource exhaustion per tenant:

```yaml
tenant_limits:
  max_upload_size_mb: 50
  max_uploads_per_day: 100
  max_storage_gb: 10
  rate_limit_requests: 1000  # per hour
```

### DefectDojo Scaling

For large deployments, consider:

1. **Dedicated DefectDojo per tenant**: Maximum isolation
2. **Shared DefectDojo with strict ACLs**: Cost-effective
3. **DefectDojo cluster**: High availability

---

## Migration Guide

### From Single-Tenant to Multi-Tenant

1. **Export existing data**:
   ```bash
   kekkai-portal export --output backup.json
   ```

2. **Create tenant structure**:
   ```bash
   kekkai-portal tenant create --id legacy --name "Legacy Data"
   ```

3. **Import with tenant assignment**:
   ```bash
   kekkai-portal import --input backup.json --tenant legacy
   ```

### From CLI-Only to Portal

See [CLI-to-Portal Sync Guide](cli-sync.md) for migration steps.

---

## Troubleshooting

### "Cross-tenant access denied"

**Cause**: User attempting to access another tenant's resource

**Solution**: Verify user is authenticated with correct tenant API key or SSO

### Tenant Not Found

**Cause**: API key doesn't match any tenant

**Solution**:
1. Verify API key is correct
2. Check tenant is enabled
3. Regenerate API key if needed

### Upload Fails with Tenant Error

**Cause**: DefectDojo product/engagement mismatch

**Solution**:
1. Verify `dojo_product_id` exists in DefectDojo
2. Verify `dojo_engagement_id` belongs to the product
3. Check DefectDojo API connectivity

---

## Related Documentation

- [SAML 2.0 Setup](saml-setup.md) - Configure SSO per tenant
- [RBAC Configuration](rbac.md) - Role-based access within tenants
- [Deployment Guide](deployment.md) - Production deployment
- [CLI-Portal Sync](cli-sync.md) - Connect CLI to Portal
