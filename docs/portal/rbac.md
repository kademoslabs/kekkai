# Role-Based Access Control (RBAC)

This guide covers configuring role-based access control in Kekkai Portal for enterprise deployments.

---

## Overview

Kekkai Portal implements RBAC with the following principles:

- **Least Privilege**: Users receive minimal permissions for their function
- **Deterministic Mapping**: SAML attributes map to roles without escalation paths
- **Tenant Isolation**: Cross-tenant access is strictly prohibited
- **Deny by Default**: Undefined permissions are denied

---

## Role Hierarchy

Kekkai Portal defines four roles with increasing privileges:

```
┌─────────────────────────────────────────────────────────────┐
│                      TENANT ADMIN                           │
│  Full tenant control, SSO config, API key management        │
├─────────────────────────────────────────────────────────────┤
│                         ADMIN                               │
│  User management, integrations, audit logs                  │
├─────────────────────────────────────────────────────────────┤
│                        ANALYST                              │
│  Upload scans, triage findings, export reports              │
├─────────────────────────────────────────────────────────────┤
│                        VIEWER                               │
│  Read-only: view findings, dashboard, reports               │
└─────────────────────────────────────────────────────────────┘
```

---

## Permission Matrix

### Viewer Permissions

| Permission | Description |
|------------|-------------|
| `view_findings` | View security findings |
| `view_dashboard` | Access dashboard metrics |
| `view_reports` | View generated reports |

**Use Case**: Developers who need visibility into security findings affecting their code.

### Analyst Permissions

Includes all Viewer permissions, plus:

| Permission | Description |
|------------|-------------|
| `create_upload` | Upload scan results |
| `update_finding_status` | Mark findings as resolved, false positive, etc. |
| `export_findings` | Export findings to CSV/JSON |

**Use Case**: Security engineers who triage and manage findings daily.

### Admin Permissions

Includes all Analyst permissions, plus:

| Permission | Description |
|------------|-------------|
| `manage_users` | Add/remove users, assign roles |
| `manage_integrations` | Configure Jira, Slack, etc. |
| `view_audit_logs` | Access audit trail |

**Use Case**: Security team leads who manage the Portal instance.

### Tenant Admin Permissions

Includes all Admin permissions, plus:

| Permission | Description |
|------------|-------------|
| `manage_tenant` | Update tenant settings |
| `manage_saml_config` | Configure SSO settings |
| `rotate_api_key` | Rotate tenant API keys |
| `delete_tenant` | Delete tenant (destructive) |

**Use Case**: Organization administrators with full control over the tenant.

---

## SAML Attribute Mapping

Roles are assigned based on SAML attributes from your Identity Provider.

### Supported Attributes

Portal checks these SAML attribute names (in order):

1. `role`
2. `roles`
3. `group`
4. `groups`

### Attribute Values

| SAML Value | Mapped Role |
|------------|-------------|
| `viewer` | Viewer |
| `analyst` | Analyst |
| `admin` | Admin |
| `tenant_admin` | Tenant Admin |
| `tenant-admin` | Tenant Admin |
| `tenantadmin` | Tenant Admin |

### Default Role

If no role attribute matches, users are assigned **Viewer** role (least privilege).

### IdP Configuration Examples

#### Okta

Add a custom attribute `kekkaiRole` to your SAML app:

```
Attribute Statements:
  Name: role
  Value: appuser.kekkaiRole
```

Then set `kekkaiRole` per user or group assignment.

#### Azure AD

Create App Roles in your application registration:

```json
{
  "allowedMemberTypes": ["User"],
  "displayName": "Analyst",
  "value": "analyst",
  "description": "Security analyst role"
}
```

Configure the `roles` claim in token configuration.

#### Google Workspace

Use a custom attribute or Department field:

```
Attribute Mapping:
  App attribute: role
  Google attribute: Department
```

Set department to: `viewer`, `analyst`, `admin`, or `tenant_admin`.

---

## Configuration

### Environment Variables

```bash
# Default role for users without role attribute
PORTAL_DEFAULT_ROLE=viewer

# Strict mode: reject users without explicit role
PORTAL_RBAC_STRICT_MODE=false
```

### Custom Role Mapping

Override default attribute-to-role mapping:

```yaml
# /etc/kekkai-portal/rbac.yml
rbac:
  role_mapping:
    # Custom attribute values
    "security-engineer": "analyst"
    "security-lead": "admin"
    "it-admin": "tenant_admin"
    "developer": "viewer"

  # Default role when no mapping matches
  default_role: "viewer"

  # Reject users without explicit role mapping
  strict_mode: false
```

---

## Authorization Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ User Action │───>│ Extract Role │───>│ Check Perm  │
└─────────────┘    │ from Context │    │   Matrix    │
                   └──────────────┘    └──────┬──────┘
                                              │
                          ┌───────────────────┴───────────────────┐
                          │                                       │
                          v                                       v
                   ┌─────────────┐                         ┌─────────────┐
                   │   ALLOWED   │                         │   DENIED    │
                   │ Log success │                         │ Log warning │
                   └─────────────┘                         │ Return 403  │
                                                           └─────────────┘
```

### Cross-Tenant Protection

All authorization checks enforce tenant boundaries:

1. User's `tenant_id` extracted from session
2. Resource's `tenant_id` compared
3. Mismatch → **Access Denied** (even for admins)

```
User (tenant: acme-corp) accessing resource (tenant: other-org)
→ DENIED: "Cross-tenant access denied"
```

---

## Best Practices

### Least Privilege Setup

1. **Start with Viewer**: Assign Viewer role by default
2. **Elevate as needed**: Promote to Analyst only for active triagers
3. **Limit Admins**: Only security leads need Admin role
4. **Single Tenant Admin**: One Tenant Admin per organization

### Recommended Role Distribution

| Team Size | Viewers | Analysts | Admins | Tenant Admins |
|-----------|---------|----------|--------|---------------|
| 5-10 | 3-7 | 1-2 | 1 | 1 |
| 11-50 | 8-40 | 2-8 | 1-2 | 1 |
| 51-200 | 40-180 | 5-15 | 2-4 | 1-2 |

### Role Assignment via Groups

Use IdP groups for scalable role assignment:

```
IdP Group: kekkai-viewers → role: viewer
IdP Group: kekkai-analysts → role: analyst
IdP Group: kekkai-admins → role: admin
```

This allows:
- Self-service via group membership requests
- Audit trail in IdP
- Easy onboarding/offboarding

---

## Audit Logging

All authorization decisions are logged:

### Successful Authorization

```json
{
  "event": "authz.allowed",
  "user_id": "[REDACTED]",
  "tenant_id": "acme-corp",
  "role": "analyst",
  "permission": "create_upload",
  "timestamp": "2026-01-30T10:15:30Z"
}
```

### Denied Authorization

```json
{
  "event": "authz.denied.permission",
  "user_id": "[REDACTED]",
  "tenant_id": "acme-corp",
  "role": "viewer",
  "permission": "create_upload",
  "reason": "Role viewer lacks create_upload",
  "timestamp": "2026-01-30T10:15:30Z"
}
```

### Cross-Tenant Denial

```json
{
  "event": "authz.denied.cross_tenant",
  "user_id": "[REDACTED]",
  "tenant_id": "acme-corp",
  "target_tenant_id": "other-org",
  "permission": "view_findings",
  "timestamp": "2026-01-30T10:15:30Z"
}
```

---

## API Authorization

### Bearer Token Authentication

For API access, include the tenant API key:

```bash
curl -H "Authorization: Bearer kek_your_api_key" \
     https://portal.example.com/api/v1/findings
```

API keys inherit the permissions of the tenant's default role.

### Permission Requirements by Endpoint

| Endpoint | Method | Required Permission |
|----------|--------|-------------------|
| `/api/v1/findings` | GET | `view_findings` |
| `/api/v1/upload` | POST | `create_upload` |
| `/api/v1/findings/:id/status` | PATCH | `update_finding_status` |
| `/api/v1/reports/export` | GET | `export_findings` |
| `/api/v1/users` | GET/POST | `manage_users` |
| `/api/v1/audit-logs` | GET | `view_audit_logs` |
| `/api/v1/tenant/settings` | GET/PATCH | `manage_tenant` |
| `/api/v1/tenant/saml` | GET/PATCH | `manage_saml_config` |
| `/api/v1/tenant/api-key/rotate` | POST | `rotate_api_key` |

---

## Troubleshooting

### User Has Wrong Role

**Symptom**: User can't access expected features

**Solution**:
1. Check SAML response for `role` attribute value
2. Verify value matches expected mapping
3. Check Portal logs for role assignment

```bash
grep "saml.assertion_processed" /var/log/kekkai-portal/portal.log
```

### Permission Denied Unexpectedly

**Symptom**: User receives 403 error

**Solution**:
1. Check audit logs for denial reason
2. Verify user's role has required permission
3. Check for cross-tenant access attempt

### Role Not Updating After IdP Change

**Symptom**: User's IdP role changed but Portal shows old role

**Solution**:
1. User must re-authenticate (logout/login)
2. Clear session if needed
3. Verify IdP sends updated role attribute

---

## Security Considerations

### No Default Admin Accounts

Portal does not create default admin accounts. Initial Tenant Admin must be:
1. Assigned via SAML attribute from IdP
2. Or created via CLI during initial setup

### Deterministic Role Mapping

Role mapping is deterministic and server-controlled:
- Users cannot self-assign roles
- Role escalation requires IdP change
- No client-side role information trusted

### Session Binding

User context (including role) is bound to session:
- Role checked on every request
- Session invalidation removes all access
- No persistent role cache on client

---

## Related Documentation

- [SAML 2.0 Setup](saml-setup.md) - Configure SSO
- [Multi-Tenant Architecture](multi-tenant.md) - Tenant isolation
- [Deployment Guide](deployment.md) - Production deployment
- [Portal Overview](README.md) - General Portal documentation
