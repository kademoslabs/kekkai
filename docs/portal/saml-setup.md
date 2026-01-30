# SAML 2.0 SSO Setup Guide

This guide covers configuring SAML 2.0 Single Sign-On (SSO) for Kekkai Portal with popular Identity Providers.

---

## Overview

Kekkai Portal supports SAML 2.0 for enterprise authentication, enabling:

- **Single Sign-On**: Users authenticate via your corporate IdP
- **Automatic Role Mapping**: SAML attributes map to Portal roles
- **Session Management**: Configurable session lifetime with secure defaults
- **Replay Protection**: One-time assertion validation (ASVS V6.8.3)

---

## Prerequisites

- Kekkai Portal deployed and accessible
- Enterprise license with SSO feature enabled
- Admin access to your Identity Provider
- TLS/HTTPS configured on Portal (required for SAML)

---

## Service Provider (SP) Metadata

Configure your IdP with the following Kekkai Portal SP details:

| Setting | Value |
|---------|-------|
| **Entity ID** | `https://your-portal.example.com/saml/metadata` |
| **ACS URL** | `https://your-portal.example.com/saml/acs` |
| **SLO URL** | `https://your-portal.example.com/saml/slo` (optional) |
| **NameID Format** | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| **Binding** | `HTTP-POST` |

---

## Identity Provider Configuration

### Okta

#### Step 1: Create SAML Application

1. Log into Okta Admin Console
2. Navigate to **Applications** → **Create App Integration**
3. Select **SAML 2.0** and click **Next**
4. Configure:
   - **App name**: `Kekkai Portal`
   - **App logo**: Upload Kekkai logo (optional)

#### Step 2: Configure SAML Settings

```
Single sign-on URL: https://your-portal.example.com/saml/acs
Audience URI (SP Entity ID): https://your-portal.example.com/saml/metadata
Name ID format: EmailAddress
Application username: Email
```

#### Step 3: Configure Attribute Statements

| Name | Value |
|------|-------|
| `email` | `user.email` |
| `displayName` | `user.displayName` |
| `role` | `appuser.kekkaiRole` |

#### Step 4: Assign Users

1. Go to **Assignments** tab
2. Assign users or groups
3. Set `kekkaiRole` attribute per user/group:
   - `viewer` - Read-only access
   - `analyst` - Upload and triage findings
   - `admin` - Manage users and integrations
   - `tenant_admin` - Full tenant control

#### Step 5: Export IdP Metadata

1. Go to **Sign On** tab
2. Click **View SAML setup instructions**
3. Copy:
   - Identity Provider Single Sign-On URL
   - Identity Provider Issuer
   - X.509 Certificate

---

### Azure AD (Entra ID)

#### Step 1: Create Enterprise Application

1. Open Azure Portal → **Microsoft Entra ID**
2. Navigate to **Enterprise applications** → **New application**
3. Click **Create your own application**
4. Name: `Kekkai Portal`, select **Non-gallery application**

#### Step 2: Configure Single Sign-On

1. Go to **Single sign-on** → **SAML**
2. Edit **Basic SAML Configuration**:

```
Identifier (Entity ID): https://your-portal.example.com/saml/metadata
Reply URL (ACS URL): https://your-portal.example.com/saml/acs
Sign on URL: https://your-portal.example.com/
Logout URL: https://your-portal.example.com/saml/slo
```

#### Step 3: Configure Attributes & Claims

Edit **Attributes & Claims**:

| Claim name | Source attribute |
|------------|------------------|
| `emailaddress` | `user.mail` |
| `displayname` | `user.displayname` |
| `role` | `user.assignedroles` |

#### Step 4: Configure App Roles

1. Go to **App registrations** → find your app
2. Navigate to **App roles** → **Create app role**
3. Create roles:

| Display Name | Value | Description |
|--------------|-------|-------------|
| Viewer | `viewer` | Read-only access |
| Analyst | `analyst` | Upload and triage |
| Admin | `admin` | User management |
| Tenant Admin | `tenant_admin` | Full control |

#### Step 5: Assign Users

1. Return to **Enterprise applications** → your app
2. Go to **Users and groups** → **Add user/group**
3. Assign users with appropriate roles

#### Step 6: Download Federation Metadata

1. In **SAML Certificates** section
2. Download **Federation Metadata XML**

---

### Google Workspace

#### Step 1: Create SAML App

1. Open Google Admin Console
2. Navigate to **Apps** → **Web and mobile apps**
3. Click **Add app** → **Add custom SAML app**

#### Step 2: Configure Google IdP Details

Copy the following for Portal configuration:
- **SSO URL**
- **Entity ID**
- **Certificate** (download)

#### Step 3: Configure Service Provider Details

```
ACS URL: https://your-portal.example.com/saml/acs
Entity ID: https://your-portal.example.com/saml/metadata
Start URL: https://your-portal.example.com/
Name ID format: EMAIL
Name ID: Basic Information > Primary email
```

#### Step 4: Configure Attribute Mapping

| App attribute | Google Directory attribute |
|---------------|---------------------------|
| `email` | Primary email |
| `displayName` | Full name |
| `role` | Department (or custom attribute) |

#### Step 5: Enable for Users

1. Click **User access**
2. Enable for your organizational units
3. Click **Save**

---

## Portal Configuration

After configuring your IdP, update Kekkai Portal settings:

### Environment Variables

```bash
# IdP Configuration
PORTAL_SAML_ENTITY_ID="https://idp.example.com/saml"
PORTAL_SAML_SSO_URL="https://idp.example.com/saml/sso"
PORTAL_SAML_SLO_URL="https://idp.example.com/saml/slo"  # Optional
PORTAL_SAML_CERTIFICATE="/path/to/idp-certificate.pem"

# SP Configuration
PORTAL_SP_ENTITY_ID="https://your-portal.example.com/saml/metadata"
PORTAL_SP_ACS_URL="https://your-portal.example.com/saml/acs"

# Session Settings
PORTAL_SESSION_LIFETIME=28800  # 8 hours (default)
PORTAL_SAML_CLOCK_SKEW=300     # 5 minutes (default)
```

### Configuration File

Alternatively, use a configuration file:

```yaml
# /etc/kekkai-portal/saml.yml
saml:
  idp:
    entity_id: "https://idp.example.com/saml"
    sso_url: "https://idp.example.com/saml/sso"
    slo_url: "https://idp.example.com/saml/slo"
    certificate_path: "/etc/kekkai-portal/certs/idp.pem"
    # Or use fingerprint for certificate pinning
    certificate_fingerprint: "AB:CD:EF:..."

  sp:
    entity_id: "https://your-portal.example.com/saml/metadata"
    acs_url: "https://your-portal.example.com/saml/acs"

  security:
    want_assertions_signed: true
    session_lifetime: 28800
    allow_clock_skew: 300
```

---

## Session Management

### Session Lifetime

Configure session duration based on security requirements:

| Use Case | Recommended Lifetime |
|----------|---------------------|
| High Security | 1 hour (3600) |
| Standard | 8 hours (28800) |
| Convenience | 24 hours (86400) |

```bash
PORTAL_SESSION_LIFETIME=28800
```

### Session Token

After SAML authentication, Portal issues a signed session token:

- HMAC-SHA256 signed
- Contains: user ID, tenant ID, session ID, expiration
- Transmitted via secure, HTTPOnly cookie

---

## Security Considerations

### Replay Protection (ASVS V6.8.3)

Kekkai Portal implements assertion replay protection:

- Each SAML assertion ID is tracked
- Reused assertion IDs are rejected
- Assertion IDs expire after 1 hour

### Signature Validation (ASVS V6.8.2)

Always enable assertion signature validation:

```yaml
security:
  want_assertions_signed: true
```

### Clock Skew

Allow reasonable clock drift between IdP and Portal:

```bash
PORTAL_SAML_CLOCK_SKEW=300  # 5 minutes
```

### Certificate Management

1. **Store certificates securely**: Use file permissions `600` or secrets manager
2. **Monitor expiration**: IdP certificates typically expire annually
3. **Certificate rotation**: Update before expiration to avoid SSO outages

---

## Troubleshooting

### "Invalid signature" Error

**Cause**: IdP certificate mismatch or rotation

**Solution**:
1. Download fresh certificate from IdP
2. Update `PORTAL_SAML_CERTIFICATE` path
3. Restart Portal

### "Assertion has expired" Error

**Cause**: Clock drift between IdP and Portal

**Solution**:
1. Sync server clocks using NTP
2. Increase `PORTAL_SAML_CLOCK_SKEW` if necessary

### "Assertion not yet valid" Error

**Cause**: Portal clock ahead of IdP

**Solution**:
1. Verify NTP synchronization
2. Check `NotBefore` constraint in SAML response

### "Assertion already used" (Replay Error)

**Cause**: User clicked back button or assertion was replayed

**Solution**: This is expected security behavior. User should re-authenticate.

### Role Not Mapped Correctly

**Cause**: SAML attribute name mismatch

**Solution**:
1. Verify IdP sends `role` or `roles` attribute
2. Check attribute values match: `viewer`, `analyst`, `admin`, `tenant_admin`
3. Review Portal logs for attribute values received

### Debug Logging

Enable debug logging to troubleshoot SAML issues:

```bash
PORTAL_LOG_LEVEL=DEBUG
```

Check logs for:
- `saml.assertion_processed` - Successful authentication
- `saml.replay_detected` - Replay attack blocked
- `saml.certificate_fingerprint_mismatch` - Certificate issue

---

## Testing SSO

### Verify Configuration

1. Access Portal login page
2. Click "Sign in with SSO"
3. Authenticate with your IdP
4. Verify correct role assignment in Portal

### Test Role Mapping

Create test users in IdP with different roles:

| Test User | IdP Role | Expected Portal Role |
|-----------|----------|---------------------|
| viewer@test.com | viewer | Viewer |
| analyst@test.com | analyst | Analyst |
| admin@test.com | admin | Admin |

### Verify Session Expiration

1. Authenticate via SSO
2. Wait for session timeout
3. Verify re-authentication is required

---

## Related Documentation

- [RBAC Configuration](rbac.md) - Role and permission setup
- [Multi-Tenant Architecture](multi-tenant.md) - Tenant isolation
- [Deployment Guide](deployment.md) - Production deployment
- [Portal Overview](README.md) - General Portal documentation
