# Kekkai Portal

The Kekkai Portal is a hosted, multi-tenant security dashboard backed by DefectDojo. It provides authenticated file uploads, tenant isolation, and a modern Kekkai-themed UI.

## Features

- **Multi-tenant Architecture**: Complete isolation between tenants
- **Authenticated Uploads**: Bearer token authentication for API access
- **File Validation**: Type and size restrictions on uploads (JSON/SARIF only)
- **Secure by Default**: Security headers, rate limiting, no sensitive data logging
- **Kekkai Branding**: Modern UI with Kekkai theme colors

## Quick Start

### Development Server

Run the portal locally:

```bash
# Set up environment
export PORTAL_TENANT_STORE=/tmp/tenants.json
export PORTAL_UPLOAD_DIR=/tmp/portal-uploads

# Start the server
python -m portal.web
# or
kekkai-portal
```

### Docker Deployment

Use Docker Compose for production:

```bash
cd apps/portal
docker-compose up -d
```

## API Reference

### Health Check

```
GET /api/v1/health
```

Returns:
```json
{"status": "healthy"}
```

### Upload Scan Results

```
POST /api/v1/upload
Authorization: Bearer <api-key>
Content-Type: multipart/form-data

file: <scan-results.json>
```

Returns:
```json
{
  "success": true,
  "upload_id": "abc123...",
  "file_hash": "sha256...",
  "tenant_id": "your-tenant",
  "dojo_product_id": 1,
  "dojo_engagement_id": 10
}
```

### Get Tenant Information

**New in Milestone 2**

```
GET /api/v1/tenant/info
Authorization: Bearer <api-key>
```

Returns the authenticated tenant's metadata:

```json
{
  "id": "your-tenant",
  "name": "Your Organization",
  "dojo_product_id": 1,
  "dojo_engagement_id": 10,
  "enabled": true,
  "max_upload_size_mb": 10,
  "auth_method": "api_key",
  "default_role": "viewer"
}
```

### List Uploads

**New in Milestone 2**

```
GET /api/v1/uploads?limit=50
Authorization: Bearer <api-key>
```

Returns a list of recent uploads for the authenticated tenant:

```json
{
  "uploads": [
    {
      "upload_id": "abc123",
      "filename": "scan.json",
      "timestamp": "1706097600",
      "size_bytes": 1024
    }
  ]
}
```

Query Parameters:
- `limit` (optional): Maximum number of uploads to return (default: 50, max: 100)

### Get Statistics

**New in Milestone 2**

```
GET /api/v1/stats
Authorization: Bearer <api-key>
```

Returns statistics for the authenticated tenant:

```json
{
  "total_uploads": 42,
  "total_size_bytes": 1048576,
  "last_upload_time": "1706097600"
}
```

### Dashboard

```
GET /
Authorization: Bearer <api-key> (optional)
```

Returns the Kekkai-themed dashboard HTML. If authenticated, shows upload form and tenant info. If unauthenticated, shows authentication prompt.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORTAL_HOST` | `127.0.0.1` | Server bind address |
| `PORTAL_PORT` | `8000` | Server port |
| `PORTAL_TENANT_STORE` | `/var/lib/kekkai-portal/tenants.json` | Tenant data file |
| `PORTAL_UPLOAD_DIR` | System temp dir | Upload storage directory |

## Security

### Authentication

- Bearer token authentication required for uploads
- API keys are stored as SHA-256 hashes
- Constant-time comparison prevents timing attacks

### Tenant Isolation (ASVS V8.4.1)

- Each tenant has unique product/engagement IDs in DefectDojo
- Upload paths are isolated per tenant
- Cross-tenant access attempts are blocked and logged

### File Uploads (ASVS V5.2.2, V5.2.4)

- Only `.json` and `.sarif` files allowed
- File size limits enforced per tenant
- Content validated as valid JSON
- Files stored outside web root with restricted permissions

### Security Headers

All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy: default-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`

## Tenant Management

### Create a Tenant

```python
from portal.tenants import TenantStore

store = TenantStore(Path("/path/to/tenants.json"))
tenant, api_key = store.create(
    tenant_id="acme-corp",
    name="ACME Corporation",
    dojo_product_id=1,
    dojo_engagement_id=10,
)
print(f"API Key (save this!): {api_key}")
```

### Rotate API Key

```python
new_key = store.rotate_api_key("acme-corp")
print(f"New API Key: {new_key}")
```

## Architecture

```
Portal
  |
  +-- nginx (reverse proxy with TLS)
  |     |
  |     +-- /static/* -> static files
  |     +-- /api/* -> portal WSGI
  |     +-- / -> portal WSGI
  |
  +-- Portal WSGI App
  |     |
  |     +-- TenantStore (file-based auth)
  |     +-- Upload Handler (validation + storage)
  |
  +-- DefectDojo (backend)
        |
        +-- PostgreSQL
        +-- Valkey (Redis)
        +-- Celery workers
```

## Troubleshooting

### "Missing Authorization header"

Ensure you include the `Authorization` header:
```bash
curl -H "Authorization: Bearer kek_your_api_key" \
     http://localhost:8000/api/v1/upload
```

### "Invalid file type"

Only `.json` and `.sarif` files are accepted. Ensure your file has the correct extension.

### "File too large"

Check your tenant's `max_upload_size_mb` setting. Default is 10MB.

## Related Documentation

- [CI Mode Guide](../ci-mode.md) - Using Kekkai in CI/CD
- [Dojo Guide](../dojo/dojo.md) - Local DefectDojo orchestration
