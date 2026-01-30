# Kekkai Dojo — Local DefectDojo Orchestration

Kekkai Dojo provides a streamlined way to run DefectDojo locally for vulnerability management and reporting. It handles the complexity of Docker Compose configuration, environment setup, and stack orchestration so you can focus on security testing.

## Overview

DefectDojo is an open-source vulnerability management platform that helps track and prioritize security findings. Kekkai Dojo makes it easy to:

- **Start a local DefectDojo instance** with optimized defaults
- **Manage the stack lifecycle** (start, stop, status checks)
- **Automatically configure** credentials, databases, and services
- **Access the UI** with a single command

All DefectDojo services run in Docker containers using compose profiles, ensuring isolation and reproducibility.

---

## Quick Start

### Prerequisites

- Docker (with Docker Compose v2 or docker-compose v1)
- Available ports: 8080 (HTTP) and 8443 (HTTPS)

### Start DefectDojo

```bash
kekkai dojo up --wait --open
```

This command will:
1. Generate a docker-compose.yml and .env file in `~/.kekkai/dojo/`
2. Create secure random credentials for the database and admin user
3. Start all services (nginx, uwsgi, celery workers, postgres, redis)
4. Wait for the UI to become ready
5. Open `http://localhost:8080/` in your browser

### Default Credentials

The admin credentials are auto-generated and stored in `~/.kekkai/dojo/.env`:

- **Username:** `admin`
- **Password:** (check the `.env` file for `DD_ADMIN_PASSWORD`)

To view your admin password:

```bash
cat ~/.kekkai/dojo/.env | grep DD_ADMIN_PASSWORD
```

### Stop DefectDojo

```bash
kekkai dojo down
```

This stops and removes all containers while preserving data in Docker volumes.

---

## Commands

### `kekkai dojo up`

Start the local DefectDojo stack.

**Options:**
- `--compose-dir <path>` — Directory for compose files (default: `~/.kekkai/dojo`)
- `--project-name <name>` — Docker Compose project name (default: `kekkai-dojo`)
- `--port <port>` — HTTP port for the UI (default: `8080`)
- `--tls-port <port>` — HTTPS port for the UI (default: `8443`)
- `--wait` — Wait for UI to become ready before returning
- `--open` — Open the UI in your default browser after starting

**Environment Variables:**
- `KEKKAI_DOJO_COMPOSE_DIR` — Override compose directory
- `KEKKAI_DOJO_PROJECT_NAME` — Override project name
- `KEKKAI_DOJO_PORT` — Override HTTP port
- `KEKKAI_DOJO_TLS_PORT` — Override HTTPS port

**Examples:**

```bash
# Start with default settings
kekkai dojo up

# Start on custom port and wait for readiness
kekkai dojo up --port 9000 --wait

# Start and immediately open in browser
kekkai dojo up --open

# Use custom compose directory
kekkai dojo up --compose-dir /tmp/my-dojo
```

**Port Collision Detection:**

Kekkai Dojo checks if the specified ports are available before starting. If a port is already in use, the command will fail with an error message. Choose different ports using `--port` and `--tls-port`.

---

### `kekkai dojo down`

Stop and remove all DefectDojo containers.

**Options:**
- `--compose-dir <path>` — Directory for compose files (default: `~/.kekkai/dojo`)
- `--project-name <name>` — Docker Compose project name (default: `kekkai-dojo`)

**Examples:**

```bash
# Stop the stack
kekkai dojo down

# Stop stack in custom directory
kekkai dojo down --compose-dir /tmp/my-dojo
```

**Volume Cleanup:**

Docker volumes (`defectdojo_postgres`, `defectdojo_media`, `defectdojo_redis`) **are removed** by `dojo down` to ensure a clean state and prevent orphaned resources. This is intentional to avoid volume conflicts on subsequent restarts.

If you need to preserve data between sessions, consider backing up volumes before running `dojo down`:

```bash
# Backup postgres data before shutdown
docker run --rm -v kekkai-dojo_defectdojo_postgres:/data -v $(pwd):/backup \
  alpine tar czf /backup/dojo-postgres-backup.tar.gz -C /data .
```

---

### `kekkai dojo status`

Show the current status of all DefectDojo services.

**Options:**
- `--compose-dir <path>` — Directory for compose files (default: `~/.kekkai/dojo`)
- `--project-name <name>` — Docker Compose project name (default: `kekkai-dojo`)

**Example Output:**

```
nginx: running health=healthy ports=[{"HostIp":"0.0.0.0","HostPort":"8080"}]
uwsgi: running
celerybeat: running
celeryworker: running
initializer: exited exit_code=0
postgres: running health=healthy
valkey: running
```

**Service States:**
- `running` — Service is active
- `exited` — Service has stopped (expected for initializer)
- `restarting` — Service is restarting due to failure

**Health Status:**
- `healthy` — Health check passing
- `unhealthy` — Health check failing
- `starting` — Health check in progress

---

### `kekkai dojo open`

Open the DefectDojo UI in your default browser.

**Options:**
- `--compose-dir <path>` — Directory for compose files (default: `~/.kekkai/dojo`)
- `--port <port>` — HTTP port for the UI (default: reads from `.env` or uses `8080`)

**Examples:**

```bash
# Open UI at default port
kekkai dojo open

# Open UI at custom port
kekkai dojo open --port 9000
```

---

## Configuration

### File Locations

All DefectDojo configuration files are stored in `~/.kekkai/dojo/` by default:

- `docker-compose.yml` — Compose stack definition
- `.env` — Environment variables and secrets

### Environment Variables

The `.env` file contains auto-generated values for:

- **Admin Credentials:**
  - `DD_ADMIN_USER` — Admin username (default: `admin`)
  - `DD_ADMIN_PASSWORD` — Auto-generated secure password
  - `DD_ADMIN_MAIL` — Admin email (default: `admin@defectdojo.local`)

- **Database:**
  - `DD_DATABASE_NAME` — Postgres database name
  - `DD_DATABASE_USER` — Postgres user
  - `DD_DATABASE_PASSWORD` — Auto-generated database password
  - `DD_DATABASE_URL` — Full database connection string

- **Services:**
  - `DD_CELERY_BROKER_URL` — Redis/Valkey broker URL
  - `DD_SECRET_KEY` — Django secret key (auto-generated)
  - `DD_CREDENTIAL_AES_256_KEY` — Encryption key (auto-generated)

- **Performance Tuning:**
  - `DD_CELERY_WORKER_CONCURRENCY` — Worker concurrency (default: `1`)
  - `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` — Task prefetch (default: `1`)

### Customization

You can edit `.env` to customize settings, but **do not** regenerate keys or passwords after initialization as this will break the existing database.

Safe to modify:
- `DD_ADMIN_MAIL`
- `DD_ADMIN_FIRST_NAME`
- `DD_ADMIN_LAST_NAME`
- `DD_CELERY_WORKER_CONCURRENCY`
- `DD_ALLOWED_HOSTS`

**Do not modify after first start:**
- `DD_ADMIN_PASSWORD` (change via DefectDojo UI instead)
- `DD_DATABASE_PASSWORD`
- `DD_SECRET_KEY`
- `DD_CREDENTIAL_AES_256_KEY`

---

## Performance Tuning

### Default Settings

Kekkai Dojo uses conservative defaults optimized for local development:

- **Celery Workers:** 1 concurrent worker
- **Postgres:** 50 max connections, 256MB shared buffers
- **Worker Prefetch:** 1 task at a time

### Scaling Up

For heavier workloads, edit `~/.kekkai/dojo/.env`:

```bash
# Increase worker concurrency
DD_CELERY_WORKER_CONCURRENCY=4
DD_CELERY_WORKER_PREFETCH_MULTIPLIER=4
```

Then restart the stack:

```bash
kekkai dojo down
kekkai dojo up --wait
```

### Resource Usage

Expected resource consumption:
- **CPU:** ~1-2 cores under normal load
- **Memory:** ~2-4 GB total across all containers
- **Disk:** ~500MB for images, variable for database (grows with findings)

---

## Docker Compose Details

### Services

The Kekkai Dojo stack includes:

1. **nginx** — Reverse proxy and static file serving
2. **uwsgi** — Django application server
3. **celerybeat** — Scheduled task coordinator
4. **celeryworker** — Background task processor
5. **initializer** — One-time database migration and user creation
6. **postgres** — PostgreSQL 18 database
7. **valkey** — Redis-compatible broker (celery queue)

### Volumes

Three named volumes persist data:

- `defectdojo_postgres` — Database files
- `defectdojo_media` — Uploaded files and reports
- `defectdojo_redis` — Redis/Valkey data

### Profiles

All services use the `dojo` profile. This ensures they only start when explicitly requested via `kekkai dojo up`.

---

## Integration with Kekkai Scan

*(Placeholder for future integration)*

In a future milestone, Kekkai will support uploading scan results directly to the local DefectDojo instance:

```bash
# Run scanners and upload to DefectDojo
kekkai scan --upload-to-dojo
```

This will automatically:
- Create products and engagements
- Upload findings from Semgrep, Trivy, etc.
- Track vulnerability remediation

---

## Troubleshooting

See [Troubleshooting Guide](dojo-troubleshooting.md) for common issues and solutions.

## Security Considerations

See [Security Guide](dojo-security.md) for security best practices and threat model.

---

## Further Reading

- [DefectDojo Documentation](https://documentation.defectdojo.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Kekkai Dojo Security Guide](dojo-security.md)
- [Kekkai Dojo Troubleshooting](dojo-troubleshooting.md)
