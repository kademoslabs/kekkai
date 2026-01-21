# Kekkai Dojo Quick Start

Get a local DefectDojo vulnerability management platform running in minutes.

## Prerequisites

- Docker installed (with Docker Compose)
- Ports 8080 and 8443 available

Verify Docker is running:

```bash
docker --version
docker compose version
```

---

## Start DefectDojo

```bash
kekkai dojo up --wait --open
```

This single command will:
1. ✅ Generate secure configuration and credentials
2. ✅ Start all DefectDojo services in Docker
3. ✅ Wait for the UI to become ready (~2-3 minutes)
4. ✅ Open `http://localhost:8080/` in your browser

---

## Login

When the UI opens, log in with:

- **Username:** `admin`
- **Password:** See `~/.kekkai/dojo/.env`

To view your password:

```bash
cat ~/.kekkai/dojo/.env | grep DD_ADMIN_PASSWORD
```

Copy the password value and log in.

---

## Check Status

At any time, check if DefectDojo is running:

```bash
kekkai dojo status
```

Expected output when healthy:

```
nginx: running health=healthy
uwsgi: running
celerybeat: running
celeryworker: running
initializer: exited exit_code=0
postgres: running health=healthy
valkey: running
```

---

## Stop DefectDojo

When you're done:

```bash
kekkai dojo down
```

Your data is preserved in Docker volumes. Next time you run `kekkai dojo up`, your projects and findings will still be there.

---

## Open UI Later

If DefectDojo is already running and you want to open the UI:

```bash
kekkai dojo open
```

---

## Custom Port

If port 8080 is already in use:

```bash
kekkai dojo up --port 9000 --wait --open
```

This starts DefectDojo on `http://localhost:9000/`.

---

## Complete Removal

To fully remove DefectDojo and all data:

```bash
# Stop services
kekkai dojo down

# Remove Docker volumes (DELETES ALL DATA)
docker volume rm kekkai-dojo_defectdojo_postgres \
                 kekkai-dojo_defectdojo_media \
                 kekkai-dojo_defectdojo_redis

# Remove configuration
rm -rf ~/.kekkai/dojo
```

**Warning:** This permanently deletes all vulnerability findings, projects, and settings.

---

## Next Steps

- Read the [full Kekkai Dojo guide](dojo.md)
- Check the [troubleshooting guide](dojo-troubleshooting.md) if you encounter issues
- Review [security considerations](dojo-security.md) before using in production

---

## Common Issues

### Port Already In Use

**Error:** `Port 8080 is already in use`

**Solution:** Use a different port:

```bash
kekkai dojo up --port 9000 --wait
```

### Docker Not Running

**Error:** `Docker Compose not found`

**Solution:** Start Docker Desktop or the Docker daemon:

```bash
# On Linux with systemd
sudo systemctl start docker

# On macOS/Windows
# Start Docker Desktop application
```

### Services Not Healthy

**Error:** Services show `unhealthy` in status

**Solution:** Check Docker logs:

```bash
docker logs kekkai-dojo-nginx-1
docker logs kekkai-dojo-uwsgi-1
```

See the [troubleshooting guide](dojo-troubleshooting.md) for detailed solutions.
