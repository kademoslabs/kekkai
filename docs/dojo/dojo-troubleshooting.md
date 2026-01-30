# Kekkai Dojo Troubleshooting

Common issues and solutions for running DefectDojo locally with Kekkai Dojo.

---

## Installation Issues

### Docker Not Found

**Symptom:**

```
RuntimeError: Docker Compose not found; install docker and docker compose
```

**Cause:** Docker or Docker Compose is not installed or not in PATH.

**Solution:**

Install Docker:

- **macOS/Windows:** Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- **Linux:** Follow [Docker Engine installation](https://docs.docker.com/engine/install/)

Verify installation:

```bash
docker --version
docker compose version
```

---

### Port Already In Use

**Symptom:**

```
RuntimeError: Port 8080 is already in use
```

**Cause:** Another service is already bound to port 8080 or 8443.

**Solution 1:** Use a different port:

```bash
kekkai dojo up --port 9000 --tls-port 9443 --wait
```

**Solution 2:** Find and stop the conflicting service:

```bash
# On Linux/macOS
sudo lsof -i :8080
sudo lsof -i :8443

# On Windows (PowerShell)
Get-NetTCPConnection -LocalPort 8080
```

Kill the process or change its port configuration.

---

### Permission Denied

**Symptom:**

```
PermissionError: [Errno 13] Permission denied: '/home/user/.kekkai/dojo/.env'
```

**Cause:** Insufficient permissions to create files in `~/.kekkai/dojo/`.

**Solution:**

Ensure the directory is writable:

```bash
mkdir -p ~/.kekkai/dojo
chmod 700 ~/.kekkai/dojo
```

If using Docker in rootless mode, ensure your user is in the `docker` group:

```bash
sudo usermod -aG docker $USER
# Log out and log back in for changes to take effect
```

---

## Startup Issues

### Services Won't Start

**Symptom:**

```bash
kekkai dojo status
# Shows all services as "exited" or "not found"
```

**Cause:** Docker daemon not running or compose file corrupted.

**Solution 1:** Start Docker daemon:

```bash
# On Linux with systemd
sudo systemctl start docker

# On macOS/Windows
# Start Docker Desktop application
```

**Solution 2:** Regenerate compose file:

```bash
rm -rf ~/.kekkai/dojo
kekkai dojo up --wait
```

---

### Container Keeps Restarting

**Symptom:**

```bash
kekkai dojo status
# Shows "restarting" for one or more services
```

**Cause:** Service health check failing or initialization error.

**Solution:**

Check container logs:

```bash
docker logs kekkai-dojo-nginx-1
docker logs kekkai-dojo-uwsgi-1
docker logs kekkai-dojo-postgres-1
```

Common causes:

1. **Database not ready:** Wait longer for postgres to initialize
   ```bash
   docker logs kekkai-dojo-postgres-1
   ```

2. **Port conflict inside containers:** Restart the stack
   ```bash
   kekkai dojo down
   kekkai dojo up --wait
   ```

3. **Insufficient resources:** Increase Docker memory/CPU limits in Docker Desktop settings

---

### Timeout Waiting for UI

**Symptom:**

```
RuntimeError: DefectDojo UI did not become ready in time
```

**Cause:** Services taking longer than 5 minutes to start.

**Solution 1:** Check service status manually:

```bash
kekkai dojo status
```

Wait for all services to show `running` and nginx to show `health=healthy`.

**Solution 2:** Check nginx logs:

```bash
docker logs kekkai-dojo-nginx-1
```

Look for errors like:
- `502 Bad Gateway` → uwsgi not ready
- `Connection refused` → Database not ready

**Solution 3:** Increase timeout by starting without `--wait`, then check status:

```bash
kekkai dojo up
# Wait 5 minutes
kekkai dojo status
```

---

## Runtime Issues

### Cannot Access UI

**Symptom:**

Browser shows "Unable to connect" at `http://localhost:8080/`.

**Cause:** Services not running or firewall blocking connection.

**Solution 1:** Check service status:

```bash
kekkai dojo status
```

Ensure nginx is `running` and `health=healthy`.

**Solution 2:** Test with curl:

```bash
curl -I http://localhost:8080/
```

If curl works but browser doesn't, try:
- Clear browser cache
- Try a different browser
- Use incognito/private mode

**Solution 3:** Check firewall:

```bash
# Linux
sudo iptables -L -n | grep 8080

# macOS
sudo pfctl -s rules | grep 8080
```

Temporarily disable firewall for testing (re-enable afterward).

---

### Login Fails

**Symptom:**

DefectDojo UI rejects admin credentials.

**Cause:** Incorrect password or initializer failed.

**Solution 1:** Verify password:

```bash
cat ~/.kekkai/dojo/.env | grep DD_ADMIN_PASSWORD
```

Copy the exact value (no extra spaces).

**Solution 2:** Check initializer logs:

```bash
docker logs kekkai-dojo-initializer-1
```

Look for errors like:
- `Database connection failed` → Check postgres logs
- `Admin user already exists` → Normal, use existing password

**Solution 3:** Reset admin password:

```bash
docker exec -it kekkai-dojo-uwsgi-1 \
  python manage.py changepassword admin
```

Follow prompts to set a new password.

---

### Slow Performance

**Symptom:**

DefectDojo UI is slow or unresponsive.

**Cause:** Insufficient resources or too few workers.

**Solution 1:** Check Docker resource usage:

```bash
docker stats
```

If memory/CPU is maxed out, increase Docker limits in Docker Desktop settings.

**Solution 2:** Increase worker concurrency:

Edit `~/.kekkai/dojo/.env`:

```bash
DD_CELERY_WORKER_CONCURRENCY=4
DD_CELERY_WORKER_PREFETCH_MULTIPLIER=4
```

Restart:

```bash
kekkai dojo down
kekkai dojo up --wait
```

**Solution 3:** Check database performance:

```bash
docker exec -it kekkai-dojo-postgres-1 \
  psql -U defectdojo -c "SELECT count(*) FROM django_session;"
```

If session count is very high, clear old sessions:

```bash
docker exec -it kekkai-dojo-uwsgi-1 \
  python manage.py clearsessions
```

---

### Data Loss After Restart

**Symptom:**

Projects and findings disappear after running `kekkai dojo down` and `kekkai dojo up`.

**Cause:** This is expected behavior. `kekkai dojo down` removes volumes by default to ensure clean state and prevent orphaned resources.

**Solution:**

If you need to preserve data between sessions:

1. **Backup before shutdown:**

   ```bash
   # Backup postgres data
   docker run --rm -v kekkai-dojo_defectdojo_postgres:/data -v $(pwd):/backup \
     alpine tar czf /backup/dojo-postgres-backup.tar.gz -C /data .
   ```

2. **Restore after startup:**

   ```bash
   kekkai dojo up --wait
   # Stop postgres temporarily
   docker stop kekkai-dojo-postgres-1
   # Restore data
   docker run --rm -v kekkai-dojo_defectdojo_postgres:/data -v $(pwd):/backup \
     alpine sh -c "cd /data && tar xzf /backup/dojo-postgres-backup.tar.gz"
   # Restart postgres
   docker start kekkai-dojo-postgres-1
   ```

3. **For persistent development:**

   Consider using DefectDojo's native docker-compose setup if you need data persistence across sessions.

---

## Database Issues

### Connection Refused

**Symptom:**

```
django.db.utils.OperationalError: could not connect to server: Connection refused
```

**Cause:** Postgres not running or not healthy.

**Solution 1:** Check postgres status:

```bash
kekkai dojo status | grep postgres
```

Should show `running health=healthy`.

**Solution 2:** Check postgres logs:

```bash
docker logs kekkai-dojo-postgres-1
```

Look for:
- `database system is ready to accept connections` → Good
- `FATAL: password authentication failed` → Credential mismatch

**Solution 3:** Restart postgres:

```bash
docker restart kekkai-dojo-postgres-1
```

Wait 30 seconds, then check status again.

---

### Migration Errors

**Symptom:**

```
django.db.migrations.exceptions.InconsistentMigrationHistory
```

**Cause:** Database schema corrupted or out of sync.

**Solution:**

Recreate the database:

```bash
kekkai dojo down
docker volume rm kekkai-dojo_defectdojo_postgres
kekkai dojo up --wait
```

**⚠️ Warning:** This deletes all vulnerability data.

---

## Network Issues

### Cannot Reach External Services

**Symptom:**

DefectDojo cannot fetch data from external APIs (e.g., CVE databases).

**Cause:** Docker network isolation or firewall blocking outbound connections.

**Solution 1:** Test outbound connectivity:

```bash
docker exec -it kekkai-dojo-uwsgi-1 \
  curl -I https://nvd.nist.gov/
```

If this fails, check:
- Host internet connection
- Docker network mode (should be `bridge`)
- Outbound firewall rules

**Solution 2:** Configure HTTP proxy (if behind corporate proxy):

Edit `~/.kekkai/dojo/.env`:

```bash
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=http://proxy.company.com:8080
```

Restart stack:

```bash
kekkai dojo down
kekkai dojo up --wait
```

---

### Port Forwarding Not Working

**Symptom:**

Cannot access DefectDojo from another machine on the network.

**Cause:** Docker binds to `0.0.0.0` by default, but firewall may block incoming connections.

**Solution:**

Enable incoming connections (⚠️ only on trusted networks):

**Linux (ufw):**
```bash
sudo ufw allow 8080/tcp
```

**macOS:**
System Preferences → Security & Privacy → Firewall → Firewall Options → Allow DefectDojo

**⚠️ Security Warning:** See [Security Guide](dojo-security.md) before exposing DefectDojo to the network.

---

## Docker Compose Issues

### Version Mismatch

**Symptom:**

```
ERROR: The Compose file './docker-compose.yml' is invalid
```

**Cause:** Docker Compose v1 and v2 have different syntax.

**Solution:**

Kekkai Dojo uses Compose v2 format (3.9). Ensure you have Docker Compose v2:

```bash
docker compose version
# Should show: Docker Compose version v2.x.x
```

If using v1 (`docker-compose`), upgrade to v2.

---

### Profile Not Applied

**Symptom:**

Services show as "not found" or don't start.

**Cause:** Docker Compose not using the `dojo` profile.

**Solution:**

Kekkai Dojo automatically applies the `dojo` profile. If you manually run `docker compose`, add:

```bash
docker compose --profile dojo up
```

---

## Cleanup and Reset

### Complete Reset

To completely remove Kekkai Dojo and start fresh:

```bash
# 1. Stop all services
kekkai dojo down

# 2. Remove containers (if any remain)
docker rm -f $(docker ps -aq --filter "name=kekkai-dojo")

# 3. Remove volumes (DELETES ALL DATA)
docker volume rm kekkai-dojo_defectdojo_postgres \
                 kekkai-dojo_defectdojo_media \
                 kekkai-dojo_defectdojo_redis

# 4. Remove configuration
rm -rf ~/.kekkai/dojo

# 5. Start fresh
kekkai dojo up --wait --open
```

---

## Getting Help

If your issue is not listed here:

1. **Check Docker logs:** `docker logs <container-name>`
2. **Search DefectDojo issues:** [DefectDojo GitHub Issues](https://github.com/DefectDojo/django-DefectDojo/issues)
3. **Check Kekkai issues:** [Kekkai GitHub Issues](https://github.com/kademoslabs/kekkai/issues)
4. **Ask the community:** DefectDojo Slack or forums

When reporting issues, include:
- Output of `kekkai dojo status`
- Relevant logs from `docker logs`
- Your Docker version: `docker --version`
- Your OS and version

---

## Known Limitations

1. **TLS/HTTPS:** Kekkai Dojo does not configure HTTPS. For secure connections, use a reverse proxy like Caddy or nginx.

2. **Email:** Email sending is not configured. Password resets and notifications will not work without SMTP setup.

3. **LDAP/SSO:** Enterprise authentication methods are not configured in the default setup.

4. **Backups:** No automatic backup mechanism. You must manually backup volumes if needed.

5. **Multi-user:** While DefectDojo supports multiple users, Kekkai Dojo is optimized for single-user local development.

For production deployments with these features, see the [DefectDojo documentation](https://documentation.defectdojo.com/).
