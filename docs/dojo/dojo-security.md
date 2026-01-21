# Kekkai Dojo Security Guide

This document outlines security considerations, threat model, and best practices for running DefectDojo locally with Kekkai Dojo.

---

## Security Model

### Local-First Design

Kekkai Dojo is designed for **local development and testing** environments. It:

- ✅ Runs entirely on your machine (no cloud dependencies)
- ✅ Generates unique credentials per installation
- ✅ Uses isolated Docker containers with minimal privileges
- ✅ Does not expose services to the network by default

### Not Production-Ready

**⚠️ Kekkai Dojo is NOT intended for production deployments.** It lacks:

- ❌ TLS/HTTPS configuration for the UI
- ❌ Network isolation and firewall rules
- ❌ Backup and disaster recovery
- ❌ High availability and load balancing
- ❌ Hardened container images and security scanning
- ❌ Audit logging and monitoring

For production DefectDojo deployments, follow the [official DefectDojo production guide](https://documentation.defectdojo.com/production/).

---

## Threat Model

### Threats Mitigated

1. **Credential Reuse**
   - **Risk:** Using default passwords like `admin/admin` in local environments
   - **Mitigation:** Kekkai Dojo auto-generates strong random passwords for admin and database users

2. **Port Collisions**
   - **Risk:** Accidentally binding to ports already in use, causing service conflicts
   - **Mitigation:** Pre-flight port availability checks before starting services

3. **Container Privilege Escalation**
   - **Risk:** Containers with elevated privileges could pivot to the host
   - **Mitigation:** No containers run with `privileged: true`, no extra Linux capabilities, no host filesystem mounts

4. **Exposed Secrets in Logs**
   - **Risk:** Credentials printed to stdout/stderr during setup
   - **Mitigation:** Passwords are stored in `.env` files only, not printed to console

### Threats NOT Mitigated

1. **Docker Socket Exposure**
   - **Risk:** Docker socket (`/var/run/docker.sock`) provides root-equivalent access to the host
   - **Impact:** If Docker runs as root, any container compromise could escalate to full host control
   - **Recommendation:** Use Docker in rootless mode where possible, or ensure trusted images only

2. **Local File System Access**
   - **Risk:** The `.env` file in `~/.kekkai/dojo/.env` contains sensitive credentials in plaintext
   - **Impact:** Any user or process with read access to your home directory can read credentials
   - **Recommendation:**
     - Set restrictive file permissions: `chmod 600 ~/.kekkai/dojo/.env`
     - Use encrypted home directories
     - Do not commit `.env` files to version control

3. **Network Exposure**
   - **Risk:** Services bind to `0.0.0.0` by default, making them accessible to the network
   - **Impact:** If your firewall allows incoming connections, DefectDojo could be accessible to other machines
   - **Recommendation:**
     - Run a firewall that blocks incoming connections by default
     - On shared networks, bind to `127.0.0.1` instead (requires manual compose file editing)

4. **Data Persistence**
   - **Risk:** Docker volumes persist data indefinitely, even after `kekkai dojo down`
   - **Impact:** Sensitive vulnerability data remains on disk until volumes are explicitly removed
   - **Recommendation:** Remove volumes when no longer needed:
     ```bash
     docker volume rm kekkai-dojo_defectdojo_postgres \
                      kekkai-dojo_defectdojo_media \
                      kekkai-dojo_defectdojo_redis
     ```

5. **Supply Chain Attacks**
   - **Risk:** DefectDojo Docker images are pulled from Docker Hub without signature verification
   - **Impact:** Compromised images could execute malicious code
   - **Recommendation:**
     - Pin specific image versions instead of `:latest`
     - Scan images with tools like `docker scan` or Trivy
     - Review DefectDojo's official images and build from source if needed

---

## Best Practices

### Secure Configuration

1. **Restrict File Permissions**

   ```bash
   chmod 700 ~/.kekkai/dojo
   chmod 600 ~/.kekkai/dojo/.env
   ```

2. **Use Strong Passwords**

   Kekkai Dojo generates 20-character random passwords by default. If you change them, ensure they are strong:

   ```bash
   # Generate a secure password
   openssl rand -base64 24
   ```

3. **Rotate Credentials Regularly**

   If you use DefectDojo long-term, rotate the admin password periodically via the DefectDojo UI (Settings → Users).

4. **Limit Network Exposure**

   To bind DefectDojo to localhost only, edit `~/.kekkai/dojo/docker-compose.yml`:

   ```yaml
   services:
     nginx:
       ports:
         - target: 8080
           published: 8080
           protocol: tcp
           mode: host
           # Add this line:
           bind: 127.0.0.1
   ```

   **Note:** This requires stopping and restarting the stack.

5. **Use Docker Rootless Mode**

   Run Docker without root privileges to limit container-to-host escalation risks:

   - [Docker Rootless Mode Documentation](https://docs.docker.com/engine/security/rootless/)

---

### Data Protection

1. **Encrypt Home Directory**

   Use full-disk encryption or encrypted home directories (e.g., FileVault on macOS, LUKS on Linux).

2. **Backup Sensitive Data**

   If you store real vulnerability data in DefectDojo:

   ```bash
   # Backup volumes
   docker run --rm \
     -v kekkai-dojo_defectdojo_postgres:/data \
     -v $(pwd):/backup \
     alpine tar czf /backup/dojo-postgres-backup.tar.gz /data
   ```

   Store backups securely (encrypted, access-controlled).

3. **Clean Up After Use**

   Remove the stack and volumes when no longer needed:

   ```bash
   kekkai dojo down
   docker volume rm kekkai-dojo_defectdojo_postgres \
                    kekkai-dojo_defectdojo_media \
                    kekkai-dojo_defectdojo_redis
   rm -rf ~/.kekkai/dojo
   ```

---

### Network Security

1. **Use a Firewall**

   Ensure your host firewall blocks incoming connections by default.

   **Linux (ufw):**
   ```bash
   sudo ufw enable
   sudo ufw default deny incoming
   ```

   **macOS:**
   Enable the built-in firewall in System Preferences → Security & Privacy → Firewall.

2. **Avoid Public Networks**

   Do not run Kekkai Dojo on untrusted networks (e.g., public Wi-Fi) without a VPN.

3. **Monitor Network Activity**

   Check which ports Docker is exposing:

   ```bash
   docker ps --format "table {{.Names}}\t{{.Ports}}"
   ```

---

### Container Security

1. **Scan Images**

   Before running DefectDojo, scan the images:

   ```bash
   docker pull defectdojo/defectdojo-django:latest
   docker scan defectdojo/defectdojo-django:latest
   ```

   Or use Trivy:

   ```bash
   trivy image defectdojo/defectdojo-django:latest
   ```

2. **Pin Image Versions**

   Edit `~/.kekkai/dojo/.env` to pin specific versions:

   ```bash
   DJANGO_VERSION=2.33.5
   NGINX_VERSION=1.33.5
   ```

   Check [DefectDojo releases](https://github.com/DefectDojo/django-DefectDojo/releases) for the latest stable versions.

3. **Limit Container Capabilities**

   Kekkai Dojo does not grant extra capabilities to containers. If you modify the compose file, avoid:

   ```yaml
   # DO NOT ADD THESE
   privileged: true
   cap_add:
     - SYS_ADMIN
   ```

---

## Incident Response

### Suspected Compromise

If you suspect your Kekkai Dojo instance has been compromised:

1. **Stop All Services Immediately**

   ```bash
   kekkai dojo down
   ```

2. **Inspect Logs**

   ```bash
   docker logs kekkai-dojo-nginx-1
   docker logs kekkai-dojo-uwsgi-1
   docker logs kekkai-dojo-postgres-1
   ```

   Look for:
   - Unexpected login attempts
   - Database connection errors
   - Network connections to unknown IPs

3. **Remove Containers and Volumes**

   ```bash
   docker rm -f $(docker ps -aq --filter "name=kekkai-dojo")
   docker volume rm kekkai-dojo_defectdojo_postgres \
                    kekkai-dojo_defectdojo_media \
                    kekkai-dojo_defectdojo_redis
   ```

4. **Regenerate Credentials**

   ```bash
   rm -rf ~/.kekkai/dojo
   kekkai dojo up --wait
   ```

5. **Review Host Security**

   - Check for unauthorized SSH keys
   - Review running processes: `ps aux`
   - Check for suspicious cron jobs: `crontab -l`

---

## Reporting Security Issues

If you discover a security vulnerability in Kekkai Dojo:

**Do NOT open a public issue.**

Report privately to: **[security@kademos.org](mailto:security@kademos.org)**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if applicable)

---

## Further Reading

- [DefectDojo Security Documentation](https://documentation.defectdojo.com/security/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
