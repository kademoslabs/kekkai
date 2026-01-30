# Kekkai Troubleshooting Guide

Solutions for common issues when using Kekkai.

---

## Quick Diagnostics

Run these commands to gather diagnostic information:

```bash
# Check Kekkai version
kekkai --version

# Check Docker status
docker info

# Check Docker Compose
docker compose version

# Verify configuration
cat ~/.config/kekkai/config.toml
```

---

## Docker Issues

### Docker Daemon Not Running

**Symptom:**
```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock
```

**Solutions:**

1. **Start Docker daemon:**
   ```bash
   # Linux (systemd)
   sudo systemctl start docker

   # macOS
   open -a Docker

   # Windows
   # Start Docker Desktop from Start menu
   ```

2. **Check Docker status:**
   ```bash
   docker info
   ```

3. **Verify socket permissions:**
   ```bash
   ls -la /var/run/docker.sock
   # Should show: srw-rw---- 1 root docker
   ```

### Permission Denied on Docker Socket

**Symptom:**
```
permission denied while trying to connect to the Docker daemon socket
```

**Solutions:**

1. **Add user to docker group:**
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker  # Apply without logout
   ```

2. **Or use sudo (not recommended for regular use):**
   ```bash
   sudo kekkai scan
   ```

### Docker Image Pull Fails

**Symptom:**
```
Error response from daemon: pull access denied
```

**Solutions:**

1. **Check network connectivity:**
   ```bash
   docker pull hello-world
   ```

2. **Verify image exists:**
   ```bash
   docker pull aquasec/trivy:latest
   docker pull returntocorp/semgrep:latest
   docker pull zricethezav/gitleaks:latest
   ```

3. **Check Docker Hub rate limits:**
   ```bash
   # Authenticate to increase limits
   docker login
   ```

4. **Use a mirror if behind firewall:**
   ```bash
   # Configure Docker daemon.json with mirror
   ```

---

## Scanner Issues

### Trivy Scanner Fails

**Symptom:**
```
trivy failed: timeout exceeded
```

**Solutions:**

1. **Increase timeout:**
   ```bash
   kekkai scan --timeout 1800  # 30 minutes
   ```

2. **Check Trivy database update:**
   ```bash
   docker run --rm aquasec/trivy:latest image --download-db-only
   ```

3. **Verify sufficient disk space:**
   ```bash
   df -h
   # Trivy needs ~500MB for database
   ```

### Semgrep Scanner Fails

**Symptom:**
```
semgrep failed: out of memory
```

**Solutions:**

1. **Increase Docker memory limit:**
   - Docker Desktop: Settings > Resources > Memory
   - Minimum: 4GB recommended

2. **Scan specific directories:**
   ```bash
   kekkai scan --repo ./src  # Smaller scope
   ```

3. **Exclude large directories in `.semgrepignore`:**
   ```
   node_modules/
   vendor/
   dist/
   ```

### Gitleaks Scanner Fails

**Symptom:**
```
gitleaks failed: unable to detect git repository
```

**Solutions:**

1. **Ensure directory is a git repository:**
   ```bash
   git status
   # Or initialize if needed:
   git init
   ```

2. **Check git availability:**
   ```bash
   git --version
   ```

3. **Gitleaks runs with `--no-git` flag by default** - this scans files without requiring git history. If you see this error, check file permissions.

### All Scanners Timeout

**Symptom:**
```
Scanner timeout after 900s
```

**Solutions:**

1. **Increase global timeout:**
   ```toml
   # config.toml
   timeout_seconds = 1800
   ```

2. **Or via CLI:**
   ```bash
   KEKKAI_TIMEOUT_SECONDS=1800 kekkai scan
   ```

3. **Check system resources:**
   ```bash
   # CPU/memory usage
   top
   htop

   # Docker resource usage
   docker stats
   ```

---

## DefectDojo Issues

### Dojo Stack Won't Start

**Symptom:**
```
Error: Cannot start service django
```

**Solutions:**

1. **Check port availability:**
   ```bash
   # Check if port 8080 is in use
   lsof -i :8080
   netstat -tlnp | grep 8080

   # Use different port
   kekkai dojo up --port 9000
   ```

2. **Clean up previous runs:**
   ```bash
   kekkai dojo down
   docker system prune -f
   kekkai dojo up --wait
   ```

3. **Check Docker Compose logs:**
   ```bash
   cd ~/.kekkai/dojo
   docker compose logs
   ```

### Dojo Health Check Fails

**Symptom:**
```
Waiting for DefectDojo... timeout
```

**Solutions:**

1. **Check service status:**
   ```bash
   kekkai dojo status
   ```

2. **View container logs:**
   ```bash
   cd ~/.kekkai/dojo
   docker compose logs django
   docker compose logs celeryworker
   ```

3. **Restart specific service:**
   ```bash
   cd ~/.kekkai/dojo
   docker compose restart django
   ```

4. **Increase wait timeout:**
   ```bash
   # Wait longer for slow systems
   sleep 60 && kekkai dojo status
   ```

### Dojo Import Fails

**Symptom:**
```
Import failed: 401 Unauthorized
```

**Solutions:**

1. **Verify API key:**
   ```bash
   # Get API key from DefectDojo UI:
   # Settings > API v2 Key
   export KEKKAI_DOJO_API_KEY="your-key-here"
   ```

2. **Check Dojo URL:**
   ```bash
   curl http://localhost:8080/api/v2/
   # Should return API info
   ```

3. **Verify product/engagement exist:**
   - Log into DefectDojo UI
   - Create Product if needed
   - Create Engagement if needed

---

## Configuration Issues

### Config File Not Found

**Symptom:**
```
Config not found at ~/.config/kekkai/config.toml
```

**Solutions:**

1. **Initialize configuration:**
   ```bash
   kekkai init
   ```

2. **Use custom config path:**
   ```bash
   kekkai scan --config ./my-config.toml
   ```

3. **Check default location:**
   ```bash
   # Linux/macOS
   ls -la ~/.config/kekkai/

   # Windows
   dir %APPDATA%\kekkai\
   ```

### Invalid TOML Syntax

**Symptom:**
```
ValueError: config file must contain a table
```

**Solutions:**

1. **Validate TOML syntax:**
   ```bash
   # Install toml validator
   pip install toml
   python -c "import toml; toml.load('config.toml')"
   ```

2. **Check for common errors:**
   - Missing quotes around strings
   - Unclosed brackets
   - Invalid characters

3. **Reset to defaults:**
   ```bash
   kekkai init --force
   ```

### Environment Variable Not Working

**Symptom:**
```
Environment variable KEKKAI_* not being applied
```

**Solutions:**

1. **Verify variable is set:**
   ```bash
   echo $KEKKAI_REPO_PATH
   env | grep KEKKAI
   ```

2. **Export the variable:**
   ```bash
   export KEKKAI_REPO_PATH="/path/to/repo"
   # Not just: KEKKAI_REPO_PATH="/path/to/repo"
   ```

3. **Check precedence:**
   - CLI flags override environment variables
   - Environment variables override config file

---

## CI/CD Issues

### GitHub Actions: Docker Not Available

**Symptom:**
```
Cannot connect to Docker daemon
```

**Solutions:**

1. **Use correct runner:**
   ```yaml
   runs-on: ubuntu-latest  # Has Docker pre-installed
   ```

2. **Don't use `container:` with Docker commands:**
   ```yaml
   # WRONG - container doesn't have Docker access
   container: python:3.12

   # RIGHT - use runner directly
   runs-on: ubuntu-latest
   ```

### GitLab CI: Docker-in-Docker Issues

**Symptom:**
```
error during connect: Get http://docker:2376/v1.40/info
```

**Solutions:**

1. **Configure DinD properly:**
   ```yaml
   services:
     - docker:24-dind

   variables:
     DOCKER_HOST: tcp://docker:2376
     DOCKER_TLS_CERTDIR: "/certs"
     DOCKER_CERT_PATH: "/certs/client"
     DOCKER_TLS_VERIFY: "1"
   ```

2. **Use privileged mode:**
   ```yaml
   # In GitLab runner config
   [[runners]]
     [runners.docker]
       privileged = true
   ```

### CircleCI: Remote Docker Issues

**Symptom:**
```
Error: docker socket not available
```

**Solutions:**

1. **Add setup_remote_docker:**
   ```yaml
   steps:
     - checkout
     - setup_remote_docker:
         version: 20.10.18
     - run: kekkai scan --ci
   ```

2. **Note: Volume mounts don't work with remote Docker.** Copy files instead:
   ```yaml
   - run: docker cp . container:/workspace
   ```

### PR Comments Not Posting

**Symptom:**
```
PR comment requested but no GitHub token provided
```

**Solutions:**

1. **Set token in environment:**
   ```yaml
   env:
     GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
   ```

2. **Check permissions:**
   ```yaml
   permissions:
     contents: read
     pull-requests: write
   ```

3. **Verify PR context:**
   - Comments only work in PR context
   - Check `GITHUB_EVENT_PATH` is set

---

## ThreatFlow Issues

### Local Model Not Found

**Symptom:**
```
Error: Local model not found at specified path
```

**Solutions:**

1. **Download a model:**
   ```bash
   # Example with llama.cpp compatible model
   wget https://huggingface.co/TheBloke/model/resolve/main/model.gguf
   ```

2. **Specify correct path:**
   ```bash
   kekkai threatflow --model-path /path/to/model.gguf
   ```

3. **Use mock mode for testing:**
   ```bash
   kekkai threatflow --model-mode mock
   ```

### Remote API Key Invalid

**Symptom:**
```
Error: API key required for remote mode
```

**Solutions:**

1. **Set API key via environment:**
   ```bash
   export KEKKAI_THREATFLOW_API_KEY="your-key"
   kekkai threatflow --model-mode openai
   ```

2. **Or via CLI (less secure):**
   ```bash
   kekkai threatflow --model-mode openai --api-key "your-key"
   ```

---

## Performance Issues

### Scans Are Slow

**Solutions:**

1. **Exclude unnecessary directories:**
   ```toml
   # .semgrepignore
   node_modules/
   vendor/
   .git/
   dist/
   build/
   ```

2. **Run specific scanners:**
   ```bash
   kekkai scan --scanners trivy  # Just one scanner
   ```

3. **Increase resources:**
   - Docker Desktop: Increase CPU/memory allocation
   - CI: Use larger runners

### High Memory Usage

**Solutions:**

1. **Limit concurrent scanners:**
   ```bash
   # Run sequentially instead of parallel
   kekkai scan --scanners trivy
   kekkai scan --scanners semgrep
   kekkai scan --scanners gitleaks
   ```

2. **Reduce repository size:**
   - Use sparse checkout in CI
   - Exclude large binary files

---

## Getting Help

If you're still stuck:

1. **Check existing issues:**
   [GitHub Issues](https://github.com/kademoslabs/kekkai/issues)

2. **File a new issue with:**
   - Kekkai version (`kekkai --version`)
   - OS and version
   - Docker version (`docker version`)
   - Full error message
   - Steps to reproduce

3. **Security issues:**
   Email [security@kademos.org](mailto:security@kademos.org)

---

## See Also

- [CLI Reference](../ci/cli-reference.md) - Command options
- [Configuration Guide](../config/configuration.md) - Config file format
- [CI Integration Guide](../ci/ci-integration.md) - CI/CD setup
