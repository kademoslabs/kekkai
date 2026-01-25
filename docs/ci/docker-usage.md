# Docker Usage Guide

Run Kekkai CLI in a hardened Docker container without installing Python locally.

## Quick Start

### Build the Image

```bash
cd /path/to/kekkai
docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .
```

### Run Commands

```bash
# Show help
docker run --rm kademoslabs/kekkai:latest --help

# Show version
docker run --rm kademoslabs/kekkai:latest --version

# Run scan (mount current directory read-only)
docker run --rm -v "$(pwd):/workspace:ro" -w /workspace \
  kademoslabs/kekkai:latest scan --repo /workspace
```

---

## Using the Hardened Wrapper Script

For convenience and security, use the provided wrapper script:

```bash
# Make wrapper executable
chmod +x scripts/kekkai-docker

# Run commands
./scripts/kekkai-docker --help
./scripts/kekkai-docker scan --repo .
```

### Set Up Alias

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
alias kekkai="/path/to/kekkai/scripts/kekkai-docker"
```

Now you can run:

```bash
kekkai --version
kekkai scan --repo .
```

---

## Security Model

The Docker wrapper applies multiple security hardening controls:

### 1. Non-Root User Execution

- Container runs as UID 1000 (user `kekkai`)
- No root privileges inside the container
- Limits privilege escalation attack surface

### 2. Read-Only Filesystem

- Container root filesystem is read-only (`--read-only`)
- Only `/tmp` is writable (via tmpfs with `noexec,nosuid`)
- Prevents container modification attacks

### 3. Dropped Capabilities

- All Linux capabilities dropped (`--cap-drop=ALL`)
- Container cannot perform privileged operations
- Mitigates container escape vulnerabilities

### 4. No Privilege Escalation

- `--security-opt=no-new-privileges:true`
- Prevents gaining additional privileges via setuid binaries
- Defense-in-depth control

### 5. Read-Only Repository Mount

- Host repository mounted as `-v $(pwd):/workspace:ro`
- Container cannot modify source code or repository
- Prevents tampering with scan targets

---

## Threat Model

### Abuser Stories & Mitigations

| Abuser Story | Mitigation |
|--------------|------------|
| **AS-1**: Attacker tries to escalate privileges via container | All capabilities dropped, `no-new-privileges` flag set |
| **AS-2**: Attacker attempts to write to host filesystem | Repository mounted read-only, container filesystem read-only |
| **AS-3**: Attacker exploits container runtime vulnerability | Minimal base image (python:3.12-slim), non-root user, defense-in-depth layers |
| **AS-4**: Attacker modifies container filesystem to persist malware | Read-only filesystem prevents modifications |
| **AS-5**: Attacker uses tmpfs to execute malicious code | tmpfs mounted with `noexec` flag |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Kekkai Docker Image
        run: docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .

      - name: Run Security Scan
        run: |
          docker run --rm \
            -v "$PWD:/workspace:ro" \
            -w /workspace \
            kademoslabs/kekkai:latest scan --repo /workspace --ci
```

### GitLab CI

```yaml
security_scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .
    - docker run --rm -v "$CI_PROJECT_DIR:/workspace:ro" -w /workspace
        kademoslabs/kekkai:latest scan --repo /workspace --ci
```

### CircleCI

```yaml
version: 2.1

jobs:
  scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - setup_remote_docker
      - run:
          name: Build Kekkai Image
          command: docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .
      - run:
          name: Security Scan
          command: |
            docker run --rm -v "$PWD:/workspace:ro" -w /workspace \
              kademoslabs/kekkai:latest scan --repo /workspace --ci
```

---

## Troubleshooting

### Permission Denied Errors

If you see "permission denied" when scanning:

**Problem**: Container runs as UID 1000, but your files are owned by different user.

**Solution**: Files are mounted read-only, so this is expected for write operations. For scanning, read-only access is sufficient.

### Docker Not Found

**Problem**: `docker: command not found`

**Solution**: Install Docker following [official documentation](https://docs.docker.com/get-docker/).

### Image Build Fails

**Problem**: Build errors during `docker build`

**Solutions**:
- Ensure you're in the project root directory
- Check that `apps/kekkai/Dockerfile` exists
- Verify `pyproject.toml` and `src/` directory are present
- Check network connectivity for pulling base image

### Slow Build Times

**Problem**: Image builds take too long

**Solutions**:
- Use BuildKit: `DOCKER_BUILDKIT=1 docker build ...`
- Check Docker disk space: `docker system df`
- Clean up old images: `docker system prune`

### Container Exits Immediately

**Problem**: Container starts but exits without output

**Solution**: Check logs with `docker logs <container_id>` or run with `-it` for interactive mode.

---

## Advanced Usage

### Custom Output Directory

To write scan results outside container:

```bash
# Create output directory on host
mkdir -p ./kekkai-results

# Mount it as writable
docker run --rm \
  -v "$(pwd):/workspace:ro" \
  -v "$(pwd)/kekkai-results:/output:rw" \
  -w /workspace \
  kademoslabs/kekkai:latest scan --repo /workspace --run-dir /output
```

### Running DefectDojo Stack

The Docker wrapper is for CLI only. For DefectDojo, use existing commands:

```bash
kekkai dojo up --wait --open
```

### Debugging Container

To debug issues inside the container:

```bash
docker run --rm -it --entrypoint /bin/bash \
  kademoslabs/kekkai:latest
```

---

## Related Documentation

- [CI Mode Guide](ci-mode.md) - Policy enforcement in CI/CD
- [Kekkai Dojo Guide](../dojo/dojo.md) - DefectDojo integration
- [Main README](../../README.md) - Project overview

---

## Support

For issues with Docker wrapper:

1. Check [GitHub Issues](https://github.com/kademoslabs/kekkai/issues)
2. Review [Troubleshooting](#troubleshooting) section above
3. Report security concerns to [security@kademos.org](mailto:security@kademos.org)
