# Kekkai CI/CD Integration Guide

Integrate Kekkai into your CI/CD pipelines for automated security scanning.

---

## Overview

Kekkai provides CI mode (`--ci`) that:
- Runs security scanners
- Evaluates policy rules
- Returns appropriate exit codes
- Outputs structured JSON for downstream tools
- Posts findings as PR comments (optional)

---

## Exit Codes

| Code | Meaning | CI Action |
|------|---------|-----------|
| `0` | All checks passed | Continue pipeline |
| `1` | General error | Fail job |
| `2` | Policy violation | Fail job (findings exceed threshold) |
| `3` | Scanner error | Fail job (scanner failed) |

---

## GitHub Actions

### Basic Workflow

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Kekkai
        run: pip install kekkai-cli

      - name: Run Security Scan
        run: kekkai scan --ci --fail-on critical,high

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: ~/.kekkai/runs/
```

### With PR Comments

```yaml
# .github/workflows/security-pr.yml
name: Security Scan with PR Comments

on:
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Kekkai
        run: pip install kekkai-cli

      - name: Run Security Scan with PR Comments
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          kekkai scan --ci \
            --fail-on critical,high \
            --pr-comment \
            --comment-severity medium \
            --max-comments 25
```

### Full Pipeline with DefectDojo

```yaml
# .github/workflows/security-full.yml
name: Full Security Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    services:
      docker:
        image: docker:24-dind
        options: --privileged
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Kekkai
        run: pip install kekkai-cli

      - name: Initialize Kekkai
        run: kekkai init

      - name: Run Security Scan
        id: scan
        run: |
          kekkai scan --ci \
            --fail-on critical,high \
            --output ./policy-result.json
        continue-on-error: true

      - name: Upload Policy Result
        uses: actions/upload-artifact@v4
        with:
          name: policy-result
          path: ./policy-result.json

      - name: Check Scan Result
        if: steps.scan.outcome == 'failure'
        run: |
          echo "Security scan found policy violations"
          cat ./policy-result.json
          exit 1
```

### Matrix Strategy for Multiple Scanners

```yaml
# .github/workflows/security-matrix.yml
name: Security Scan Matrix

on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        scanner: [trivy, semgrep, gitleaks]
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Kekkai
        run: pip install kekkai-cli

      - name: Run ${{ matrix.scanner }}
        run: kekkai scan --scanners ${{ matrix.scanner }} --ci

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.scanner }}-results
          path: ~/.kekkai/runs/
```

---

## GitLab CI

### Basic Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - security

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

security-scan:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install kekkai-cli
  script:
    - kekkai scan --ci --fail-on critical,high
  artifacts:
    when: always
    paths:
      - ~/.kekkai/runs/
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### With Docker-in-Docker

```yaml
# .gitlab-ci.yml
security-scan:
  stage: security
  image: python:3.12
  services:
    - docker:24-dind
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - pip install kekkai-cli
  script:
    - kekkai scan --ci --fail-on critical,high --output policy-result.json
  artifacts:
    when: always
    paths:
      - policy-result.json
    reports:
      dotenv: policy-result.json
```

### Merge Request Comments

```yaml
# .gitlab-ci.yml
security-scan-mr:
  stage: security
  image: python:3.12
  before_script:
    - pip install kekkai-cli
  script:
    - |
      kekkai scan --ci \
        --fail-on critical,high \
        --output policy-result.json
    - |
      # Post comment to MR (requires GITLAB_TOKEN with api scope)
      if [ -f policy-result.json ]; then
        curl --request POST \
          --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
          --form "body=$(cat policy-result.json | jq -r '.summary')" \
          "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## CircleCI

### Basic Configuration

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - setup_remote_docker
      - run:
          name: Install Kekkai
          command: pip install kekkai-cli
      - run:
          name: Run Security Scan
          command: kekkai scan --ci --fail-on critical,high
      - store_artifacts:
          path: ~/.kekkai/runs
          destination: security-results

workflows:
  security:
    jobs:
      - security-scan:
          filters:
            branches:
              only:
                - main
                - develop
```

### With Policy Output

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - setup_remote_docker
      - run:
          name: Install Kekkai
          command: pip install kekkai-cli
      - run:
          name: Run Security Scan
          command: |
            kekkai scan --ci \
              --fail-on critical,high \
              --output /tmp/policy-result.json || true
      - run:
          name: Check Results
          command: |
            if [ -f /tmp/policy-result.json ]; then
              cat /tmp/policy-result.json
              exit_code=$(jq -r '.exit_code' /tmp/policy-result.json)
              exit $exit_code
            fi
      - store_artifacts:
          path: /tmp/policy-result.json
          destination: policy-result.json

workflows:
  security:
    jobs:
      - security-scan
```

---

## Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: pip install kekkai-cli
    displayName: 'Install Kekkai'

  - script: kekkai scan --ci --fail-on critical,high --output $(Build.ArtifactStagingDirectory)/policy-result.json
    displayName: 'Run Security Scan'
    continueOnError: true

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)/policy-result.json
      artifactName: security-results
    condition: always()
```

---

## Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent {
        docker {
            image 'python:3.12'
        }
    }

    stages {
        stage('Install') {
            steps {
                sh 'pip install kekkai-cli'
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    kekkai scan --ci \
                        --fail-on critical,high \
                        --output policy-result.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'policy-result.json', allowEmptyArchive: true
                    archiveArtifacts artifacts: '~/.kekkai/runs/**/*', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        failure {
            echo 'Security scan failed - check policy-result.json'
        }
    }
}
```

---

## Docker-Based Scanning

For environments without Python, use the Docker wrapper:

```yaml
# GitHub Actions with Docker
- name: Run Security Scan (Docker)
  run: |
    docker run --rm \
      -v "${{ github.workspace }}:/repo:ro" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      kademoslabs/kekkai:latest \
      scan --repo /repo --ci --fail-on critical,high
```

---

## Policy Configuration

### Strict Policy (Block on Any Finding)

```bash
kekkai scan --ci --fail-on critical,high,medium,low
```

### Lenient Policy (Block on Critical Only)

```bash
kekkai scan --ci --fail-on critical
```

### Threshold-Based Policy

Create a config file with thresholds:

```toml
# .kekkai.toml
[policy]
fail_on_critical = true
fail_on_high = true
fail_on_medium = false
max_critical = 0
max_high = 5
max_medium = 20
max_total = 50
```

```bash
kekkai scan --ci --config .kekkai.toml
```

---

## Best Practices

1. **Start lenient, tighten over time** - Begin with `--fail-on critical` and gradually add `high`, `medium`

2. **Use PR comments for visibility** - Developers see findings in context

3. **Cache scan results** - Store artifacts for debugging and audit trails

4. **Run scanners in parallel** - Use matrix strategies for faster pipelines

5. **Pin tool versions** - Use specific Kekkai versions in CI for reproducibility:
   ```bash
   pip install kekkai-cli==1.2.3
   ```

6. **Secure tokens** - Use repository secrets, never hardcode tokens

7. **Handle failures gracefully** - Use `continue-on-error` with manual result checking

---

## Troubleshooting CI

### Docker Not Available

Ensure Docker is available in your CI environment:
- GitHub Actions: Use `ubuntu-latest` runner
- GitLab CI: Add `docker:dind` service
- CircleCI: Use `setup_remote_docker`

### Permission Denied

Check that the CI user has access to:
- Docker socket (`/var/run/docker.sock`)
- Repository files (read access)
- Output directories (write access)

### Timeout Issues

Increase timeout for large repositories:
```bash
kekkai scan --ci --timeout 1800  # 30 minutes
```

Or set in config:
```toml
timeout_seconds = 1800
```

---

## See Also

- [CLI Reference](cli-reference.md) - All command options
- [Configuration Guide](../config/configuration.md) - Config file format
- [Troubleshooting](../troubleshooting/troubleshooting.md) - Common issues
- [CI Mode Details](ci-mode.md) - In-depth CI mode documentation
