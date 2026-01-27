SHELL := /bin/bash
PY := python3

.PHONY: setup fmt lint test unit integration regression sec ci ci-quick build sbom release clean pipx-test docker-image docker-test brew-test native-test windows-unit windows-integration windows-test slsa-test slsa-verify

setup:
	python3 -m pip install -U pip wheel
	pip install -r requirements/dev.txt

fmt: ## Format
	ruff format .

lint: ## Lint + types
	ruff check .
	mypy --explicit-package-bases --namespace-packages src

unit: ## Unit tests
	pytest -m "not integration and not e2e and not regression" --cov=src --cov-report=term-missing

integration: ## Integration tests
	pytest -m "integration" --cov=src --cov-append

regression: ## Regression tests
	pytest -m "regression" --cov=src --cov-append

sec:
	bandit -q -r src -s B404,B603,B105,B310 || bandit -q -r src --skip B404,B603,B105,B310
	pip-audit -r requirements/dev.txt || true
	pip-audit --skip-editable || true

collect:
	pytest --collect-only -m "integration" -q
	pytest --collect-only -m "regression" -q

test-ci: ## Test CI/CD automation utilities
	pytest tests/ci -v --cov=src/kekkai_core/ci --cov-report=term-missing

validate-workflows: ## Validate GitHub Actions workflow syntax
	@echo "Validating GitHub Actions workflows..."
	@for file in .github/workflows/*.yml .github/workflows/*.yaml; do \
		if [ -f "$$file" ]; then \
			echo "Checking $$file..."; \
			python3 -c "import yaml; yaml.safe_load(open('$$file'))" && echo "  ✅ Valid YAML" || exit 1; \
		fi \
	done
	@echo "✅ All workflows valid"

ci-quick: fmt lint unit sec

ci: fmt lint collect test-ci unit integration regression sec

build: ## Build Python wheel and sdist
	$(PY) -m pip install -q build
	$(PY) -m build

sbom: ## Generate Software Bill of Materials
	@echo "Generating SBOM..."
	@mkdir -p dist
	pip freeze --exclude-editable > dist/requirements-frozen.txt
	@echo "SBOM written to dist/requirements-frozen.txt"

release: build sbom ## Build release artifacts
	@echo "Release artifacts in dist/"
	ls -la dist/

pipx-test: ## Validate pipx install works in isolation
	python3 -m pip install -q -U pipx
	pipx install . --force
	pipx run kekkai --version
	pipx run kekkai --help
	pipx uninstall kekkai

docker-image: ## Build docker image for magic alias usage
	docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .

docker-test: ## Test Docker wrapper
	chmod +x scripts/kekkai-docker
	./scripts/kekkai-docker --version
	./scripts/kekkai-docker --help

docker-scan: ## Scan Docker image for vulnerabilities
	@if ! command -v trivy >/dev/null 2>&1; then \
		echo "Trivy not installed. Install: https://aquasecurity.github.io/trivy/"; \
		exit 1; \
	fi
	docker build -t kademoslabs/kekkai:scan -f apps/kekkai/Dockerfile .
	trivy image --severity CRITICAL,HIGH,MEDIUM,LOW kademoslabs/kekkai:scan

docker-sign: ## Sign Docker image with Cosign
	@if ! command -v cosign >/dev/null 2>&1; then \
		echo "Cosign not installed. Install: https://docs.sigstore.dev/cosign/installation/"; \
		exit 1; \
	fi
	@echo "Signing image kademoslabs/kekkai:latest..."
	@if [ -z "$$COSIGN_PRIVATE_KEY" ]; then \
		echo "COSIGN_PRIVATE_KEY not set. Using keyless signing..."; \
		cosign sign --yes kademoslabs/kekkai:latest; \
	else \
		echo "$$COSIGN_PRIVATE_KEY" > /tmp/cosign.key; \
		cosign sign --yes --key /tmp/cosign.key kademoslabs/kekkai:latest; \
		rm -f /tmp/cosign.key; \
	fi

docker-verify: ## Verify Docker image signature
	@if ! command -v cosign >/dev/null 2>&1; then \
		echo "Cosign not installed. Install: https://docs.sigstore.dev/cosign/installation/"; \
		exit 1; \
	fi
	@echo "Verifying signature for kademoslabs/kekkai:latest..."
	@if [ -z "$$COSIGN_PUBLIC_KEY" ]; then \
		echo "COSIGN_PUBLIC_KEY not set. Using keyless verification..."; \
		cosign verify kademoslabs/kekkai:latest; \
	else \
		echo "$$COSIGN_PUBLIC_KEY" > /tmp/cosign.pub; \
		cosign verify --key /tmp/cosign.pub kademoslabs/kekkai:latest; \
		rm -f /tmp/cosign.pub; \
	fi

docker-sbom: ## Generate SBOM for Docker image
	@if ! command -v trivy >/dev/null 2>&1; then \
		echo "Trivy not installed. Install: https://aquasecurity.github.io/trivy/"; \
		exit 1; \
	fi
	@mkdir -p dist
	docker build -t kademoslabs/kekkai:sbom -f apps/kekkai/Dockerfile .
	trivy image --format spdx-json --output dist/sbom.spdx.json kademoslabs/kekkai:sbom
	@echo "SBOM generated: dist/sbom.spdx.json"

docker-security-test: ## Run Docker security tests
	pytest tests/docker -v --cov=src/kekkai_core/docker --cov-report=term-missing

cosign-keygen: ## Generate Cosign keypair for image signing
	@echo "🔐 Generating Cosign keypair..."
	@if ! command -v cosign >/dev/null 2>&1; then \
		echo "❌ Cosign not installed. Install: https://docs.sigstore.dev/cosign/installation/"; \
		exit 1; \
	fi
	@mkdir -p .cosign-keys
	@echo "⚠️  You will be prompted to enter a password for the private key"
	@cd .cosign-keys && cosign generate-key-pair
	@echo "✅ Keys generated in .cosign-keys/"
	@echo ""
	@echo "📋 Next steps:"
	@echo "  1. Add to GitHub Secrets:"
	@echo "     - COSIGN_PRIVATE_KEY (content of .cosign-keys/cosign.key)"
	@echo "     - COSIGN_PASSWORD (password you just entered)"
	@echo "  2. Backup .cosign-keys/cosign.pub for verification"
	@echo "  3. Securely delete local keys after upload:"
	@echo "     shred -vfz -n 10 .cosign-keys/cosign.key"
	@echo ""
	@echo "⚠️  NEVER commit .cosign-keys/ to git (already in .gitignore)"
	@echo ""
	@echo "📖 See docs/security/cosign-key-management.md for details"

cosign-verify-setup: ## Verify Cosign key setup in environment
	@echo "🔍 Verifying Cosign configuration..."
	@if ! command -v cosign >/dev/null 2>&1; then \
		echo "❌ Cosign not installed"; \
		exit 1; \
	fi
	@if [ -z "$$COSIGN_PRIVATE_KEY" ]; then \
		echo "❌ COSIGN_PRIVATE_KEY not set in environment"; \
		echo "💡 For GitHub Actions: Set as repository secret"; \
		echo "💡 For local testing: export COSIGN_PRIVATE_KEY=\"\$$(cat .cosign-keys/cosign.key)\""; \
		exit 1; \
	fi
	@if [ -z "$$COSIGN_PASSWORD" ]; then \
		echo "❌ COSIGN_PASSWORD not set in environment"; \
		exit 1; \
	fi
	@echo "✅ Cosign environment variables configured"
	@echo "🔑 Private key length: $$(echo "$$COSIGN_PRIVATE_KEY" | wc -c) bytes"

brew-test: ## Smoke test formula locally (macOS only)
	@if command -v brew >/dev/null 2>&1; then \
		echo "Testing Homebrew installation..."; \
		brew tap kademoslabs/tap || true; \
		brew install kademoslabs/tap/kekkai || brew upgrade kademoslabs/tap/kekkai; \
		kekkai --version; \
	else \
		echo "Homebrew not installed, skipping brew-test"; \
	fi

native-test: ## Test native mode scanner backends
	pytest tests/test_scanner_backends.py tests/test_scanner_native.py -v
	pytest -m "integration" tests/integration/test_kekkai_native_mode.py -v
	pytest -m "regression" tests/regression/test_native_command_manifest.py -v

installer-test: ## Test tool installer module
	pytest tests/test_installer_*.py -v --cov=src/kekkai/installer --cov-report=term-missing
	pytest -m "integration" tests/integration/test_installer_e2e.py -v
	pytest -m "regression" tests/regression/test_installer_backends.py -v

slsa-test: ## Test SLSA provenance verification module
	pytest tests/test_slsa_provenance.py -v --cov=src/kekkai_core/slsa --cov-report=term-missing
	pytest -m "integration" tests/integration/test_slsa_verification.py -v
	pytest -m "regression" tests/regression/test_slsa_backwards_compat.py -v

github-test: ## Test GitHub PR commenter module
	pytest tests/test_github_commenter_*.py -v --cov=src/kekkai/github --cov-report=term-missing
	pytest -m "integration" tests/integration/test_github_pr_api.py -v
	pytest -m "regression" tests/regression/test_github_commenter_json_compat.py -v

slsa-verify: ## Verify SLSA provenance for a release artifact (usage: make slsa-verify ARTIFACT=dist/kekkai-1.0.0.whl)
	@if [ -z "$(ARTIFACT)" ]; then \
		echo "Usage: make slsa-verify ARTIFACT=<path-to-artifact>"; \
		exit 1; \
	fi
	@if ! command -v slsa-verifier >/dev/null 2>&1; then \
		echo "slsa-verifier not installed. Install: https://github.com/slsa-framework/slsa-verifier"; \
		exit 1; \
	fi
	slsa-verifier verify-artifact "$(ARTIFACT)" \
		--provenance-path "$(ARTIFACT).intoto.jsonl" \
		--source-uri github.com/kademoslabs/kekkai

triage-test: ## Test triage TUI module
	pytest tests/test_triage_*.py -v --cov=src/kekkai/triage --cov-report=term-missing --cov-fail-under=0
	pytest -m "integration" tests/integration/test_triage_workflow.py -v
	pytest -m "regression" tests/regression/test_triage_backwards_compat.py -v

windows-unit: ## Windows unit tests
	pytest tests/windows -v --cov=src/kekkai_core/windows --cov-report=term-missing

windows-integration: ## Windows integration tests
	pytest tests/integration/test_scoop_*.py tests/integration/test_windows_*.py tests/integration/test_chocolatey_*.py -v

windows-test: windows-unit windows-integration ## All Windows tests
	@echo "✅ All Windows tests passed"

chocolatey-unit: ## Chocolatey unit tests
	pytest tests/windows/test_chocolatey_*.py -v --cov=src/kekkai_core/windows --cov-append --cov-report=term-missing

chocolatey-integration: ## Chocolatey integration tests
	pytest tests/integration/test_chocolatey_*.py -v

chocolatey-test: chocolatey-unit chocolatey-integration ## All Chocolatey tests
	@echo "✅ All Chocolatey tests passed"

test-matrix: ## Run full cross-platform test suite
	@echo "Running cross-platform test matrix..."
	pytest tests/ci/test_cross_platform.py -v
	pytest tests/integration/test_platform_parity.py -v
	pytest tests/regression/test_platform_regressions.py -v
	@echo "✅ Cross-platform tests completed"

benchmark: ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	pytest tests/ci/test_benchmarks.py -v -m "not integration"
	@echo "✅ Benchmarks completed"
	@echo "Results stored in .benchmarks/"

benchmark-full: ## Run all benchmarks including integration
	@echo "Running all performance benchmarks..."
	pytest tests/ci/test_benchmarks.py -v
	@echo "✅ All benchmarks completed"

coverage-report: ## Generate comprehensive coverage report
	@echo "Generating coverage report..."
	pytest --cov=src --cov-report=html --cov-report=term-missing
	@echo "✅ Coverage report generated in htmlcov/"

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml dist build *.egg-info src/*.egg-info .benchmarks htmlcov
