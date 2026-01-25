SHELL := /bin/bash
PY := python3

.PHONY: setup fmt lint test unit integration regression sec ci ci-quick build sbom release clean pipx-test docker-image docker-test brew-test

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

ci-quick: fmt lint unit sec

ci: fmt lint collect unit integration regression sec

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

brew-test: ## Smoke test formula locally (macOS only)
	@if command -v brew >/dev/null 2>&1; then \
		echo "Testing Homebrew installation..."; \
		brew tap kademoslabs/tap || true; \
		brew install kademoslabs/tap/kekkai || brew upgrade kademoslabs/tap/kekkai; \
		kekkai --version; \
	else \
		echo "Homebrew not installed, skipping brew-test"; \
	fi

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml dist build *.egg-info src/*.egg-info
