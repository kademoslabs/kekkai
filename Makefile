SHELL := /bin/bash
PY := python3

.PHONY: setup fmt lint test unit integration regression sec ci ci-quick clean

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
	bandit -q -r src
	pip-audit -r requirements/dev.txt || true
	pip-audit --skip-editable || true

collect:
	pytest --collect-only -m "integration" -q
	pytest --collect-only -m "regression" -q

ci-quick: fmt lint unit sec

ci: fmt lint collect unit integration regression sec

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml
