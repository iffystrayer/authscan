# auth-scan developer Makefile.
#
# Everything goes through `uv run` so contributors don't need to remember
# to activate the venv. `make sync` materialises the lockfile-pinned dev
# environment in `.venv/`.

UV ?= uv
PY_SRCS := src tests

.PHONY: help sync test test-cov lint format format-check typecheck ci clean

help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

sync:  ## Install/refresh the dev environment from uv.lock
	$(UV) sync --group dev

test:  ## Run the test suite
	$(UV) run pytest

test-cov:  ## Run tests with coverage
	$(UV) run pytest --cov=src/auth_scan --cov-report=term-missing

lint:  ## Lint with ruff (no formatting changes)
	$(UV) run ruff check $(PY_SRCS)

format:  ## Auto-format with ruff
	$(UV) run ruff format $(PY_SRCS)
	$(UV) run ruff check $(PY_SRCS) --fix

format-check:  ## Verify formatting without writing
	$(UV) run ruff format --check $(PY_SRCS)

typecheck:  ## Type-check with mypy (non-blocking for now; see pyproject.toml)
	$(UV) run mypy src/ || true

ci:  ## Run every quality gate (mirrors the GitHub Actions workflow)
	$(UV) run ruff format --check $(PY_SRCS)
	$(UV) run ruff check $(PY_SRCS)
	$(UV) run pytest
	$(UV) run mypy src/ || true

clean:  ## Remove build artifacts and caches
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
