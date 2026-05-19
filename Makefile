# auth-scan developer Makefile.
#
# Everything goes through `uv run` so contributors don't need to remember
# to activate the venv. `make sync` materialises the lockfile-pinned dev
# environment in `.venv/`.

UV ?= uv
PY_SRCS := src tests

.PHONY: help sync test test-cov integration lint format format-check typecheck ci clean \
        scan-crapi-setup scan-crapi-up scan-crapi scan-crapi-down

# Where we cache external integration-target checkouts. Override with
# AUTHSCAN_TARGETS_DIR=... to put them somewhere else.
AUTHSCAN_TARGETS_DIR ?= $(HOME)/.cache/authscan-targets
CRAPI_REPO := https://github.com/OWASP/crAPI.git
CRAPI_REF ?= main
CRAPI_DIR := $(AUTHSCAN_TARGETS_DIR)/crAPI
CRAPI_URL ?= http://localhost:8888

help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

sync:  ## Install/refresh the dev environment from uv.lock
	$(UV) sync --group dev

test:  ## Run the test suite
	$(UV) run pytest

test-cov:  ## Run tests with coverage
	$(UV) run pytest --cov=src/auth_scan --cov-report=term-missing

integration:  ## Run the slow end-to-end integration suite against vuln_app
	$(UV) run pytest -m slow tests/integration/

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

# ── External integration targets ────────────────────────────────
#
# These are opt-in helpers for ad-hoc validation against larger
# deliberately-vulnerable apps. They're NOT wired into CI; you only run
# them locally when cutting a release or chasing a regression.
# See docs/integration-targets.md.

scan-crapi-setup:  ## Clone OWASP crAPI into $(AUTHSCAN_TARGETS_DIR)
	@mkdir -p $(AUTHSCAN_TARGETS_DIR)
	@if [ ! -d "$(CRAPI_DIR)/.git" ]; then \
		echo "Cloning OWASP crAPI -> $(CRAPI_DIR)"; \
		git clone --depth 1 --branch $(CRAPI_REF) $(CRAPI_REPO) $(CRAPI_DIR); \
	else \
		echo "crAPI already present at $(CRAPI_DIR); pulling latest"; \
		git -C $(CRAPI_DIR) fetch --depth 1 origin $(CRAPI_REF) && \
		git -C $(CRAPI_DIR) reset --hard origin/$(CRAPI_REF); \
	fi

scan-crapi-up: scan-crapi-setup  ## Bring crAPI up via docker-compose
	@command -v docker >/dev/null || { echo "docker not found"; exit 1; }
	cd $(CRAPI_DIR)/deploy/docker && docker compose -f docker-compose.yml --profile prod up -d
	@echo "crAPI starting — ~2 min on a warm cache. Watch with: docker compose -f $(CRAPI_DIR)/deploy/docker/docker-compose.yml logs -f"

scan-crapi:  ## Scan a running crAPI instance and write an HTML report
	$(UV) run auth-scan $(CRAPI_URL) \
		--modules all \
		--allow-private-redirects \
		--output html \
		--output-file /tmp/authscan-crapi.html
	@echo "Report: /tmp/authscan-crapi.html"

scan-crapi-down:  ## Stop the crAPI stack
	cd $(CRAPI_DIR)/deploy/docker && docker compose -f docker-compose.yml down -v
