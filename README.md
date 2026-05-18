# auth-scan

**CLI web authentication security assessment tool.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

auth-scan is a CLI-first, protocol-agnostic authentication security scanner that detects common web authentication vulnerabilities. It supports JWT analysis, session management testing, brute force/dictionary attacks, security header checks, and more.

## Quick Start

```bash
# Install (uv recommended)
uv tool install auth-scan
# or: pip install auth-scan

# Run a quick scan
auth-scan https://example.com --quick

# Full scan with every registered module (built-ins + plugins)
auth-scan https://example.com --modules all

# JSON output to a specific file for CI/CD
auth-scan https://example.com --output json --output-file results.json

# Stream a single-format report to stdout (useful for pipes)
auth-scan https://example.com --output sarif --output-file -
```

## Features

- **Probe Phase**: Discover security headers, cookies, forms, TLS configuration, and JWT tokens
- **JWT Analyzer**: Detect alg=none, key confusion (RS256→HS256), expired tokens, sensitive data in payloads
- **Session Tests**: Cookie attribute analysis (HttpOnly, Secure, SameSite), session fixation, session invalidation
- **Brute Force**: Default credential testing, login form discovery, rate limit detection, user enumeration
- **Multi-format output**: Terminal (Rich), JSON, Markdown, HTML, PDF, SARIF
- **Configuration**: YAML config, profiles, environment variable overrides
- **CI/CD ready**: Exit codes based on finding severity, machine-readable output

## Usage

```
auth-scan <TARGET> [OPTIONS]

TARGET is the URL to scan (e.g., https://example.com).

Options:
  --modules TEXT...        Modules to run: probe, jwt, session, brute,
                           oauth, mfa, websocket, api_key, or 'all'
                           (expands to every registered module).
  --output, -o FORMAT...   Output: terminal, json, markdown, html, pdf, sarif
  --config, -c PATH        YAML config file
  --profile, -P NAME       Named profile from config
  --quick                  Quick scan (probe + headers only)
  --agentic                Enable adaptive scanning
  --rate-limit N           Requests per second (default: 10)
  --timeout N              Request timeout in seconds (default: 30)
  --proxy URL              Proxy URL
  --cookie KEY=VALUE       Initial cookie (repeatable)
  --header KEY=VALUE       Custom header (repeatable)
  --wordlist, -w PATH      Password wordlist
  --user-wordlist PATH     Username wordlist
  --scope DOMAIN           Allowed domain (repeatable)
  --verbose, -v            Increase verbosity
  --quiet, -q              Minimal output
  --no-color               Disable colored output
  --no-redact              Show secrets in output (DANGEROUS)
  --output-dir PATH        Directory for auto-named report files
                           (default: ./scan-results)
  --output-file PATH       Write a single report to this exact path
                           (or '-' for stdout). Requires exactly one
                           non-terminal --output format.
  --init                   Generate default config file
  --version                Show version
  --help                   Show this help
```

### Reporters

| `--output` value | Extension | Single-file via `--output-file` | Notes |
|---|---|---|---|
| `terminal` | (stdout)      | n/a | Default; Rich-formatted summary table. |
| `json`     | `.json`       | ✅  | Machine-readable. Redaction by default. |
| `markdown` | `.md`         | ✅  | Consultant-style write-up. |
| `html`     | `.html`       | ✅  | Standalone HTML (embedded CSS). |
| `pdf`      | `.pdf`        | ✅  | Requires `auth-scan[pdf]` extra (WeasyPrint). |
| `sarif`    | `.sarif.json` | ✅  | GitHub Code Scanning / SonarQube compatible. |

Use `--output-file -` with a single non-terminal format to pipe to stdout.

## Configuration

Generate a default config:

```bash
auth-scan --init
# Creates auth-scan-config.yml
```

Use config and profiles:

```bash
auth-scan https://example.com --config auth-scan-config.yml --profile ci-pipeline
```

Environment variable overrides (prefix `AUTH_SCAN_`):

```bash
AUTH_SCAN_RATE_LIMIT=5 AUTH_SCAN_PROXY=http://127.0.0.1:8080 auth-scan https://example.com
```

## Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | No CRITICAL or HIGH findings |
| 1 | LOW findings only |
| 2 | MEDIUM findings present |
| 3 | HIGH findings present |
| 4 | CRITICAL findings present |
| 255 | Fatal error |

## Development

We use [uv](https://docs.astral.sh/uv/) for reproducible dev environments. The lockfile `uv.lock` is committed; `uv sync` will materialise the exact resolved set every time. A `Makefile` wraps the common workflows.

```bash
# Clone and install (creates .venv, installs the project + dev group)
git clone https://github.com/auth-scan/auth-scan
cd auth-scan
make sync   # or: uv sync --group dev

# Common targets
make test         # uv run pytest
make lint         # uv run ruff check src tests
make format       # uv run ruff format + ruff check --fix
make format-check # verify formatting without writing
make typecheck    # uv run mypy src/   (advisory — see below)
make ci           # everything CI runs: format-check + lint + tests + mypy

# Run the CLI itself
uv run auth-scan https://example.com
```

### Quality gates

CI on every push and PR runs against Python 3.10, 3.11, and 3.12 and enforces:

- `ruff format --check src tests`
- `ruff check src tests` (rules: E, F, W, I, N, UP, B, C4; line length 110)
- `pytest -q`
- `mypy src/` — **advisory** (logs but does not fail CI) until the strict baseline is restored. A handful of modules (`auth_scan.attacks.base`, `auth_scan.core.config`, `auth_scan.core.exceptions`) already run with `disallow_untyped_defs=true`; the rest will be tightened module-by-module.

If you prefer plain pip, `pip install -e ".[dev]"` still works — uv just makes the bootstrap faster and pinned.

## License

MIT License. See [LICENSE](LICENSE) for details.

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP ASVS](https://github.com/OWASP/ASVS)
- [JWT Best Practices (RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
