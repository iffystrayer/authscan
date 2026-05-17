# auth-scan

**CLI web authentication security assessment tool.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

auth-scan is a CLI-first, protocol-agnostic authentication security scanner that detects common web authentication vulnerabilities. It supports JWT analysis, session management testing, brute force/dictionary attacks, security header checks, and more.

## Quick Start

```bash
# Install
pip install auth-scan

# Run a quick scan
auth-scan https://example.com --quick

# Full scan with all modules
auth-scan https://example.com

# JSON output for CI/CD
auth-scan https://example.com --output json --output-file results.json
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
  --modules TEXT...        Modules to run: probe, jwt, session, brute (default: all)
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
  --init                   Generate default config file
  --version                Show version
  --help                   Show this help
```

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

```bash
# Clone and install in dev mode
git clone https://github.com/auth-scan/auth-scan
cd auth-scan
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
ruff format --check .

# Type check
mypy src/
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP ASVS](https://github.com/OWASP/ASVS)
- [JWT Best Practices (RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
