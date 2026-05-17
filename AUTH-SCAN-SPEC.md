# AUTH-SCAN — Software Engineering Specification

**Version:** 1.0.0
**Status:** Draft
**Last Updated:** 2026-05-16
**Author:** auth-scan Engineering Team

---

## Table of Contents

1. [Vision & Scope](#1-vision--scope)
2. [Functional Requirements](#2-functional-requirements)
3. [Non-Functional Requirements](#3-non-functional-requirements)
4. [Architecture](#4-architecture)
5. [Data Schemas](#5-data-schemas)
6. [UX Specification](#6-ux-specification)
7. [Testing Strategy](#7-testing-strategy)
8. [Roadmap & Phases](#8-roadmap--phases)

---

## 1. Vision & Scope

### Problem Statement

Web authentication is the most targeted attack surface in modern applications. The OWASP Top 10:2025 highlights broken authentication and identification failures as a persistent, critical risk category. Despite this, existing security tools remain fragmented across concern boundaries:

- **Burp Suite Pro** captures traffic and intercepts requests but requires manual configuration per auth flow, is GUI-dependent, and carries a $449/year license. It has no native adaptive scanning logic for authentication chaining.
- **OWASP ZAP** provides automated scanning but its authentication handling is limited to pre-configured scripts; it cannot dynamically discover and adapt to novel auth mechanisms.
- **nuclei** offers extensible template-based scanning but templates are static—they cannot chain findings, adapt parameters based on prior responses, or maintain cross-request state.
- **hashcat / John the Ripper** crack passwords offline but have no HTTP-level awareness of auth flows, lockout policies, or session state.
- **Custom Scripts** (Python/Bash) built ad‑hoc per engagement are fragile, non-reusable, and lack standardized reporting.

The gap is clear: there is no **CLI‑first, protocol‑agnostic authentication security scanner with an adaptive, state‑aware decision engine** that can be dropped into CI/CD pipelines, used by pentesters on engagements, and extended by security researchers.

**auth‑scan fills this gap.**

### Target Users

| Persona | Priority | Description | Core Need |
|---------|----------|-------------|-----------|
| **Penetration Tester** | P1 | Deep custom auth flow analysis, exploit chaining, producing evidence for client reports | Flexible, configurable modules that chain findings and produce consultant‑grade output |
| **Bug Bounty Hunter** | P1 | Fast reconnaissance across many targets, confidence scoring, machine‑readable output for automation | Speed, JSON output, deduplication of findings, low false‑positive rate |
| **DevSecOps / Internal Security Engineer** | P2 | CI/CD gating, regression detection, OWASP ASVS compliance auditing | Exit codes for pipeline decisions, SARIF output, consistent and deterministic results |
| **Developer** | P2 | Pre‑commit sanity checks, learning about auth vulnerabilities during development | Simple defaults, fast execution (`--quick`), educational remediation text |
| **Security Researcher** | P3 | Extending modules, contributing protocol adapters, building plugins | Clean plugin contract, entry‑point discovery, well‑documented internals |

### Explicit Out‑of‑Scope

The following are explicitly ***not*** in scope for auth‑scan. Separate tools should be used for these concerns:

- **WAF evasion** — auth‑scan does not attempt to bypass Web Application Firewalls, IP blocklists, or bot detection.
- **General vulnerability scanning** — SQL injection, XSS, SSRF, command injection, path traversal, and other non‑auth CWE categories are out of scope.
- **Network‑layer attacks** — ARP spoofing, DNS poisoning, TCP session hijacking, and other L3/L4 attacks.
- **Physical / social engineering** — Phishing simulation, USB drops, tailgating.
- **Autonomous post‑auth exploitation** — auth‑scan stops at identifying auth weaknesses; it does not autonomously pivot to RCE, data exfiltration, or lateral movement.

### Comparison Table

| Dimension | Burp Suite Pro | OWASP ZAP | nuclei | Custom Scripts | **auth‑scan** |
|-----------|---------------|-----------|--------|----------------|---------------|
| **Auth‑specific depth** | Medium (via extensions) | Low–Medium | Low (static templates) | Varies | **High** — purpose‑built auth modules |
| **Adaptive decision‑making** | Manual only | Scripted only | None | None | **OODA‑loop agentic engine** |
| **Stateful session tracking** | Manual (repeater) | Partial | None | Ad‑hoc | **First‑class session store** |
| **JWT analysis** | Via extension | Via add‑on | Templates only | Ad‑hoc | **Native: alg=none, key confusion, expiry, claims** |
| **OAuth 2.0 / OIDC testing** | Manual | Via add‑on | Templates only | Manual scripts | **Native module (Phase 2)** |
| **CLI / pipeline‑native** | ✗ | ✓ (headless) | ✓ | ✓ | **✓ — primary interface** |
| **Multi‑protocol** | HTTP only | HTTP only | Network + HTTP | Varies | **HTTP, WebSocket (planned), API** |
| **Report generation** | HTML, XML | HTML, XML, JSON, MD | JSON, Markdown | None | **Terminal, JSON, Markdown, HTML, PDF, SARIF** |
| **Cost** | $449/year | Free | Free | Free (labor) | **Free & Open Source** |
| **Plugin system** | Extensions (Java) | Add‑ons (Java) | Templates (YAML) | None | **entry‑points (Python setuptools)** |

### Guiding Principles

1. **CLI‑first, always.** Every feature is accessible from the command line. GUIs (TUI, web dashboard) are wrappers over the same core library, never the primary interface.
2. **Failing closed.** When uncertain, report a finding rather than silently skipping. Ambiguous results are flagged with low confidence rather than suppressed.
3. **Ethical by default.** Mandatory rate‑limiting (minimum 1 req/s, default 10 req/s), scope enforcement that cannot be fully disabled, and a prominent notice on first run about responsible use.
4. **Zero credential persistence.** Credentials, tokens, and session IDs are never written to disk unless `--save-config` is explicitly passed with a clear warning. All internal caches reside in memory only.
5. **Protocol‑agnostic core.** The engine, reporter, session store, and scheduler know nothing about HTTP. Protocol adapters translate domain‑specific concerns (cookies, headers, status codes) into the core model.

---

## 2. Functional Requirements

### 2.1 Scan Lifecycle

| ID | Requirement | Priority |
|----|-------------|----------|
| **FR‑SL‑001** | The CLI SHALL accept a target URL as the only required positional argument. | P0 |
| **FR‑SL‑002** | The probe phase SHALL fetch the target root (`GET /`), record response status code, all response headers, `Set‑Cookie` values, and discovered HTML forms (action, method, input fields). | P0 |
| **FR‑SL‑003** | Probe SHALL detect whether a TLS connection was established. If the target was provided as `http://`, the tool SHALL flag it and recommend HTTPS migration. If HTTPS redirects to HTTP, a HIGH‑severity finding SHALL be raised. | P0 |
| **FR‑SL‑004** | Probe SHALL detect missing security headers: `Strict‑Transport‑Security`, `X‑Content‑Type‑Options`, `X‑Frame‑Options`, `Content‑Security‑Policy`, `Referrer‑Policy`, and `Permissions‑Policy`. Each missing header SHALL produce a LOW or MEDIUM finding with remediation text. | P0 |
| **FR‑SL‑005** | Attack modules SHALL run sequentially in a specified or default order after the probe phase completes. | P0 |
| **FR‑SL‑006** | Each attack module SHALL receive the accumulated `ScanReport` (all prior findings, session state, metadata) as input. | P0 |
| **FR‑SL‑007** | When `--agentic` is enabled, the engine MAY reorder, re‑prioritize, or skip modules based on probe findings and the attack surface model. | P1 |
| **FR‑SL‑008** | The scan SHALL accept a `--config` flag pointing to a YAML configuration file. CLI flags override config file values. | P0 |
| **FR‑SL‑009** | The scan SHALL accept a `--resume SCAN_ID` flag to continue from a previously saved scan state (JSON checkpoint file). | P1 |
| **FR‑SL‑010** | The scan SHALL produce a non‑zero exit code when CRITICAL or HIGH findings exist (see exit code mapping in §6). | P0 |
| **FR‑SL‑011** | The `--quick` flag SHALL skip brute‑force, deep analysis, and any module with `priority > 50`. Only probe + header checks + static JWT decode run. | P0 |
| **FR‑SL‑012** | The `--scope` flag (repeatable) SHALL accept domain/IP allowlist entries. The engine SHALL enforce scope and refuse to follow redirects or issue requests to out‑of‑scope hosts. | P0 |
| **FR‑SL‑013** | SIGINT (Ctrl+C) SHALL trigger graceful shutdown: in‑flight requests are cancelled, partial results are saved to the checkpoint file, and the reporter outputs whatever is available. | P0 |
| **FR‑SL‑014** | `--timeout` SHALL set a global request timeout in seconds. Individual modules MAY override this via config. | P1 |
| **FR‑SL‑015** | During long‑running modules (brute‑force, deep session analysis), a progress indicator SHALL be displayed: Rich spinner with "N findings so far" updated in real time. | P1 |

### 2.2 JWT Analyzer

| ID | Requirement | Priority |
|----|-------------|----------|
| **FR‑JWT‑001** | The JWT Analyzer SHALL detect JWTs in: `Authorization: Bearer ...` headers, cookie values, response body payloads, and any `localStorage`/`sessionStorage` references found in inline JavaScript (best‑effort regex). | P0 |
| **FR‑JWT‑002** | For each detected JWT, the module SHALL decode the header and payload without cryptographic verification, reporting the signing algorithm (`alg`), key ID (`kid`), and type (`typ`). | P0 |
| **FR‑JWT‑003** | The module SHALL test the `alg=none` attack: construct a JWT with `"alg":"none"` and an empty signature, then submit it to the target. If the server accepts it, a CRITICAL finding SHALL be recorded. | P0 |
| **FR‑JWT‑004** | If the token uses RS256 (or any asymmetric algorithm), the module SHALL test key confusion: attempt HMAC‑SHA256 verification using the public key (extracted from a JWKS endpoint or embedded in the token header `jku`/`x5c`) as the HMAC secret. If the server accepts it, a CRITICAL finding SHALL be recorded. | P0 |
| **FR‑JWT‑005** | The module SHALL extract and evaluate the `exp` (expiration) claim. If the token is expired but still accepted by the server, a HIGH finding SHALL be recorded. If the token lifetime exceeds 24 hours, a MEDIUM finding SHALL advise shorter lifetimes. | P0 |
| **FR‑JWT‑006** | The module SHALL evaluate the `nbf` (not‑before) claim. If a future‑dated token is accepted before the `nbf` timestamp, a MEDIUM finding SHALL be recorded. | P1 |
| **FR‑JWT‑007** | The module SHALL inspect the JWT payload for sensitive data: plaintext passwords, email addresses in `sub` when it is a PII field, internal user IDs, role assignments, or credit card numbers (regex pattern). Each instance SHALL produce a HIGH finding. | P0 |
| **FR‑JWT‑008** | If `aud` (audience) and `iss` (issuer) claims are present, the module SHALL evaluate whether the target properly validates them. A crafted token with a wrong `aud`/`iss` that is accepted SHALL produce a HIGH finding. | P1 |

### 2.3 Brute Force

| ID | Requirement | Priority |
|----|-------------|----------|
| **FR‑BF‑001** | The Brute Force module SHALL auto‑discover login forms from the probe phase metadata. It SHALL identify the form action URL, HTTP method, username field name(s), password field name(s), and any CSRF token or hidden fields that must be submitted. | P0 |
| **FR‑BF‑002** | The module SHALL accept `--wordlist` (password wordlist path) and `--username‑wordlist` (username wordlist path) flags. | P0 |
| **FR‑BF‑003** | A built‑in default wordlist of approximately 100 common passwords (`admin`, `password`, `123456`, `letmein`, etc.) SHALL be available for quick tests when no external wordlist is provided. | P0 |
| **FR‑BF‑004** | The module SHALL detect account lockout by observing: HTTP status code changes (e.g., `423 Locked`, consistent `403` after N attempts), error message pattern changes (e.g., "account locked" strings), and response timing anomalies (sudden fast responses indicating lockout). When lockout is detected, the module SHALL halt credential attempts for that account and record an INFO finding. | P1 |
| **FR‑BF‑005** | The module SHALL detect rate limiting by observing: `429 Too Many Requests` responses, increasing response latency (linear or exponential backoff), and `Retry‑After` headers. Upon detection, the module SHALL automatically throttle to the observed limit and record a MEDIUM finding. | P1 |
| **FR‑BF‑006** | The module SHALL detect user enumeration by comparing responses for valid‑looking vs. invalid‑looking usernames: different status codes, different response body lengths (±5%), different error message content, and response timing differences (>200ms). If enumeration is possible, a MEDIUM finding SHALL be recorded. | P1 |

### 2.4 Session Tests

| ID | Requirement | Priority |
|----|-------------|----------|
| **FR‑ST‑001** | The Session Tests module SHALL analyze every `Set‑Cookie` header from the probe phase and report on: `HttpOnly` presence, `Secure` presence, `SameSite` value (Strict/Lax/None), `Domain` attribute (overly broad?), `Path` attribute, and `Max‑Age`/`Expires` (session duration). Each missing or misconfigured attribute SHALL produce a finding with the appropriate severity. | P0 |
| **FR‑ST‑002** | The module SHALL test session fixation: send a known session ID to the server before authentication, then authenticate, and check whether the session ID changed. If the server accepts the pre‑authentication session ID after login, a HIGH finding SHALL be recorded. | P0 |
| **FR‑ST‑003** | The module SHALL test session invalidation: obtain an authenticated session cookie, issue a logout request, then attempt to reuse the session cookie. If the server still accepts it, a HIGH finding SHALL be recorded. | P0 |
| **FR‑ST‑004** | The module SHALL inspect all state‑changing forms (POST, PUT, DELETE with forms) discovered during probe for the absence of CSRF tokens. If no anti‑CSRF token is present, a MEDIUM finding SHALL be recorded. | P1 |
| **FR‑ST‑005** | The module SHALL test cookie scope: set a cookie on the parent domain and check whether subdomains receive it (cookie leakage), and attempt to set a cookie with a broader `Domain` attribute than the current host. Each violation SHALL produce a MEDIUM finding. | P1 |
| **FR‑ST‑006** | The module SHALL scan all anchor elements, form actions, and redirect targets in HTML responses for session IDs embedded in URL query parameters (e.g., `?sessionid=...` or `?jsessionid=...`). Each instance SHALL produce a HIGH finding. | P0 |
| **FR‑ST‑007** | The module SHALL analyze session ID entropy: measure token length, character set diversity (alphanumeric, hex, base64), and perform basic randomness checks (Shannon entropy, runs test). Low‑entropy session IDs SHALL produce a MEDIUM finding. | P1 |

### 2.5 Agentic Decision Engine

| ID | Requirement | Priority |
|----|-------------|----------|
| **FR‑AE‑001** | The agentic engine SHALL implement an OODA loop: **Observe** (collect probe/module results and HTTP response data), **Orient** (update the attack surface model with new endpoints, auth mechanisms, tokens, forms, and relationships), **Decide** (select the next module, its parameters, or conclude the scan), **Act** (execute the selected module). | P1 |
| **FR‑AE‑002** | The engine SHALL maintain an "attack surface model" — a directed graph data structure capturing: discovered endpoints (URLs), authentication mechanisms detected (JWT, cookie‑based, basic, OAuth), tokens with their properties, HTML forms, and edges representing relationships (e.g., "form POSTs to `/login`", "JWT in cookie set by `/api/auth`"). | P1 |
| **FR‑AE‑003** | Each finding SHALL carry a confidence score (float, 0.0–1.0) indicating the engine's certainty. Direct observations (e.g., missing `Secure` flag) have confidence ≥0.95. Inferred findings (e.g., "likely user enumeration") have confidence 0.5–0.8. | P1 |
| **FR‑AE‑004** | The engine SHALL chain low‑severity findings into higher‑severity exploit paths. Example: user enumeration (MEDIUM) + weak password accepted (MEDIUM) → account takeover (CRITICAL). Chained findings SHALL reference each other via `chain_parent` IDs. | P1 |
| **FR‑AE‑005** | The engine SHALL de‑duplicate findings across modules. If the same vulnerability is discovered via different paths (e.g., weak cookie flags found by both probe and session module), only one finding SHALL be emitted with both evidence sources attached. | P1 |
| **FR‑AE‑006** | After scan completion, the engine SHALL generate a "next steps" recommendation list: prioritized actions (e.g., "1. Fix JWT alg=none [CRITICAL], 2. Add HttpOnly to session cookie [HIGH]") based on finding severity and chaining potential. | P1 |
| **FR‑AE‑007** | The `--agentic` flag SHALL enable adaptive mode. When not set (default), the engine runs all specified modules in their default order deterministically. | P1 |
| **FR‑AE‑008** | In agentic mode, the engine SHALL stop when confidence in the attack surface model exceeds a configurable threshold (`--confidence‑threshold`, default 0.9), or when all available modules are exhausted. | P1 |
| **FR‑AE‑009** | Agentic mode SHALL record every decision made in a "decision trail" (list of timestamped entries: `{"step": N, "observed": ..., "decided": "run jwt_analyzer", "reason": "JWT found in response"}`) for auditability. | P1 |
| **FR‑AE‑010** | `--max‑depth` SHALL limit the number of recursive OODA cycles in agentic mode (default 5). This prevents infinite loops from ambiguous responses. | P1 |

### 2.6 Reporting

| ID | Requirement | Priority |
|----|-------------|----------|
| **FR‑RP‑001** | Terminal output SHALL use Rich‑formatted tables with color‑coded severity levels (💀 CRITICAL: bold red, 🔴 HIGH: red, 🟠 MEDIUM: yellow, 🟡 LOW: blue, ℹ INFO: dim). | P0 |
| **FR‑RP‑002** | `--output json` SHALL produce a complete, machine‑readable JSON report conforming to the ScanReport schema (see §5). | P0 |
| **FR‑RP‑003** | `--output markdown` SHALL produce a consultant‑grade Markdown report with executive summary, findings table, detailed finding sections including evidence and remediation, and an appendix with scan metadata. | P1 |
| **FR‑RP‑004** | `--output html` SHALL produce a standalone, styled HTML report (no external dependencies) suitable for direct sharing with clients. | P1 |
| **FR‑RP‑005** | `--output pdf` SHALL produce a PDF report via WeasyPrint (pure Python HTML→PDF conversion, no headless browser required). | P2 |
| **FR‑RP‑006** | `--output sarif` SHALL produce SARIF v2.1.0 output for direct integration with GitHub code scanning, GitLab SAST, and other SARIF‑consuming tools. | P1 |
| **FR‑RP‑007** | Every report format SHALL include an executive summary section containing: an overall risk score (weighted sum of finding severities, scaled to 0–100), finding counts grouped by severity, and the top 3–5 actionable recommendations. | P0 |
| **FR‑RP‑008** | All output SHALL be sanitized by default: JWT signatures, session cookie values, tokens, passwords, and any string matching a secret pattern SHALL be redacted (replaced with `[REDACTED]`). The `--no‑redact` flag SHALL disable this behavior, with a prominent warning in the output. | P0 |

### 2.7 Configuration & Profiles

| ID | Requirement | Priority |
|----|-------------|----------|
| **FR‑CF‑001** | A YAML configuration file SHALL be supported with all scan parameters: target, modules, rate limit, timeout, proxy, custom headers, cookies, auth credentials (type + credentials), scope rules, output settings, wordlist paths, and agentic settings. | P0 |
| **FR‑CF‑002** | Named profiles SHALL be supported within the config file: a `profiles:` section where each key is a profile name containing a partial or complete config override. `--profile quick‑owa` SHALL apply the named profile's settings. | P1 |
| **FR‑CF‑003** | All config values SHALL be overridable via environment variables with the `AUTH_SCAN_` prefix (e.g., `AUTH_SCAN_RATE_LIMIT=5`, `AUTH_SCAN_PROXY=http://127.0.0.1:8080`). Nested keys use double‑underscore (`AUTH_SCAN_AUTH__TYPE=bearer`). | P1 |
| **FR‑CF‑004** | `--init` SHALL generate a default `auth-scan-config.yml` file in the current directory with every available option, documented with inline comments. | P0 |
| **FR‑CF‑005** | Config loading SHALL validate all values and produce clear, actionable error messages (e.g., `"rate_limit must be a positive integer, got 'fast'"`) pointing to the exact key path. | P1 |
| **FR‑CF‑006** | `--set key=value` (repeatable) SHALL allow per‑invocation overrides of any config key (e.g., `--set rate_limit=3 --set output.formats=[json,terminal]`). | P1 |

---

## 3. Non‑Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| **NFR‑001** | Scan 100 endpoints in under 5 minutes at the default rate limit of 10 req/s. | Performance |
| **NFR‑002** | Memory usage SHALL remain under 512 MB for scans of up to 1,000 endpoints. | Resource |
| **NFR‑003** | Credentials, tokens, API keys, and secrets SHALL never be written to disk unless `--save‑config` is explicitly passed with a clear warning on stderr. | Security |
| **NFR‑004** | All log output (both stderr and log file) SHALL redact secrets by default. Redaction SHALL apply to: Authorization header values, Set‑Cookie values, `--password` values, JWT signatures, and any value matching a configurable secret regex pattern. | Security |
| **NFR‑005** | Rate limiting SHALL be mandatory and enforced at the HTTP adapter level. Default: 10 req/s. Configurable range: 1–100 req/s. No rate limiting above 100 req/s without an explicit `--i‑know‑what‑im‑doing` flag. | Safety |
| **NFR‑006** | Scope enforcement SHALL be mandatory. The HTTP adapter SHALL intercept every outbound request and redirect. Any request to a host not matching the scope allowlist SHALL be blocked. A `--no‑scope` flag exists but requires `--i‑know‑what‑im‑doing`. | Safety |
| **NFR‑007** | Python 3.10 SHALL be the minimum supported version. The codebase SHALL use Python 3.10+ features (structural pattern matching, `|` union types) where appropriate. | Compatibility |
| **NFR‑008** | Supported platforms: Linux (primary, tested on Ubuntu 22.04+), macOS (12+), Windows (10+, via WSL2 or native Python). | Compatibility |
| **NFR‑009** | The tool SHALL be pip‑installable: `pip install auth‑scan`. A `pyproject.toml` SHALL define the package, dependencies, and `[project.scripts]` entry point. | Distribution |
| **NFR‑010** | External plugin modules SHALL be discoverable via setuptools `entry_points` under the group `auth_scan.modules`. Each entry point SHALL point to a class inheriting from `BaseAttackModule`. | Extensibility |
| **NFR‑011** | All HTTP communication SHALL support TLS 1.2 and TLS 1.3. The `--no‑verify` flag SHALL disable certificate verification (useful for internal testing). `--ca‑bundle` SHALL specify a custom CA bundle path. | Security |
| **NFR‑012** | Proxy support SHALL cover HTTP, HTTPS, and SOCKS5 proxies via `--proxy` flag and the standard `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment variables. | Compatibility |
| **NFR‑013** | Every network operation SHALL have a timeout. Default: 30 seconds. Configurable via `--timeout` and per‑module in config. Operations that time out SHALL produce an INFO finding, not a fatal error. | Reliability |
| **NFR‑014** | Every outbound HTTP request SHALL carry a unique `X‑Request‑ID` header (UUID4) for traceability. The request ID SHALL appear in logs, evidence, and debug output. | Observability |
| **NFR‑015** | Structured logging SHALL emit JSON Lines to a log file (`scan‑{scan_id}.log`). Human‑readable output SHALL emit to stderr (colored, with Rich). The `--verbose` flag SHALL increase stderr detail; `--quiet` SHALL suppress everything except findings and errors. | Observability |

---

## 4. Architecture

### 4.1 High‑Level Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI (click)                              │
│      auth-scan <TARGET> [OPTIONS]                               │
│      ┌──────────┐  ┌────────────┐  ┌──────────────────────┐    │
│      │  Argument│  │  Config    │  │  Profile / Env Var   │    │
│      │  Parser  │  │  Loader    │  │  Override Merger     │    │
│      └────┬─────┘  └──────┬─────┘  └───────────┬──────────┘    │
│           └───────────────┼────────────────────┘                │
│                           ▼                                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │ ScanConfig
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Engine                                    │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────────┐   │
│  │    Probe     │  │   Agentic      │  │  Module Scheduler │   │
│  │    Phase     │  │   Engine       │  │  (sequential /    │   │
│  │              │  │  (OODA Loop)   │  │   agentic order)  │   │
│  └──────┬───────┘  └───────┬────────┘  └────────┬──────────┘   │
│         │                  │                     │               │
│         │    ┌─────────────┴─────────────┐       │               │
│         │    │   Attack Surface Model    │       │               │
│         │    │  ┌─────────────────────┐  │       │               │
│         │    │  │   Endpoint Graph    │  │       │               │
│         │    │  │  (URLs → Auth       │  │       │               │
│         │    │  │   Mechanisms →      │  │       │               │
│         │    │  │   Tokens → Forms)   │  │       │               │
│         │    │  └─────────────────────┘  │       │               │
│         │    └───────────────────────────┘       │               │
│         │                                        │               │
│         ▼                                        ▼               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Attack Modules                          │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │   │
│  │  │   JWT    │  │  Brute   │  │ Session  │  │  OAuth   │ │   │
│  │  │ Analyzer │  │  Force   │  │  Tests   │  │(Phase 2) │ │   │
│  │  │ (P0)     │  │ (P0)     │  │ (P0)     │  │          │ │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐               │   │
│  │  │   MFA    │  │   API    │  │  Custom   │               │   │
│  │  │  Tests   │  │   Key    │  │  Plugins  │               │   │
│  │  │(Phase 2) │  │ Analysis │  │ (Phase 2) │               │   │
│  │  └──────────┘  └──────────┘  └──────────┘               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   Session    │  │    Config    │  │      Reporter        │   │
│  │    Store     │  │   Manager    │  │  (term/json/md/html  │   │
│  │              │  │              │  │   /pdf/sarif)        │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└──────────────────────┬──────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────┐
│                  HTTP Adapter (requests)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │    Retry     │  │    Proxy     │  │   TLS Verification   │   │
│  │    Logic     │  │   Support    │  │   Control            │   │
│  │  (exponential│  │  (HTTP/HTTPS │  │  (verify/ca-bundle/  │   │
│  │   backoff)   │  │   /SOCKS5)   │  │   no-verify)         │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │  Rate        │  │    Scope     │  │   Request ID         │   │
│  │  Limiter     │  │   Enforcer   │  │   Generator          │   │
│  │ (token       │  │ (domain/IP   │  │   (UUID4)            │   │
│  │  bucket)     │  │  allowlist)  │  │                      │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 State Machines

#### Scan Lifecycle State Machine

```
                    ┌─────────┐
                    │  INIT   │
                    └────┬────┘
                         │ parse CLI + config
                         ▼
                    ┌─────────┐
                    │ PROBING │───────timeout/error──────▶┌─────────┐
                    └────┬────┘                          │ FAILED  │
                         │ probe complete                 └─────────┘
                         ▼
                 ┌───────────────┐
                 │ANALYZING_PROBE│
                 └───────┬───────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌────────────┐ ┌───────────┐ ┌──────────────┐
    │RUNNING     │ │RUNNING    │ │RUNNING       │    ... one per module
    │_MODULE     │ │_MODULE    │ │_MODULE       │
    │(JWT)       │ │(Session)  │ │(Brute)       │
    └─────┬──────┘ └─────┬─────┘ └──────┬───────┘
          │              │              │
          └──────────────┼──────────────┘
                         │
                    ┌────▼────┐    agentic only
                    │DECIDING │◄──────────────────────┐
                    │_NEXT    │                        │
                    └────┬────┘                        │
                         │ decided: continue            │
                         └─────────────────────────────┘
                         │ decided: done
                         ▼
                   ┌──────────┐
                   │REPORTING │
                   └────┬─────┘
                        │
                        ▼
                   ┌──────────┐
                   │   DONE   │
                   └──────────┘

    Any state ────fatal error────▶ FAILED (partial results saved)
```

#### Agentic Loop State Machine (OODA)

```
    ┌──────────┐
    │ OBSERVE  │◄──────────────────────────────────────┐
    │ collect  │                                        │
    │ module   │                                        │
    │ output   │                                        │
    └────┬─────┘                                        │
         │                                              │
         ▼                                              │
    ┌──────────┐                                        │
    │  ORIENT  │                                        │
    │ update   │                                        │
    │ attack   │                                        │
    │ surface  │                                        │
    │ model    │                                        │
    └────┬─────┘                                        │
         │                                              │
         ▼                                              │
    ┌──────────┐     confidence < threshold &&          │
    │ DECIDE   │─────depth < max_depth──────────────────┘
    │ select   │
    │ next     │     confidence >= threshold ||
    │ action   │─────no modules remain──────▶ CONCLUDE
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │   ACT    │
    │ execute  │
    │ selected │
    │ module   │
    └──────────┘
```

### 4.3 Module Plugin Contract

Every attack module (built‑in or external) SHALL conform to the following abstract base class:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ModuleResult:
    """Return value from every attack module."""
    findings: list          # list[Finding]
    state_update: dict      # merged into report.session_state
    metadata: dict          # module‑specific data for downstream modules
    errors: list[str]
    warnings: list[str]


class BaseAttackModule(ABC):
    """
    Contract for all attack modules.

    Built‑in modules inherit from this class directly.
    External plugins are discovered via setuptools entry_points
    under the group `auth_scan.modules` and must also inherit
    from this base class.
    """

    name: str                # Unique module identifier (e.g., "jwt_analyzer")
    description: str         # Human‑readable description
    version: str = "1.0.0"  # Semantic version
    priority: int = 50       # Default ordering (lower runs first)

    @abstractmethod
    def prerequisites(self, report: "ScanReport") -> list[str]:
        """
        Return a list of prerequisite module names that must run before
        this module. Return an empty list if there are none.

        The engine resolves the dependency graph and runs prerequisites
        first, avoiding circular dependencies.
        """
        ...

    @abstractmethod
    def run(
        self,
        target: str,
        http_client: "HttpClient",
        report: "ScanReport",
        config: "ScanConfig",
    ) -> ModuleResult:
        """
        Execute the attack module.

        Args:
            target: The target URL.
            http_client: The HTTP adapter for making requests.
            report: The accumulated ScanReport from all prior phases/modules.
            config: The merged scan configuration.

        Returns:
            ModuleResult with findings, state updates, and metadata.
        """
        ...
```

**Built‑in module priorities:**
| Module | Priority |
|--------|----------|
| Probe | 0 |
| JWT Analyzer | 10 |
| Session Tests | 20 |
| Brute Force | 30 |
| OAuth Tester (Phase 2) | 40 |
| MFA Bypass Tests (Phase 2) | 50 |
| API Key Analysis (Phase 2) | 60 |

### 4.4 Technology Choices

| Component | Technology | Rationale |
|-----------|------------|-----------|
| **Language** | Python 3.10+ | Rich ecosystem (`requests`, `click`, `rich`, `pyjwt`), readable code, familiar to pentesters, rapid development |
| **CLI Framework** | Click 8.x | Composable commands, decorator‑based, battle‑tested, excellent testability |
| **Terminal Output** | Rich 13.x | Tables, progress bars, panels, syntax highlighting, markdown rendering |
| **HTTP Client** | requests 2.31+ with urllib3 Retry | Session persistence, proxy support, TLS control, connection pooling |
| **JWT Handling** | PyJWT 2.8+ + cryptography 41+ | JWT decode/encode, algorithm‑specific signing, key generation, JWKS parsing |
| **HTML Parsing** | BeautifulSoup4 4.12+ + lxml | Form extraction, link discovery, token scraping |
| **Report Templating** | Jinja2 3.x | Template inheritance for Markdown/HTML reports, separation of logic and presentation |
| **PDF Generation** | WeasyPrint 60+ | Pure Python HTML→PDF, no headless browser, reproducible output |
| **Async (future)** | aiohttp / httpx | For Phase 3 TUI and high‑concurrency scans |
| **Configuration** | PyYAML 6.x + Pydantic 2.x | YAML parsing with schema validation via Pydantic models |
| **Package Metadata** | pyproject.toml (setuptools) | Modern Python packaging, entry_points for plugin discovery |

### 4.5 Directory Structure

```
auth-scan/
├── pyproject.toml
├── README.md
├── LICENSE
├── AUTH-SCAN-SPEC.md
│
├── auth_scan/
│   ├── __init__.py              # Version, package metadata
│   ├── cli.py                   # Click CLI entry point
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py            # Scan orchestrator, lifecycle state machine
│   │   ├── http_client.py       # requests wrapper: retry, proxy, TLS, scope, rate
│   │   ├── session.py           # Cookie jar, token store, JWT parser
│   │   ├── reporter.py          # Multi‑format output: term, JSON, MD, HTML, PDF, SARIF
│   │   ├── config.py            # YAML + env var + profile merger, Pydantic validation
│   │   ├── agentic.py           # OODA loop, attack surface model, decision engine
│   │   └── scope.py             # Domain/IP allowlist/denylist enforcement
│   │
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── base.py              # BaseAttackModule ABC + ModuleResult
│   │   ├── probe.py             # Probe phase: headers, forms, cookies, TLS check
│   │   ├── jwt_analyzer.py      # FR‑JWT‑001 through FR‑JWT‑008
│   │   ├── brute.py             # FR‑BF‑001 through FR‑BF‑006
│   │   ├── session_tests.py     # FR‑ST‑001 through FR‑ST‑007
│   │   └── oauth.py             # (Phase 2) OAuth 2.0/OIDC flow testing
│   │
│   ├── adapters/
│   │   ├── __init__.py
│   │   └── web.py               # HTTP/HTML form auth adapter (default)
│   │
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── terminal.py          # Rich tables, panels, color output
│   │   ├── json_reporter.py     # Machine‑readable JSON
│   │   ├── markdown.py          # Consultant‑grade Markdown
│   │   ├── html_reporter.py     # Standalone HTML (Jinja2)
│   │   ├── pdf_reporter.py      # WeasyPrint HTML→PDF
│   │   └── sarif_reporter.py    # SARIF v2.1.0
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── finding.py           # Finding dataclass
│   │   ├── report.py            # ScanReport dataclass
│   │   ├── severity.py          # Severity enum
│   │   └── config.py            # ScanConfig Pydantic model
│   │
│   └── utils/
│       ├── __init__.py
│       ├── wordlists.py         # Wordlist loading, built‑in defaults
│       ├── entropy.py           # Shannon entropy, randomness tests
│       └── redact.py            # Secret redaction for output
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Shared fixtures, mock HTTP server
│   ├── core/
│   │   ├── test_http_client.py
│   │   ├── test_session.py
│   │   ├── test_reporter.py
│   │   ├── test_engine.py
│   │   ├── test_config.py
│   │   └── test_agentic.py
│   ├── attacks/
│   │   ├── test_jwt_analyzer.py
│   │   ├── test_brute.py
│   │   └── test_session_tests.py
│   ├── test_cli.py
│   └── fixtures/
│       ├── vuln_app/
│       │   ├── app.py           # Vulnerable Flask test app
│       │   ├── requirements.txt
│       │   └── README.md
│       └── test_config.yml
│
├── wordlists/
│   └── common_passwords.txt     # Built‑in 100‑password default
│
├── docs/
│   ├── architecture.md
│   ├── modules.md
│   ├── contributing.md
│   └── plugin-guide.md
│
└── .github/
    └── workflows/
        ├── lint.yml
        ├── test.yml
        └── publish.yml
```

---

## 5. Data Schemas

### 5.1 Severity Enum

```python
from enum import Enum


class Severity(str, Enum):
    """
    Finding severity levels.

    The numeric range is used for CVSS mapping and risk scoring.
    The string value is used for serialization.
    """
    CRITICAL = "critical"   # 9.0 – 10.0
    HIGH     = "high"       # 7.0 – 8.9
    MEDIUM   = "medium"     # 4.0 – 6.9
    LOW      = "low"        # 0.1 – 3.9
    INFO     = "info"       # 0.0

    @property
    def numeric(self) -> float:
        """Return the midpoint of the severity range."""
        return {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 2.0,
            Severity.INFO: 0.0,
        }[self]
```

### 5.2 Finding Dataclass

```python
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4


@dataclass
class Finding:
    """A single security finding produced by a module."""

    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""                           # Short, human‑readable title
    severity: Severity = Severity.INFO        # Severity level
    description: str = ""                     # Detailed explanation of the vulnerability
    evidence: dict = field(default_factory=dict)
    # evidence contains:
    #   request: dict   — {method, url, headers, body (truncated)}
    #   response: dict  — {status, headers, body (truncated)}
    #   notes: str      — human‑readable context
    remediation: str = ""                     # Actionable fix instructions
    cwe_id: Optional[str] = None             # CWE ID (e.g., "CWE-287", "CWE-384")
    cvss_score: Optional[float] = None        # CVSS v3.1 score (0.0–10.0)
    module_name: str = ""                     # Which module produced this finding
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0                   # Engine confidence (0.0–1.0)
    chain_parent: Optional[str] = None        # Finding ID this was chained from
    chain_children: list[str] = field(default_factory=list)  # Finding IDs chained from this
    tags: list[str] = field(default_factory=list)  # e.g., ["jwt", "crypto", "session"]
    request_id: Optional[str] = None          # UUID of the HTTP request that produced evidence

    def to_dict(self, redact: bool = True) -> dict:
        """Serialize to dict, optionally redacting sensitive fields."""
        ...
```

### 5.3 ScanReport Dataclass

```python
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ScanReport:
    """The accumulated state of a scan — passed between phases/modules."""

    scan_id: str = field(default_factory=lambda: str(uuid4()))
    target: str = ""                          # Original target URL
    effective_target: str = ""                # Final URL after redirects
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    status: str = "initialized"               # initialized|probing|running|completed|failed

    # Probe results and discovered artifacts
    metadata: dict = field(default_factory=dict)
    # metadata contains:
    #   server_info: {server, powered_by, ...}
    #   security_headers: {header_name: present (bool)}
    #   forms: [{action, method, inputs: [{name, type, value}]}]
    #   jwt_tokens: [{location, cookie_name, algorithm, expires, issues}]
    #   endpoints_discovered: [str]
    #   rate_limiting: {detected: bool, limit: int, retry_after: str}

    # Findings (the primary output)
    findings: list[Finding] = field(default_factory=list)

    # Authentication session state
    session_state: dict = field(default_factory=dict)
    # session_state contains:
    #   cookies: {name: {value, http_only, secure, same_site, domain, path}}
    #   tokens: {location: {type: jwt|bearer|api_key, value, properties}}
    #   authenticated: bool
    #   auth_type: str  # bearer|basic|form|cookie|oauth2|unknown

    # Snapshot of config used (for audit trail)
    config_snapshot: dict = field(default_factory=dict)

    # Agentic decision trail
    decision_trail: list[dict] = field(default_factory=list)
    # decision_trail entries:
    #   {step: int, timestamp: str, action: "observe"|"orient"|"decide"|"act",
    #    detail: str, model_state_snapshot: dict}

    def add_finding(self, finding: Finding) -> None:
        """Add a finding, auto‑populating timestamp and deduplicating."""
        ...

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        ...

    @property
    def risk_score(self) -> float:
        """Overall risk score: weighted sum of finding severities, 0–100."""
        ...
```

### 5.4 ModuleResult Dataclass

```python
from dataclasses import dataclass, field


@dataclass
class ModuleResult:
    """Return value from every attack module's run() method."""

    findings: list[Finding] = field(default_factory=list)
    state_update: dict = field(default_factory=dict)
    # state_update keys are merged into report.session_state
    metadata: dict = field(default_factory=dict)
    # metadata contains module‑specific data for downstream modules
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        """True if any finding has CRITICAL severity."""
        ...

    @property
    def has_errors(self) -> bool:
        """True if the module encountered non‑fatal errors."""
        ...
```

### 5.5 Configuration YAML Schema

```yaml
# auth-scan configuration file
# Generated by: auth-scan --init

# Override the CLI target (useful for config‑driven scans)
target: ""

# === Module Configuration ===

# Modules to run (in order). Default: all built‑in modules.
# Available: probe, jwt, session, brute
modules:
  - probe
  - jwt
  - session
  - brute

# === HTTP Configuration ===

# Requests per second (1–100)
rate_limit: 10

# Request timeout in seconds
timeout: 30

# Custom User‑Agent header
user_agent: "auth-scan/1.0"

# Proxy URL (http://host:port or socks5://host:port)
proxy: ""

# Custom headers added to every request
headers: {}
  # X-Custom-Header: value

# Initial cookies (Set‑Cookie format)
cookies: {}
  # sessionid: abc123

# === Authentication Configuration ===

auth:
  # Type: bearer, basic, form, cookie, oauth2
  type: ""
  credentials: {}
    # For bearer:  {token: "eyJ..."}
    # For basic:   {username: "user", password: "pass"}
    # For form:    {login_url: "/login", username_field: "user",
    #               password_field: "pass", username: "user", password: "pass"}
    # For cookie:  {name: "session", value: "abc123"}
    # For oauth2:  {client_id, client_secret, token_url, ...}

# === Scope Configuration ===

scope:
  # Allowed domains/IPs (empty = target domain only)
  allow: []
  # Blocked domains/IPs (takes precedence over allow)
  deny: []

# === Output Configuration ===

output:
  # Output formats: terminal, json, markdown, html, pdf, sarif
  formats:
    - terminal
  # Output directory for file‑based reports
  directory: "./scan-results"
  # Show secrets in output (DANGEROUS — for debugging only)
  no_redact: false

# === Wordlist Configuration ===

wordlists:
  # Path to password wordlist file
  passwords: ""
  # Path to username wordlist file
  usernames: ""

# === Agentic Engine Configuration ===

agentic:
  # Enable adaptive scanning
  enabled: false
  # Maximum recursion depth
  max_depth: 5
  # Stop when model confidence exceeds this threshold
  confidence_threshold: 0.9

# === Profiles ===
# Named sets of overrides. Use with: auth-scan --profile <name>
profiles:
  quick-owa:
    modules: [probe]
    agentic:
      enabled: false

  deep-jwt:
    modules: [probe, jwt, session]
    rate_limit: 5
    agentic:
      enabled: true
      max_depth: 8

  ci-pipeline:
    modules: [probe, jwt, session]
    output:
      formats: [json, sarif]
    agentic:
      enabled: false

  full-pentest:
    rate_limit: 3
    timeout: 60
    agentic:
      enabled: true
      max_depth: 10
      confidence_threshold: 0.95
```

---

## 6. UX Specification

### 6.1 CLI Command Tree

```
auth-scan <TARGET> [OPTIONS]

TARGET (required):
  The URL to scan. Supports http://, https://, or bare domain
  (defaults to https://). Examples:
    auth-scan https://example.com
    auth-scan example.com
    auth-scan http://192.168.1.10:3000

OPTIONS:

  Module Selection:
    --modules TEXT...        Modules to run (default: probe,jwt,session,brute)
                             Repeatable. Use "all" for every loaded module.
    --quick                  Quick scan: probe + header checks only
    --skip TEXT...           Modules to skip (repeatable)

  Output Control:
    --output, -o FORMAT...   Output formats: terminal, json, markdown,
                             html, pdf, sarif (default: terminal)
                             Repeatable for multiple formats.
    --output-dir PATH        Directory for file-based output
                             (default: ./scan-results)
    --no-redact              Show secrets in output (DANGER — for debugging)
    --no-color               Disable colored terminal output
    --verbose, -v            Increase verbosity (stackable: -v, -vv, -vvv)
    --quiet, -q              Suppress all output except errors and summary
    --silent                 Exit code only, no output at all

  Configuration:
    --config, -c PATH        Path to YAML config file
    --profile, -P NAME       Named profile from config file
    --init                   Generate default config file (auth-scan-config.yml)
    --set KEY=VALUE          Override config value (repeatable)
                             Example: --set rate_limit=5 --set agentic.enabled=true

  Scan Control:
    --agentic                Enable adaptive scanning (OODA loop)
    --max-depth N            Agentic recursion depth (default: 5)
    --confidence-threshold N Stop scanning at this confidence (default: 0.9,
                             range: 0.0–1.0)
    --timeout N              Request timeout in seconds (default: 30)
    --rate-limit N           Requests per second (default: 10, range: 1–100)
    --resume SCAN_ID         Resume a previous scan from checkpoint

  Authentication / Session:
    --auth-type TYPE         Authentication type: bearer, basic, form,
                             cookie, oauth2
    --username USER          Authentication username
    --password PASS          Authentication password
    --token TOKEN            Bearer token or API key
    --cookie KEY=VALUE       Initial cookie (repeatable)
    --header KEY=VALUE       Custom header (repeatable)

  HTTP / Network:
    --proxy URL              Proxy URL (http://host:port or socks5://host:port)
    --no-verify              Disable TLS certificate verification
    --ca-bundle PATH         Custom CA bundle for TLS verification

  Scope:
    --scope DOMAIN           Allowed domain (repeatable, default: target domain)
    --no-scope               Disable scope enforcement (requires
                             --i-know-what-im-doing)

  Wordlists:
    --wordlist, -w PATH      Password wordlist path
    --user-wordlist PATH     Username wordlist path

  Meta:
    --version                Show version and exit
    --help                   Show this help and exit
```

### 6.2 Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| **0** | Scan completed, no findings at CRITICAL or HIGH severity |
| **1** | INFO and/or LOW findings only (no MEDIUM, HIGH, or CRITICAL) |
| **2** | MEDIUM severity findings present (no HIGH or CRITICAL) |
| **3** | HIGH severity findings present (no CRITICAL) |
| **4** | CRITICAL severity findings present |
| **255** | Fatal error — scan could not complete (network failure, invalid config, etc.) |

### 6.3 Terminal Output Mockup

```
╔══════════════════════════════════════════════════════════════╗
║  auth-scan v1.0.0 — Web Authentication Security Scanner     ║
║  https://github.com/auth-scan/auth-scan                      ║
╚══════════════════════════════════════════════════════════════╝

Target: https://example.com
Started: 2026-05-16T14:32:01Z
Modules: probe, jwt, session, brute

────────────────────────────────────────────────────────────────

[PROBE] Phase 1/4 — Reconnaissance
──────────────────────────────────
  ✓ Status: 200 OK
  ✓ Server: nginx/1.24.0
  ✓ TLS: TLSv1.3, ECDHE-RSA-AES256-GCM-SHA384
  ⚠ Unencrypted redirect detected: http://example.com → https://example.com
  ⚠ Missing security header: Strict-Transport-Security
  ⚠ Missing security header: Content-Security-Policy
  ℹ Login form discovered at /login (POST, fields: username, password)
  ℹ JWT token found in cookie: auth_token (RS256)
  → 3 findings so far

[JWT ANALYZER] Phase 2/4 — Token Analysis
──────────────────────────────────────────
  ✓ Found 1 JWT in cookie: auth_token
  ⚠ Token algorithm: RS256 (asymmetric — verify key management)
  ✗ CRITICAL: alg=none attack accepted — token verified without signature!
  ✗ HIGH: Expired token still accepted (exp: 2026-01-01, 135 days ago)
  ⚠ MEDIUM: Sensitive data in JWT payload: email=admin@example.com
  ℹ Token lifetime: 30 days (consider shorter expiry)
  → 7 findings so far

[SESSION TESTS] Phase 3/4 — Session Management
───────────────────────────────────────────────
  ✓ Session cookie identified: sessionid
  ✗ HIGH: HttpOnly flag not set on session cookie
  ✗ HIGH: Session not invalidated after logout
  ⚠ MEDIUM: SameSite attribute missing — CSRF risk
  ⚠ MEDIUM: Session cookie lifetime: 24 hours (consider shorter)
  ℹ CSRF token present on /login form: csrf_token
  → 12 findings so far

[BRUTE FORCE] Phase 4/4 — Credential Strength
──────────────────────────────────────────────
  → Testing https://example.com/login (default wordlist: 100 credentials)
  ⠴ Testing credentials... (45/100) — 14 findings so far
  ✓ Rate limiting detected at ~5 req/s — auto-throttling applied
  ✗ HIGH: User enumeration possible via response timing (Δ 320ms)
  ✗ CRITICAL: Weak credentials accepted: admin / admin
  ✓ Account lockout not detected (15 failed attempts)
  → 17 findings so far

═══════════════════════════════════════════════════════════════
                     SCAN COMPLETE
═══════════════════════════════════════════════════════════════

  Duration: 3.42 seconds
  Endpoints tested: 12
  Requests sent: 147

  Findings by Severity:
  💀 CRITICAL:  2
  🔴 HIGH:      4
  🟠 MEDIUM:    6
  🟡 LOW:       4
  ℹ  INFO:      1
  ─────────────────────
  Total:        17

  Risk Score: 78/100 (HIGH)

  Top Recommendations:
  1. Fix JWT alg=none vulnerability (CRITICAL)
  2. Change default credentials (CRITICAL)
  3. Enable HttpOnly flag on all session cookies (HIGH)

  Reports saved:
  • ./scan-results/example.com-20260516-T143201Z.json
  • ./scan-results/example.com-20260516-T143201Z.md

  Exit code: 4 (CRITICAL findings present)
```

### 6.4 JSON Output Example (excerpt)

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "target": "https://example.com",
  "effective_target": "https://example.com",
  "started_at": "2026-05-16T14:32:01Z",
  "completed_at": "2026-05-16T14:32:04.42Z",
  "status": "completed",
  "risk_score": 78.0,
  "findings": [
    {
      "id": "f1e2d3c4-b5a6-7890-cdef-1234567890ab",
      "title": "JWT alg=none Accepted",
      "severity": "critical",
      "description": "The server accepts JWT tokens with the 'none' algorithm, allowing attackers to forge tokens with arbitrary payloads without any cryptographic signature.",
      "evidence": {
        "request": {
          "method": "GET",
          "url": "https://example.com/api/profile",
          "headers": {
            "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.[REDACTED]."
          }
        },
        "response": {
          "status": 200,
          "body_preview": "{\"username\":\"admin\",\"email\":\"[REDACTED]\"}"
        },
        "notes": "Server returned 200 OK with user data, confirming signature bypass."
      },
      "remediation": "Configure the JWT validation library to explicitly reject tokens with 'alg':'none'. For popular libraries: jsonwebtoken (Node) — use 'algorithms: ['RS256']' option; PyJWT (Python) — pass 'algorithms=['RS256']' to jwt.decode(); jjwt (Java) — use .requireAlgorithm().",
      "cwe_id": "CWE-347",
      "cvss_score": 9.8,
      "module_name": "jwt_analyzer",
      "timestamp": "2026-05-16T14:32:02.1Z",
      "confidence": 0.98,
      "chain_parent": null,
      "chain_children": [],
      "tags": ["jwt", "crypto", "signature-bypass"]
    }
  ],
  "metadata": {
    "server_info": {"server": "nginx/1.24.0"},
    "tls_version": "TLSv1.3",
    "endpoints_discovered": ["/login", "/api/profile", "/logout", "/register"],
    "security_headers": {
      "Strict-Transport-Security": false,
      "X-Content-Type-Options": true,
      "X-Frame-Options": true,
      "Content-Security-Policy": false,
      "Referrer-Policy": true,
      "Permissions-Policy": false
    }
  },
  "decision_trail": [],
  "config_snapshot": {
    "rate_limit": 10,
    "timeout": 30,
    "modules": ["probe", "jwt", "session", "brute"],
    "agentic": {"enabled": false}
  }
}
```

---

## 7. Testing Strategy

### 7.1 Unit Tests

All unit tests use **pytest** with fixtures for mock HTTP servers, sample tokens, and sample configs.

| Test File | Coverage Area | Key Test Cases |
|-----------|--------------|----------------|
| `tests/core/test_http_client.py` | HTTP adapter | Retry logic (429, 5xx), exponential backoff, proxy forwarding, TLS verification (valid/invalid/self‑signed), timeout handling, request ID generation, rate limiter token bucket, scope enforcement (allow/deny) |
| `tests/core/test_session.py` | Session store | JWT decode (valid/split), cookie parsing (all attributes), token detection in headers/cookies/body, session state merge from `ModuleResult`, cookie attribute analysis (HttpOnly, Secure, SameSite) |
| `tests/core/test_reporter.py` | Output formatting | Terminal table rendering, JSON serialization (full round‑trip), Markdown generation (all sections), HTML standalone output, PDF generation (basic), SARIF v2.1.0 compliance, executive summary calculation, secret redaction (all output formats) |
| `tests/core/test_engine.py` | Scan orchestrator | Probe phase complete lifecycle, module scheduling (sequential order), module dependency resolution, `ScanReport` accumulation across modules, `--quick` flag skipping, `--resume` from checkpoint, SIGINT graceful shutdown, module error isolation (one fails, others run) |
| `tests/core/test_config.py` | Configuration | YAML parsing, profile merging (profile + defaults), env var overrides (`AUTH_SCAN_*`), `--set` overrides, validation errors (clear messages), Pydantic schema enforcement |
| `tests/core/test_agentic.py` | Agentic engine | OODA loop execution, attack surface model graph updates, confidence scoring, finding chaining, deduplication, `--max-depth` enforcement, confidence threshold stopping, decision trail recording |
| `tests/attacks/test_jwt_analyzer.py` | JWT module | **FR‑JWT‑001**: JWT detection in headers/cookies/body. **FR‑JWT‑002**: Header+payload decode. **FR‑JWT‑003**: alg=none attack (both accepted/rejected paths). **FR‑JWT‑004**: Key confusion RS256→HS256. **FR‑JWT‑005**: Expiry — expired accepted, long lifetime. **FR‑JWT‑006**: nbf claim — future token accepted. **FR‑JWT‑007**: Sensitive data detection (passwords, PII, internal IDs). **FR‑JWT‑008**: aud/iss validation bypass |
| `tests/attacks/test_brute.py` | Brute force module | **FR‑BF‑001**: Login form auto‑discovery. **FR‑BF‑002**: Wordlist loading (file + built‑in). **FR‑BF‑004**: Lockout detection (status/body/timing). **FR‑BF‑005**: Rate limiting detection (429, latency, Retry‑After). **FR‑BF‑006**: User enumeration detection (status/body/timing) |
| `tests/attacks/test_session_tests.py` | Session module | **FR‑ST‑001**: Cookie attribute analysis. **FR‑ST‑002**: Session fixation test. **FR‑ST‑003**: Session invalidation after logout. **FR‑ST‑004**: CSRF token absence detection. **FR‑ST‑006**: Session ID in URL detection. **FR‑ST‑007**: Entropy analysis |
| `tests/test_cli.py` | CLI integration | All flags and combinations, `--help` output completeness, `--version`, config file loading, `--profile`, `--init` file generation, exit codes (0/1/2/3/4/255), error messages on invalid input, `ctrl+c` behavior |

### 7.2 Integration Test Matrix

Integration tests run against known test applications. Each test framework has a containerized app in the test suite with intentional vulnerabilities.

| Test Framework | App Type | JWT Tests | Session Tests | Brute Tests | OAuth Tests (Ph.2) |
|---------------|----------|-----------|---------------|-------------|---------------------|
| **Flask‑Login** | Python | ✓ alg=none, weak HS256 | ✓ fixation, invalidation, flags | ✓ default creds, enum | — |
| **Django auth** | Python | ✓ RS256, expiry | ✓ CSRF, flags, invalidation | ✓ lockout, rate limit | — |
| **Express + Passport** | Node.js | ✓ key confusion, expiry | ✓ Secure flags, SameSite | ✓ brute, enum | — |
| **Keycloak** | Java | ✓ JWKS, aud/iss | ✓ OIDC session | — | ✓ PKCE, redirect URI |
| **Auth0** | SaaS | ✓ RS256, kid header | ✓ OIDC session | — | ✓ implicit flow, state |
| **Firebase Auth** | SaaS | ✓ Google‑issued JWT | ✓ token refresh | — | — |

### 7.3 Vulnerable Test App

Located at `tests/fixtures/vuln_app/`, a Flask application with the following intentional vulnerabilities:

- Default credentials: `admin:admin`, `user:password`
- JWT signed with weak HS256 secret (`weak-secret-12345`)
- JWT endpoint that accepts `alg:none`
- Session cookie missing `HttpOnly`, `Secure`, and `SameSite` flags
- No CSRF protection on `/login` and `/profile` forms
- Session fixation: server reuses pre‑auth session ID
- No session invalidation on logout
- User enumeration via distinct error messages
- No rate limiting on `/login`
- Session ID in URL query parameter on redirects
- Sensitive data in JWT payload (email, internal role IDs)

The test app is started automatically by the integration test fixture and torn down after tests complete.

### 7.4 CI/CD Pipeline (GitHub Actions)

```yaml
# .github/workflows/ci.yml

name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v2
      - run: uv run ruff check .
      - run: uv run ruff format --check .

  type-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v2
      - run: uv run mypy auth_scan/

  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v2
        with:
          python-version: ${{ matrix.python-version }}
      - run: uv run pytest tests/ --cov=auth_scan --cov-report=xml
      - uses: codecov/codecov-action@v4

  integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v2
      - run: |
          cd tests/fixtures/vuln_app
          uv run flask run &
          sleep 3
      - run: uv run auth-scan https://localhost:5000 --no-verify --output json --output-file /tmp/result.json
      - run: uv run python -c "import json; d=json.load(open('/tmp/result.json')); assert len(d['findings']) >= 5, f'Expected >=5 findings, got {len(d[\"findings\"])}'"

  build:
    needs: [lint, type-check, test, integration]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v2
      - run: uv build

  publish:
    if: startsWith(github.ref, 'refs/tags/v')
    needs: [build]
    runs-on: ubuntu-latest
    environment: pypi
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v2
      - run: uv build
      - run: uv publish --token ${{ secrets.PYPI_TOKEN }}
```

---

## 8. Roadmap & Phases

### Phase 1 — MVP (P0)

**Goal:** `pip install auth-scan && auth-scan https://vuln-app` produces meaningful findings.

**Acceptance Criteria:**
- The tool is installable via `pip install auth-scan`.
- Running `auth-scan https://localhost:5000` (against the test app) produces ≥5 findings spanning probe, JWT, session, and brute modules.
- Terminal output uses Rich formatting with severity‑color‑coded tables.
- JSON output is complete and machine‑readable.
- `--init` generates a valid, documented YAML config file.
- Exit codes differentiate finding severities correctly.
- HTTP adapter supports retries, TLS verification, and proxy.

**Modules:**
| Module | Status | Key FRs |
|--------|--------|---------|
| Probe | Complete | FR‑SL‑001 through FR‑SL‑004 |
| JWT Analyzer | Core attacks only | FR‑JWT‑001 through FR‑JWT‑005, FR‑JWT‑007 |
| Session Tests | Core analysis only | FR‑ST‑001, FR‑ST‑002, FR‑ST‑003, FR‑ST‑006 |
| Brute Force | Default wordlist only | FR‑BF‑001 through FR‑BF‑003 |

**Output Formats:**
- Terminal (Rich)
- JSON

**Exit Codes:** 0 (no findings), 1 (INFO/LOW only), 2 (MEDIUM), 3 (HIGH), 4 (CRITICAL)

**Deliverables:**
- `auth_scan/` package with core engine, HTTP adapter, probe, JWT, session, brute modules
- `pyproject.toml` with dependencies and `[project.scripts]`
- `README.md` with installation and quickstart
- Unit tests for all core and attack modules (≥80% coverage target)
- Integration test with vulnerable Flask app
- `common_passwords.txt` (100 entries)
- GitHub Actions CI: lint, type‑check, unit tests, integration test

---

### Phase 2 — Advanced (P1)

**Goal:** Full agentic scanning, comprehensive auth module coverage, multiple report formats, and a public plugin system.

**Modules:**
| Module | Key FRs |
|--------|---------|
| JWT Cracker (wordlist‑based HMAC secret) | Extension of FR‑JWT‑004 |
| OAuth 2.0 / OIDC Flow Tester | New module — redirect URI validation, PKCE enforcement, state parameter, CSRF in `/authorize`, `response_type` confusion |
| MFA Bypass Tests | New module — response manipulation, race conditions on MFA verification, backup code brute‑force |
| WebSocket Auth | New module — token in handshake, connection‑level auth persistence |
| API Key Analysis | New module — key pattern detection, key rotation checks, least‑privilege validation |
| User Enumeration | Extension of FR‑BF‑006 — timing‑based, response‑diff‑based, registration‑based |
| Path Discovery | Common auth endpoints dictionary attack (`/admin`, `/api/auth`, `/.well-known/openid-configuration`) |

**Features:**
| Feature | Key FRs |
|---------|---------|
| Agentic Engine (OODA loop) | FR‑AE‑001 through FR‑AE‑010 |
| Finding chaining | FR‑AE‑004 |
| De‑duplication | FR‑AE‑005 |
| Markdown report output | FR‑RP‑003 |
| HTML report output | FR‑RP‑004 |
| SARIF report output | FR‑RP‑006 |
| Profile support (`--profile`) | FR‑CF‑002 |
| Env var overrides (`AUTH_SCAN_*`) | FR‑CF‑003 |
| `--set key=value` overrides | FR‑CF‑006 |
| Plugin system via `entry_points` | NFR‑010 |
| Rate‑limit detection & auto‑throttle | FR‑BF‑005 |
| Account lockout detection | FR‑BF‑004 |
| Session entropy analysis | FR‑ST‑007 |
| `--resume` scan checkpoint | FR‑SL‑009 |
| Progress indicator for long modules | FR‑SL‑015 |
| Config validation with error messages | FR‑CF‑005 |

**Deliverables:**
- Plugin developer guide (`docs/plugin-guide.md`)
- Example external plugin in a separate repo
- Full integration test matrix (Flask‑Login, Django, Express+Passport, Keycloak, Auth0, Firebase Auth)
- Coverage report integrated into CI
- `CONTRIBUTING.md` with setup instructions

---

### Phase 3 — Ecosystem (P2)

**Goal:** Multiple interfaces, deployment options, and a community plugin ecosystem.

**Features:**
| Feature | Description |
|---------|-------------|
| TUI Dashboard | Built with Textual framework — real‑time scan monitoring, interactive finding exploration, live attack surface graph visualization |
| REST API Server | FastAPI server wrapping the core engine — `POST /scan` to start, `GET /scan/{id}` for status/results, WebSocket for live progress |
| Web Dashboard | React or htmx frontend consuming the REST API — scan history, finding comparison over time, compliance dashboards |
| Plugin Marketplace | Central registry (GitHub repo) with community plugins, versioning, and compatibility metadata |
| SBOM Generation | CycloneDX or SPDX output listing all dependencies and their versions |
| Native GitHub Action | `auth-scan/action` — runs on push/PR, annotates code with findings |
| Docker Image | `ghcr.io/auth-scan/auth-scan:latest` — pre‑built for CI/CD |
| PDF report output | FR‑RP‑005 (WeasyPrint) |
| Multi‑target scanning | Accept multiple targets or a file of targets for batch scanning |
| Diff mode | Compare two scans (before/after fix) and highlight regressions or resolved findings |
| Internationalization | Error messages and remediation text in multiple languages (community‑contributed) |

**Deliverables:**
- `auth-scan-api` package (separate from core CLI)
- `auth-scan-web` package (separate)
- Dockerfile and docker‑compose.yml for full stack
- GitHub Action repository
- Plugin registry repository with submission guidelines
- User documentation site (MkDocs or Docusaurus)

---

## Appendix A: CWE Mappings

| Finding Category | Primary CWE |
|-----------------|-------------|
| JWT alg=none accepted | CWE‑347: Improper Verification of Cryptographic Signature |
| JWT key confusion (RS256→HS256) | CWE‑347 / CWE‑327: Use of a Broken or Risky Cryptographic Algorithm |
| JWT weak HMAC secret | CWE‑327 |
| JWT sensitive data exposure | CWE‑312: Cleartext Storage of Sensitive Information |
| JWT expired token accepted | CWE‑613: Insufficient Session Expiration |
| Missing HttpOnly flag | CWE‑1004: Sensitive Cookie Without 'HttpOnly' Flag |
| Missing Secure flag | CWE‑614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |
| Missing SameSite attribute | CWE‑1275: Sensitive Cookie with Improper SameSite Attribute |
| Session fixation | CWE‑384: Session Fixation |
| Session not invalidated on logout | CWE‑613 |
| Missing CSRF token | CWE‑352: Cross‑Site Request Forgery (CSRF) |
| Session ID in URL | CWE‑598: Use of GET Request Method With Sensitive Query Strings |
| Default credentials | CWE‑1392: Use of Default Credentials |
| Weak password policy | CWE‑521: Weak Password Requirements |
| User enumeration | CWE‑204: Observable Response Discrepancy |
| Missing HSTS | CWE‑319: Cleartext Transmission of Sensitive Information |
| Missing CSP | CWE‑1021: Improper Restriction of Rendered UI Layers |
| No rate limiting | CWE‑307: Improper Restriction of Excessive Authentication Attempts |
| No account lockout | CWE‑307 |
| Broad cookie Domain | CWE‑668: Exposure of Resource to Wrong Sphere |
| OAuth redirect URI not validated | CWE‑601: URL Redirection to Untrusted Site ('Open Redirect') |
| OAuth PKCE not enforced | CWE‑862: Missing Authorization |

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **Attack Surface Model** | A directed graph maintained by the agentic engine representing discovered endpoints, auth mechanisms, tokens, forms, and their relationships. |
| **Confidence Score** | A float (0.0–1.0) assigned to each finding indicating how certain the engine is. Direct observations score ≥0.95; inferred findings score lower. |
| **Decision Trail** | An ordered list of decisions made by the agentic engine, recording what was observed, what was decided, and the rationale. |
| **Finding Chaining** | The process of combining multiple low‑severity findings into a higher‑severity exploit path (e.g., user enumeration + weak password → account takeover). |
| **ModuleResult** | The return type from every attack module: findings, state updates, metadata, errors, and warnings. |
| **OODA Loop** | Observe → Orient → Decide → Act. The decision cycle used by the agentic engine to adapt scanning strategy based on accumulated knowledge. |
| **Probe Phase** | The initial reconnaissance step that fetches the target root, records headers/cookies/forms, and builds the foundation for all subsequent modules. |
| **ScanReport** | The accumulating data structure passed between modules containing all findings, session state, metadata, and decision trail. |
| **Scope Enforcement** | The HTTP adapter mechanism that blocks outbound requests and redirects to hosts not in the configured allowlist. |
| **Token Bucket** | The rate‑limiting algorithm: a bucket fills with tokens at a fixed rate; each request consumes a token; if the bucket is empty, the request is delayed. |

---

## Appendix C: References

- [OWASP Top 10:2025 — A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Application Security Verification Standard (ASVS) V3 — Session Management](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Session-management.md)
- [OWASP Testing Guide v4.2 — Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/)
- [CWE/SANS Top 25 Most Dangerous Software Errors](https://cwe.mitre.org/top25/)
- [JWT Best Practices (IETF RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
- [OAuth 2.0 Security Best Current Practice (IETF RFC 9700)](https://datatracker.ietf.org/doc/html/rfc9700)
- [SARIF v2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3-1/)
