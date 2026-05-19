# Integration Targets

This document lists the deliberately-vulnerable applications we recommend running auth-scan against. The first one is bundled and exercised in CI; the rest are external, opt-in, and meant for ad-hoc validation when you're cutting a release or chasing a regression.

> **All of these are intentionally insecure.** Do not deploy any of them on a public network or anywhere they might receive non-test traffic.

## 1. Bundled — `tests/fixtures/vuln_app/`

A Flask app of ~600 lines, ships in this repo. Run via `make integration` (or `pytest -m slow tests/integration/`).

| Auth-scan module | What it should find on vuln_app |
|---|---|
| `probe` | Missing HSTS / CSP / X-Frame-Options |
| `session` | Cookies missing HttpOnly / Secure / SameSite; session fixation |
| `jwt` | Cookie-borne JWT with weak HS256 secret; `alg=none` accepted at `/api/profile` and `/api/protected` |
| `brute` | `admin:admin`, `user:password`, `test:test`, `guest:guest`; user enumeration via distinct errors; CSRF rotation handled on `/csrf-login` |
| `oauth` | Endpoints discovered via `/.well-known/openid-configuration`; missing state, implicit-flow, missing PKCE |
| `api_key` | Synthesised key in `/config` page source |
| `mfa` | Parameter pollution on `/mfa/verify` |
| `websocket` | Token in WebSocket URL |

It also publishes a live JWKS at `/api/jwks.json` with a matching RS256 issuer at `/api/rs256-token` so the key-confusion path is reachable end-to-end.

The integration suite is **fast** (~5 s total including Flask startup) and runs on every push to `main`. It also runs on PRs that carry the `integration` label.

## 2. External — OWASP crAPI (recommended next step)

[OWASP crAPI](https://github.com/OWASP/crAPI) is a microservice-based intentionally-vulnerable API designed by OWASP. It exposes real OAuth flows, JWTs signed with weak keys, MFA bypass paths, and BOLA / mass-assignment defects. Much closer to a production-shaped target than anything we can sensibly bundle.

### Running it

```bash
# One-time setup
make scan-crapi-setup    # clones crAPI into ~/.cache/authscan-targets/crAPI

# Start the stack (8 services: auth, identity, community, workshop,
# mongo, postgres, mailhog, gateway). ~2 minutes on a warm cache.
make scan-crapi-up

# Run a full scan and dump an HTML report
make scan-crapi          # writes /tmp/authscan-crapi.html

# Tear down when finished
make scan-crapi-down
```

What we expect auth-scan to find on crAPI:
- `jwt` module: `alg=none` accepted on `/identity/api/v2/user/dashboard`
- `jwt` module: JKU-confusion variant on `/identity/api/auth/v3/check-otp`
- `brute` module: weak password policy on registration
- `session` module: JWT in `Authorization` header but also leaked into query strings on some endpoints
- `oauth` module: missing PKCE on the OAuth callback path
- `api_key` module: hardcoded API keys in the static JS bundle

This is **not** wired into CI — the crAPI stack is too heavy for our matrix and changes upstream too often. Use it locally before tagging a release.

## 3. External — PortSwigger Web Security Academy

PortSwigger hosts a free [Authentication](https://portswigger.net/web-security/authentication) lab catalogue. Each lab is a one-shot vulnerable target — there's no "scan all the labs" mode — but the labs are excellent for validating specific auth-scan modules:

| Lab | auth-scan module exercised |
|---|---|
| "JWT authentication bypass via unverified signature" | `jwt` (alg=none) |
| "JWT authentication bypass via flawed signature verification" | `jwt` (key confusion) |
| "JWT authentication bypass via jwk header injection" | `jwt` (JKU/x5u variants — not in v0.2.0; future work) |
| "OAuth account hijacking via redirect_uri" | `oauth` (redirect_uri validation) |
| "Forced OAuth profile linking" | `oauth` (missing state) |
| "Stealing OAuth access tokens via an open redirect" | `oauth` + redirect-scope test |
| "Username enumeration via different responses" | `brute` (FR-BF-006) |
| "Username enumeration via response timing" | `brute` (timing-based) |

Each lab gives you a unique URL valid for ~30 minutes. Run with `auth-scan <lab-url> --modules <relevant module>` and inspect the report. Useful for hand-validating a fix or regression.

## 4. External — Damn Vulnerable Web Application (DVWA), NodeGoat, Juice Shop

These cover ground auth-scan is **not** designed for (mostly SQLi / XSS / mass-assignment), but they're useful as **negative tests**: run auth-scan and confirm it doesn't fire on issues outside its remit, then audit the report for any genuine auth findings the apps happen to carry.

## Adding a new target

When you find another publicly-available vulnerable target that exercises an auth-scan code path, please:

1. Add a row to the table above with the URL, install command, expected findings.
2. If it's lightweight enough to docker-compose-up in <5 minutes, consider adding a `make scan-<name>` target. Otherwise just document it.
3. Do **not** wire it into CI without team agreement — the GitHub Actions runners shouldn't pay startup cost for every external target.
