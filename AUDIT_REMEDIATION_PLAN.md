# auth-scan Audit Remediation Plan

Distilled from three independent audits (Markdown audit, DOCX audit, Jules `AUDIT_REPORT.md`) and verified line-by-line against the current worktree at `src/auth_scan/`. Date: 2026-05-18.

---

## Verified findings (current state in cwd)

| ID | File:line (verified) | Verified state | Source audits |
|---|---|---|---|
| **C1** Inverted password redaction | `src/auth_scan/attacks/brute.py:318` — `"password": "[REDACTED]" if not getattr(self, "_no_redact", True) else creds[1]` | **VULNERABLE, ships plaintext password** in default mode | DOCX SEC-01 |
| **C2** Broken probe timing | `src/auth_scan/core/http_client.py:378` — `duration_ms=(time.monotonic() - time.monotonic())*1000` | Always ~0 | MD FUNC-6, DOCX SEC-05 |
| **C3** Inverted lockout heuristic | `src/auth_scan/attacks/brute.py:345` — `if avg_later < avg_time * 0.3:` | Fires on speed-up, misses real lockout | DOCX FUNC-01 |
| **C4** CSRF token reused across attempts | `src/auth_scan/attacks/brute.py:119-155, 243-244` — hidden fields read once from `report.metadata["probe_forms"]` | Brute force blind against any CSRF-protected form | DOCX FUNC-02 |
| **C5** Redirects not scope-enforced | `src/auth_scan/core/http_client.py:241,268,333` — `allow_redirects=True`; scope only checked on initial URL | SSRF / out-of-scope risk | MD SEC-3 |
| **C6** Metadata + Markdown/HTML evidence not redacted | `src/auth_scan/attacks/base.py` (`ScanReport.to_dict`); `src/auth_scan/core/reporter.py:334` renders `finding.evidence` via `tojson`, bypassing Finding redaction | Secrets leak into JSON metadata, MD/HTML evidence | MD SEC-1, SEC-2 |
| **H1** `--modules all` incomplete | `src/auth_scan/cli.py:304` — expands to `["probe","jwt","session","brute"]` only | OAuth/MFA/WebSocket/API-key silently skipped | MD FUNC-1 |
| **H2** `--output` flag wiring | `src/auth_scan/cli.py` — accepts json/markdown/html/pdf/sarif but reporter dispatch incomplete | At minimum SARIF/MD/HTML dispatch needs full audit | DOCX FUNC-04 |
| **H3** Probe exception class wrong | `src/auth_scan/core/http_client.py:318` — catches custom `HttpError` after a `self.session.get(...)` that raises `requests.exceptions.RequestException` | Fallback branch never runs | MD FUNC-7 |
| **H4** Silent HTTPS→HTTP downgrade | `src/auth_scan/core/http_client.py:318-330` — replaces `https://`→`http://` with no warning, no finding | Plaintext credential exfil during scan | DOCX SEC-03 |
| **H5** Missing `ScanConfig` fields | `src/auth_scan/core/config.py` lacks `jwt_wordlist`, `no_discovery`, `no_mfa`, `oauth_scope` | mypy strict fails; config-file path silently ignores values | MD FUNC-3 |
| **H6** OAuth discovery regex uses quote as key | `src/auth_scan/attacks/oauth.py:118,121` — `endpoints[match.group(1).strip(...)]` uses captured *quote char*, not endpoint name | Discovered endpoints unusable | MD FUNC-4 |
| **H7** OAuth default scope pre-encoded | `src/auth_scan/attacks/oauth.py:390` — `"admin%20profile%20email%20openid"` then re-encoded by `requests` | Double-encoded scope = false neg/pos | MD FUNC-5 |
| **H8** Path discovery sequential | `src/auth_scan/core/path_discovery.py` — 80 paths × 3s timeout, no pool | 80-240s before any attack starts | DOCX PERF-01, MD PERF-2 |
| **M1** Bare `except Exception: pass` everywhere | brute.py, jwt_analyzer.py, http_client.py, oauth.py, session_tests.py | Hides real failures | DOCX TD-03, MD TD-4 |
| **M2** Duplicate `probe_body` scan | `src/auth_scan/attacks/api_key.py:75-94` — SCAN_LOCATIONS includes probe_body AND followed by direct scan | Duplicate findings | DOCX TD-02 |
| **M3** Hardcoded `DEFAULT_CREDENTIALS` | `src/auth_scan/attacks/brute.py:19-62` — 40 pairs in source | Secret-scanner false alarms; not user-tunable | DOCX TD-01 |
| **M4** Agentic hardcoded module set | `src/auth_scan/core/agentic.py:457` — `>= {"jwt","session","brute","oauth","mfa","api_key"}` | Plugins ignored at termination | DOCX FUNC-05 |
| **M5** alg=none keyword check fragile | `src/auth_scan/attacks/jwt_analyzer.py:198` | False neg on `"status":"unauthorized"` style errors | DOCX FUNC-06 |
| **M6** Redaction key set too narrow | `src/auth_scan/attacks/base.py` (`_redact_dict`) | Misses `id_token`, `client_secret`, `session_id`, `private_key`, `csrf_token` | MD SEC-5 |
| **M7** Request history retains raw bodies/headers | `src/auth_scan/core/http_client.py` | Future leakage path | MD SEC-4 |
| **M8** No finding deduplication | `src/auth_scan/attacks/base.py` (`add_finding`) | Risk score skewed | DOCX SEC-04 |
| **M9** README references unsupported `--output-file` | `README.md` | Quickstart errors out | MD FUNC-2 |
| **L1** Risk score non-monotonic above 20 findings | `src/auth_scan/attacks/base.py` (`risk_score`) | Score can drop as findings rise | DOCX PERF-04 |
| **L2** API-key regexes recompiled per call | `src/auth_scan/attacks/api_key.py` (`_scan_text`) | Minor perf | DOCX PERF-03 |
| **L3** Brute force adds delays outside rate limiter | `src/auth_scan/attacks/brute.py` | Unpredictable runtime | MD PERF-3 |
| **L4** JWT-cracking always-on, up to 5000 attempts | `src/auth_scan/attacks/jwt_analyzer.py` | CPU spikes; no opt-in | MD PERF-4 |
| **L5** Per-token JWT discovery probes 4 endpoints | `src/auth_scan/attacks/jwt_analyzer.py:1201-1216 ref` | Redundant traffic | DOCX PERF-02 |
| **L6** SARIF results — verify shape | `src/auth_scan/core/reporter.py:422-427` already populates `locations`; verify `rules[]`, `ruleId` per result | One audit (DOCX TD-05) flagged this incorrectly | DOCX TD-05 (partially wrong) |
| **L7** Version drift surface | `__init__.py`, `http_client.py:147` UA, `reporter.py:77,441` all hardcoded `0.1.0`; not derived from `importlib.metadata` | Cosmetic until version bumps | MD TD-1 |
| **L8** Ruff/format/mypy not clean | repo-wide | Hygiene | MD TD-2, TD-3, Jules §1, §5 |
| **L9** Output filename slug minimal | `src/auth_scan/core/reporter.py` | Edge cases | MD REP-1 |
| **L10** `endpoints_tested=0` in CLI report call | `src/auth_scan/cli.py` | Telemetry zeroed | MD REP-2 |

## Items the audits flagged but don't actually apply

- **SEC-02 first PEM path returns raw n/e** (DOCX/Jules): the broken fragment exists at `jwt_analyzer.py:333` but lines 337-353 do construct a real RSA PEM via `cryptography`. Treat as **dead-branch cleanup**, not a complete gap.
- **SARIF missing `locations` array** (DOCX TD-05): already populated at `reporter.py:422-427`. Cross-check `rules` array and per-result `ruleId` before closing.

---

## Phase 1 — Block-engagement fixes (single PR)

Do not run another engagement until these merge.

1. **C1 — Fix inverted redaction in brute.py** at `brute.py:318`. Replace with:
   ```python
   "password": creds[1] if getattr(self, "_no_redact", False) else "[REDACTED]"
   ```
   Source `_no_redact` from `config.no_redact` in `BruteForce.__init__`/`run()`. Test default-redacted + `--no-redact` plaintext.

2. **C2 — Fix probe duration**. Hoist `start = time.monotonic()` to before `self.session.get(...)`; compute `duration_ms = (time.monotonic() - start) * 1000` after parsing. Monkeypatch-based unit test.

3. **C3 — Invert lockout heuristic + add 423/keyword detection**. `if avg_later > avg_time * 1.5:` plus `status == 423` OR body keywords `["locked","suspended","disabled","too many attempts"]`. Synthetic-timings test.

4. **C4 — Refresh CSRF/hidden fields per attempt**. Before each POST, GET the form action, re-parse hidden inputs, merge over creds. Treat 403/redirect-to-login as stale-CSRF signal. vuln_app fixture serves a CSRF form that rotates token each GET; assert admin/admin discovered.

5. **C5 — Redirect scope enforcement**. `allow_redirects=False` by default. Manually follow up to N hops, calling `_check_scope(location)` and `_is_private_ip(host)` between each. Block loopback, RFC1918, link-local, cloud metadata (169.254.169.254, fd00:ec2::254). Tests for each.

6. **C6 — Redact metadata + share redaction across reporters**. In `ScanReport.to_dict(redact)` recursively `_redact_dict` `metadata`. Cap `probe_body` to a 4 KB preview + `body_sha256` + `body_length`. In `reporter.py` use `finding.to_dict(redact=self.redact)` everywhere; pass `redact` through MD/HTML/PDF/SARIF/Terminal templates. Broaden `_redact_dict` keys: `id_token`, `refresh_token`, `client_secret`, `client_id`, `session_id`, `private_key`, `csrf_token`, `authorization`, `x-api-key`, `cookie`, `set-cookie`. Value-shape redactor for JWT, `AKIA/ASIA`, `xox[abp]-`, `ghp_/gho_`. Per-format snapshot test.

**Exit criteria:** new tests pass; per-format redaction test passes; brute-force regression discovers admin/admin against CSRF-rotating fixture.

---

## Phase 2 — User-facing correctness (next sprint)

7. **H1 — `--modules all` from canonical registry**. Replace literal list in `cli.py:304` with `list(ATTACK_REGISTRY.keys())`. CLI test asserts every shipped module is present.

8. **H2 — Wire `--output` to every reporter**. Dispatch on `--output` value into `JsonReporter | MarkdownReporter | HtmlReporter | PdfReporter | SarifReporter | TerminalReporter`. Default terminal. Add `--output-file` (per README), `-` for stdout. Update README quickstart.

9. **H3/H4 — Probe exception + HTTPS downgrade**. Call `self.get(...)` in `probe()` (or catch `requests.exceptions.RequestException`). Gate fallback on `config.allow_http_fallback` (default False). On fallback: `console.warning`, append `MEDIUM` finding `HTTPS_TO_HTTP_DOWNGRADE`, record in `redirect_chain`.

10. **H5 — Add missing `ScanConfig` fields**. Declare `jwt_wordlist: str | None = None`, `no_discovery: bool = False`, `no_mfa: bool = False`, `oauth_scope: str = "admin profile email openid"`. Wire through `_dict_to_config()`, env-var overrides, `generate_default_yaml()`. Remove `getattr(config, ...)` fallbacks.

11. **H6 — Fix OAuth discovery regex** at `oauth.py:118`:
    ```python
    r'(?P<name>authorization_endpoint|token_endpoint|userinfo_endpoint|issuer)\s*[:=]\s*["\']?(?P<url>https?://[^\s"\'<,]+)'
    ```
    Use `match.group("name")` as key, `match.group("url")` as value.

12. **H7 — Fix OAuth scope default** at `oauth.py:390` → `"admin profile email openid"`. Test asserts exactly one `%20` per space in encoded query.

13. **H8 — Parallelize path discovery**. `ThreadPoolExecutor(max_workers=config.discovery_workers)` default 10. Each task calls `RateLimiter.acquire()`. Early-exit on 5 consecutive connection failures. Expose `--discovery-workers`, `--max-paths`.

14. **M2 — Remove duplicate probe_body scan** at `api_key.py:75-94`. Single-finding test.

15. **M5 — alg=none baseline comparison** at `jwt_analyzer.py:198`. Fetch protected resource with original token first; fingerprint body (length + key-set). Mark success only when forged-token response ≈ original AND status==200.

16. **M4 — Agentic termination from dynamic registry** at `agentic.py:457`: `self._modules_run >= set(self.module_map.keys())` (or terminate purely on confidence + empty gaps).

**Exit:** ruff/format clean, mypy strict clean for changed files, integration test runs `--modules all` against vuln_app and exercises every reporter without raising.

---

## Phase 3 — Hygiene, performance, and dev experience

17. **M1 — Replace bare excepts**: typed `except (requests.RequestException, ValueError):`, log at DEBUG, append `ModuleError` to `ModuleResult.errors`. `ScanReport.summary()` surfaces skipped modules + module errors. Find with `rg -n 'except Exception:\s*pass' src/`.

18. **M3 — Externalize `DEFAULT_CREDENTIALS`**: move to `src/auth_scan/data/default_creds.txt`, load with `importlib.resources`. Add `--default-creds path`. Update `pyproject.toml` `package-data`.

19. **M6 — Broaden redaction matching** (partly in C6): substring + regex for sensitive key names; redact JWT/AKIA/ghp_-shaped values regardless of key.

20. **M7 — Bound response capture in HTTPClient history**: `body_preview` (≤4 KB), `body_sha256`, `body_length`, `content_type`. Full-body capture only behind `--debug-unsafe-capture`.

21. **M8 — Dedup findings in `add_finding`**: hash on `(module, title, endpoint, frozenset(evidence.items()))`. On collision increment `occurrence_count`.

22. **M9 — Fix README quickstart**: match wired flags; add "Reporters" table with each `--output` value.

23. **L1 — Replace risk score formula**: `score = min(100, sum(f.severity.numeric for f in findings) * 5)` (or CVSS-style). Property test: score monotonically nondecreasing as findings append.

24. **L2 — Precompile API-key regexes** at module load:
    ```python
    COMPILED_PATTERNS = [(label, re.compile(p), risk) for label, p, risk in API_KEY_PATTERNS]
    ```

25. **L3 — Centralize throttling**: remove fixed `time.sleep` from brute-force; keep `Retry-After` honoring inside rate limiter.

26. **L4 — Gate JWT HMAC cracking** behind `--jwt-crack` and `--jwt-crack-max-attempts` (default off). Report elapsed cracking time per token.

27. **L5 — Cache per-target JWT discovery**: probe 4 endpoints once before the token loop in `_discover_jwts`.

28. **L6 — Re-verify SARIF shape**: confirm `runs[0].tool.driver.rules[]` populated (ruleId per finding maps to a rule). Validate with `npx @microsoft/sarif-multitool validate`.

29. **L7 — Single version source**: `__version__ = importlib.metadata.version("auth-scan")` in `__init__.py`; UA + reporter footers read from it. Remove hardcoded `"0.1.0"` literals.

30. **L8 — Restore quality gates**:
    - `ruff format .` then `ruff check . --fix`; manually clean remaining ~199 lints.
    - `mypy --strict src/` clean; add `types-PyYAML` to dev extras.
    - `Makefile`/`tox.ini`: `make test`, `make lint`, `make typecheck`.
    - CI matrix on Python 3.11/3.12 (decide on 3.13/3.14 — currently `requires-python = ">=3.10"`).
    - CI: pytest with `[dev]` installed, ruff, mypy, sarif-multitool validate on a sample report.

31. **L9 — Stricter output slug** in `reporter.py`:
    ```python
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    suffix = hashlib.sha1(target.encode()).hexdigest()[:8]
    filename = f"{slug[:80]}_{suffix}.{ext}"
    ```

32. **L10 — Wire endpoint counts**: add `ScanReport.endpoints_tested: int` populated by engine; pass through to reporters instead of `0`.

---

## Suggested PR breakdown

| PR | Scope | Why grouped |
|---|---|---|
| **PR-1** Phase 1 critical hotfixes (C1–C6) | brute.py + http_client.py + base.py + reporter.py + tests | All block engagement |
| **PR-2** CLI/config completeness (H1, H2, H5, M9) | cli.py + config.py + README.md | All move flags from documented → working |
| **PR-3** HTTP fallback + redirect safety (H3, H4) | http_client.py | Risky surface, isolate |
| **PR-4** OAuth correctness (H6, H7) | oauth.py | Module-local |
| **PR-5** Path discovery concurrency (H8) | path_discovery.py | Perf-only |
| **PR-6** Functional improvements (M2, M4, M5) | api_key.py, agentic.py, jwt_analyzer.py | Logic |
| **PR-7** Error-handling sweep (M1) | repo-wide | Mechanical, single pass |
| **PR-8** Credentials + dedup + body bounds (M3, M6, M7, M8) | brute.py, base.py, http_client.py + new `data/` | |
| **PR-9** Quality gates + version (L1–L10) | infra/style | |

PR-5 and PR-7 can run in parallel with PR-2/3/4 (different files).

## Test scaffolding to add

- `tests/test_redaction.py` — parameterized over (reporter, secret-in-metadata, secret-in-evidence) × (redact, no-redact).
- `tests/test_scope.py` — redirect chains hitting external, loopback, RFC1918, link-local.
- `tests/integration/test_vuln_app.py` — `--modules all` against `tests/fixtures/vuln_app/`, every module emits at least one expected finding (incl. CSRF-rotating login form).
- `tests/test_cli_dispatch.py` — every `--output` value writes a valid file of the expected format.
- SARIF validation test piping report through `sarif-multitool` (skip if absent in CI).
