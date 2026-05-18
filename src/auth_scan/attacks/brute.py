"""Brute force and credential testing module."""
from __future__ import annotations

import concurrent.futures
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from auth_scan.attacks.base import (
    BaseAttackModule,
    Finding,
    ModuleResult,
    ScanReport,
    Severity,
)

# Built-in default credential pairs for quick testing
DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "password123"),
    ("admin", "123456"),
    ("admin", "letmein"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("root", "admin"),
    ("user", "user"),
    ("user", "password"),
    ("user", "123456"),
    ("test", "test"),
    ("test", "password"),
    ("guest", "guest"),
    ("guest", "password"),
    ("operator", "operator"),
    ("manager", "manager"),
    ("sa", "sa"),
    ("demo", "demo"),
    ("info", "info"),
    ("temp", "temp"),
    ("sysadmin", "sysadmin"),
    ("supervisor", "supervisor"),
    ("default", "default"),
    ("dev", "dev"),
    ("backup", "backup"),
    ("support", "support"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("oracle", "oracle"),
    ("ftp", "ftp"),
    ("tomcat", "tomcat"),
    ("jenkins", "jenkins"),
    ("service", "service"),
    ("admin", ""),  # empty password
    ("user", ""),
    ("test", ""),
    ("administrator", ""),
]


class BruteForce(BaseAttackModule):
    """Credential brute-force and default credential testing.

    Covers:
    - FR-BF-001: Auto-discover login forms from probe phase
    - FR-BF-002: Accept --wordlist and --username-wordlist
    - FR-BF-003: Built-in small default wordlist
    - FR-BF-004: Account lockout detection
    - FR-BF-005: Rate limit detection
    - FR-BF-006: User enumeration detection
    """

    name = "brute"
    description = "Test for weak, default, and common credentials"
    version = "1.0.0"
    priority = 30

    # Set in run() from config.no_redact. Default redacts (safe).
    _no_redact: bool = False

    def run(
        self,
        target: str,
        http_client: Any,
        report: ScanReport,
        config: Any,
    ) -> ModuleResult:
        result = ModuleResult()

        # Track redaction mode from config so evidence dicts can honor --no-redact.
        # Default to redacted when the attribute is absent.
        self._no_redact: bool = bool(getattr(config, "no_redact", False))

        # FR-BF-001: Discover login forms
        login_forms = self._discover_login_forms(report)
        if not login_forms:
            result.findings.append(Finding(
                title="No Login Forms Found",
                description="Cannot test credentials without discovering a login form. "
                "Check if the target uses a non-standard login mechanism.",
                severity=Severity.INFO,
                module_name=self.name,
                tags=["brute", "discovery"],
            ))
            return result

        # Load wordlists
        credentials = self._load_credentials(
            getattr(config, "wordlist", ""),
            getattr(config, "user_wordlist", ""),
        )

        # Test each login form
        for form in login_forms:
            form_result = self._test_form(form, credentials, target, http_client)
            result.findings.extend(form_result.findings)
            result.warnings.extend(form_result.warnings)
            result.metadata.update(form_result.metadata)

        return result

    def _discover_login_forms(self, report: ScanReport) -> list[dict[str, Any]]:
        """FR-BF-001: Extract login forms from probe metadata."""
        forms = report.metadata.get("probe_forms", [])
        if not forms:
            forms = report.metadata.get("forms", [])

        login_forms: list[dict[str, Any]] = []
        for form in forms:
            inputs = form.get("inputs", [])
            has_password = any(inp.get("type") == "password" for inp in inputs)
            has_text = any(inp.get("type") in ("text", "email", "") for inp in inputs)
            if has_password and has_text:
                # Identify the username and password fields
                username_fields = [
                    inp["name"] for inp in inputs
                    if inp["type"] in ("text", "email", "") and inp["name"]
                ]
                password_fields = [
                    inp["name"] for inp in inputs
                    if inp["type"] == "password" and inp["name"]
                ]
                # Find CSRF/hidden fields
                hidden_fields = [
                    {"name": inp["name"], "value": inp.get("value", "")}
                    for inp in inputs
                    if inp["type"] == "hidden" and inp["name"]
                ]
                login_forms.append({
                    "action": form.get("action", ""),
                    "method": form.get("method", "POST"),
                    "username_field": username_fields[0] if username_fields else "username",
                    "password_field": password_fields[0] if password_fields else "password",
                    "hidden_fields": hidden_fields,
                    "inputs": inputs,
                })

        return login_forms

    def _load_credentials(
        self, wordlist_path: str, user_wordlist_path: str,
    ) -> list[tuple[str, str]]:
        """FR-BF-002, FR-BF-003: Load credentials from wordlists or defaults."""
        usernames: list[str] = []
        passwords: list[str] = []

        # Load username wordlist
        if user_wordlist_path and Path(user_wordlist_path).exists():
            usernames = self._read_wordlist(user_wordlist_path)

        # Load password wordlist
        if wordlist_path and Path(wordlist_path).exists():
            passwords = self._read_wordlist(wordlist_path)

        # FR-BF-003: Use built-in defaults when no wordlists provided
        if not usernames and not passwords:
            return list(DEFAULT_CREDENTIALS)

        # Use discovered usernames + wordlist passwords
        if not usernames:
            usernames = list(set(u for u, _ in DEFAULT_CREDENTIALS))[:10]
        if not passwords:
            passwords = list(set(p for _, p in DEFAULT_CREDENTIALS))[:50]

        # Generate combinations (cartesian product, capped)
        credentials: list[tuple[str, str]] = []
        for username in usernames[:20]:
            for password in passwords[:100]:
                credentials.append((username, password))
                if len(credentials) >= 500:
                    return credentials
        return credentials

    @staticmethod
    def _read_wordlist(path: str) -> list[str]:
        """Read a wordlist file, one entry per line."""
        entries: list[str] = []
        try:
            with open(path) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        entries.append(stripped)
        except Exception:
            pass
        return entries

    def _test_form(
        self,
        form: dict[str, Any],
        credentials: list[tuple[str, str]],
        target: str,
        http_client: Any,
    ) -> ModuleResult:
        """Test credentials against a login form."""
        result = ModuleResult()
        action = form["action"]
        method = form["method"]
        username_field = form["username_field"]
        password_field = form["password_field"]
        hidden_fields = form.get("hidden_fields", [])

        # Build full action URL
        if action.startswith(("http://", "https://")):
            form_url = action
        else:
            form_url = urljoin(target + "/", action.lstrip("/"))

        result.metadata["form_url"] = form_url
        result.metadata["credentials_tested"] = 0

        # Variables for detection logic
        response_times: list[float] = []
        error_patterns: dict[str, int] = {}
        found_valid = False
        consecutive_429 = 0
        lockout_detected = False

        def test_single(creds: tuple[str, str]) -> dict[str, Any] | None:
            nonlocal lockout_detected
            if lockout_detected:
                return None

            username, password = creds
            data: dict[str, str] = {username_field: username, password_field: password}
            for hf in hidden_fields:
                data[hf["name"]] = hf["value"]

            start = time.monotonic()
            try:
                if method == "POST":
                    resp = http_client.post(form_url, data=data)
                else:
                    resp = http_client.get(f"{form_url}?{username_field}={username}&{password_field}={password}")

                elapsed = (time.monotonic() - start) * 1000
                return {
                    "username": username,
                    "password": password,
                    "status": resp.status_code,
                    "body_length": len(resp.text),
                    "body_preview": resp.text[:200].lower(),
                    "headers": dict(resp.headers),
                    "duration_ms": elapsed,
                }
            except Exception:
                return None

        # Run credential tests sequentially for now (safe for rate limit detection)
        for i, creds in enumerate(credentials):
            if lockout_detected:
                break
            if found_valid and i > 20:
                break  # We found valid creds; stop after a few more

            entry = test_single(creds)
            if entry is None:
                continue

            result.metadata["credentials_tested"] = i + 1
            response_times.append(entry["duration_ms"])

            # FR-BF-005: Rate limit detection
            if entry["status"] == 429:
                consecutive_429 += 1
                result.warnings.append(
                    f"Rate limiting detected (429 response). Consider using --rate-limit flag."
                )
                if consecutive_429 >= 2:
                    break
                time.sleep(1)
                continue
            else:
                consecutive_429 = 0

            # Check for Retry-After header
            retry_after = entry["headers"].get("Retry-After", "")
            if retry_after:
                result.warnings.append(f"Rate limiting detected: Retry-After={retry_after}")
                try:
                    time.sleep(int(retry_after))
                except ValueError:
                    time.sleep(1)

            # Detect success (heuristic: 200/302 status + no error keywords)
            body = entry["body_preview"]
            error_keywords = [
                "invalid", "incorrect", "wrong", "failed", "error",
                "try again", "not found", "does not exist", "unauthorized",
            ]
            is_error = any(kw in body for kw in error_keywords)

            if entry["status"] in (200, 302) and not is_error:
                found_valid = True
                password_for_description = creds[1] if self._no_redact else "[REDACTED]"
                result.findings.append(Finding(
                    title="Weak/Default Credentials Accepted",
                    description=(
                        f"Login succeeded with credentials: {creds[0]}:{password_for_description}"
                    ),
                    severity=Severity.CRITICAL,
                    evidence={
                        "username": creds[0],
                        "password": creds[1] if self._no_redact else "[REDACTED]",
                        "status": entry["status"],
                        "body_preview": entry["body_preview"][:200],
                        "form_url": form_url,
                    },
                    remediation=f"Change the password for user '{creds[0]}' immediately. "
                    f"Enforce a strong password policy.",
                    cwe_id="CWE-1392",
                    cvss_score=9.8,
                    module_name=self.name,
                    confidence=0.95,
                    tags=["brute", "default-credentials"],
                ))
                # Continue to detect rate limiting but don't test all

            # Track error messages for user enumeration (FR-BF-006)
            for kw in error_keywords:
                if kw in body:
                    error_patterns[kw] = error_patterns.get(kw, 0) + 1

            time.sleep(0.05)  # Minimal delay between requests (rate limiter handles rest)

        # FR-BF-004: Lockout detection
        if response_times:
            avg_time = sum(response_times[:10]) / min(10, len(response_times))
            later_times = response_times[-5:] if len(response_times) >= 10 else response_times
            avg_later = sum(later_times) / len(later_times)
            if avg_later < avg_time * 0.3:  # Significant speedup might indicate lockout
                result.findings.append(Finding(
                    title="Potential Account Lockout Detected",
                    description=(
                        "Response times decreased significantly after multiple attempts, "
                        "which may indicate account lockout is occurring."
                    ),
                    severity=Severity.INFO,
                    evidence={
                        "initial_avg_ms": f"{avg_time:.0f}",
                        "later_avg_ms": f"{avg_later:.0f}",
                    },
                    remediation="Verify account lockout behavior. This is a good security measure, "
                    "but ensure proper lockout duration and user notification.",
                    module_name=self.name,
                    tags=["brute", "lockout"],
                ))

        # FR-BF-006: User enumeration detection (enhanced)
        if len(error_patterns) >= 2:
            unique_errors = len(error_patterns)
            if unique_errors >= 2:
                result.findings.append(Finding(
                    title="User Enumeration Possible",
                    description=(
                        f"Different error patterns detected ({unique_errors} unique responses), "
                        "which may allow attackers to enumerate valid usernames."
                    ),
                    severity=Severity.MEDIUM,
                    evidence={
                        "error_patterns_detected": list(error_patterns.keys()),
                        "unique_count": unique_errors,
                    },
                    remediation="Use a generic error message for all authentication failures "
                    "(e.g., 'Invalid username or password').",
                    cwe_id="CWE-204",
                    module_name=self.name,
                    confidence=0.7,
                    tags=["brute", "user-enumeration"],
                ))

        # Enhanced: Timing-based enumeration detection
        if len(response_times) >= 3:
            sorted_times = sorted(response_times)
            p25_idx = max(0, len(sorted_times) // 4)
            p75_idx = min(len(sorted_times) - 1, 3 * len(sorted_times) // 4)
            iqr = sorted_times[p75_idx] - sorted_times[p25_idx]
            if iqr > 200:  # Significant timing variance (>200ms)
                result.findings.append(Finding(
                    title="User Enumeration: Timing-Based Discrepancy",
                    description=(
                        f"Response times varied significantly (IQR={iqr:.0f}ms). "
                        "This may indicate different processing for valid vs. invalid users."
                    ),
                    severity=Severity.MEDIUM,
                    evidence={
                        "response_time_spread_ms": f"{iqr:.0f}",
                        "min_ms": f"{sorted_times[0]:.0f}",
                        "max_ms": f"{sorted_times[-1]:.0f}",
                    },
                    remediation="Ensure consistent response times regardless of username validity.",
                    cwe_id="CWE-204",
                    module_name=self.name,
                    confidence=0.5,
                    tags=["brute", "user-enumeration", "timing"],
                ))

        if not found_valid and result.metadata.get("credentials_tested", 0) > 0:
            result.findings.append(Finding(
                title="No Default Credentials Found",
                description=f"Tested {result.metadata['credentials_tested']} credentials "
                f"against {form_url}. No weak credentials detected.",
                severity=Severity.INFO,
                evidence={"credentials_tested": result.metadata["credentials_tested"]},
                module_name=self.name,
                tags=["brute"],
            ))

        return result
