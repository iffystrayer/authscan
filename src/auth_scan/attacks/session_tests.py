"""Session management vulnerability tests."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from auth_scan.attacks.base import (
    BaseAttackModule,
    Finding,
    ModuleResult,
    ScanReport,
    Severity,
)
from auth_scan.core.session import (
    CookieAnalysis,
    analyze_session_id_entropy,
    find_session_ids_in_content,
)


class SessionTester(BaseAttackModule):
    """Test session management for common vulnerabilities.

    Covers:
    - FR-ST-001: Cookie attribute analysis (HttpOnly, Secure, SameSite, Domain, Path, Max-Age)
    - FR-ST-002: Session fixation test
    - FR-ST-003: Session invalidation after logout
    - FR-ST-004: CSRF token absence
    - FR-ST-005: Cookie scope analysis
    - FR-ST-006: Session ID in URL detection
    - FR-ST-007: Session ID entropy analysis
    """

    name = "session"
    description = "Test session management for common vulnerabilities"
    version = "1.0.0"
    priority = 20

    def run(
        self,
        target: str,
        http_client: Any,
        report: ScanReport,
        config: Any,
    ) -> ModuleResult:
        result = ModuleResult()
        is_https = target.startswith("https://")

        # FR-ST-001: Analyze cookies from probe
        probe_cookies = report.metadata.get("probe_cookies", {})
        set_cookie_headers = report.metadata.get("set_cookie_headers", [])

        cookie_analyses: list[CookieAnalysis] = []

        # Parse cookies from probe metadata
        for name, value in probe_cookies.items():
            analysis = CookieAnalysis.from_requests_cookie(name, value)
            cookie_analyses.append(analysis)

        # Also check raw Set-Cookie headers if available
        for header_value in set_cookie_headers:
            parts = header_value.split(";", 1)
            name_val = parts[0].strip().split("=", 1)
            if len(name_val) == 2:
                name, value = name_val
                analysis = CookieAnalysis(
                    name=name,
                    value=value,
                )
                # Parse attributes from the header
                for attr in parts[1:]:
                    attr = attr.strip()
                    attr_lower = attr.lower()
                    if attr_lower == "httponly":
                        analysis.http_only = True
                    elif attr_lower == "secure":
                        analysis.secure = True
                    elif attr_lower.startswith("samesite="):
                        analysis.same_site = attr.split("=", 1)[1]
                    elif attr_lower.startswith("domain="):
                        analysis.domain = attr.split("=", 1)[1]
                    elif attr_lower.startswith("path="):
                        analysis.path = attr.split("=", 1)[1]
                    elif attr_lower.startswith("max-age="):
                        try:
                            analysis.max_age = int(attr.split("=", 1)[1])
                        except ValueError:
                            pass
                    elif attr_lower.startswith("expires="):
                        analysis.expires = attr.split("=", 1)[1]
                analysis._analyze()
                cookie_analyses.append(analysis)

        if not cookie_analyses:
            result.findings.append(Finding(
                title="No Session Cookies Found",
                description="No cookies were set by the server during probing. "
                "The target may use stateless auth (JWT in Authorization header) or "
                "a non-cookie session mechanism.",
                severity=Severity.INFO,
                module_name=self.name,
                tags=["session"],
            ))
            return result

        # FR-ST-001: Report cookie attribute issues
        for analysis in cookie_analyses:
            for issue in analysis.issues:
                sev = Severity.HIGH if "Session cookie" in issue or "HttpOnly" in issue else Severity.MEDIUM
                if "missing Secure" in issue.lower() and not is_https:
                    sev = Severity.LOW  # Less critical on HTTP
                result.findings.append(Finding(
                    title=f"Cookie Security Issue: {analysis.name}",
                    description=issue,
                    severity=sev,
                    evidence={
                        "cookie_name": analysis.name,
                        "http_only": analysis.http_only,
                        "secure": analysis.secure,
                        "same_site": analysis.same_site or "not set",
                        "domain": analysis.domain,
                        "path": analysis.path,
                        "is_session": analysis.is_session_cookie,
                    },
                    remediation=(
                        "Set Secure, HttpOnly, and SameSite=Strict/Lax on all cookies, "
                        "especially session cookies."
                    ),
                    module_name=self.name,
                    tags=["session", "cookies"],
                ))

        # FR-ST-002: Session fixation test
        fixation_findings = self._test_session_fixation(target, http_client, report)
        result.findings.extend(fixation_findings)

        # FR-ST-003: Session invalidation test
        invalidation_findings = self._test_session_invalidation(target, http_client, report)
        result.findings.extend(invalidation_findings)

        # FR-ST-004: CSRF token check
        csrf_findings = self._check_csrf_tokens(report)
        result.findings.extend(csrf_findings)

        # FR-ST-006: Session ID in URL
        url_session_findings = self._check_url_session_ids(report)
        result.findings.extend(url_session_findings)

        # FR-ST-007: Session ID entropy analysis
        entropy_findings = self._analyze_entropy(cookie_analyses, probe_cookies)
        result.findings.extend(entropy_findings)

        # FR-ST-005: Cookie scope (simplified check)
        scope_findings = self._check_cookie_scope(cookie_analyses, target)
        result.findings.extend(scope_findings)

        result.state_update["sessions_analyzed"] = len(cookie_analyses)
        return result

    def _test_session_fixation(
        self, target: str, http_client: Any, report: ScanReport,
    ) -> list[Finding]:
        """FR-ST-002: Test if the server accepts a pre-authentication session ID."""
        findings: list[Finding] = []

        # Find a session cookie from probe
        probe_cookies = report.metadata.get("probe_cookies", {})
        session_cookies = [
            name for name in probe_cookies
            if any(h in name.lower() for h in ["session", "sid", "sess", "auth"])
        ]

        if not session_cookies:
            return findings

        cookie_name = session_cookies[0]
        fixed_value = "fixation-test-session-id-12345"

        # Make a request with a fixed session ID
        try:
            resp = http_client.get(
                "/",
                cookies={cookie_name: fixed_value},
            )
            # The server should either reject or issue a new session
            # If it accepts and reflects our value, it's vulnerable
            response_cookies = dict(resp.cookies)
            if cookie_name in response_cookies and response_cookies[cookie_name] == fixed_value:
                findings.append(Finding(
                    title="Session Fixation Vulnerability",
                    description=(
                        f"The server accepted and retained a pre-set session ID "
                        f"('{cookie_name}={fixed_value[:20]}...'). "
                        "An attacker can set a known session ID in a victim's browser "
                        "and hijack their session after login."
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "cookie_name": cookie_name,
                        "fixed_value": fixed_value[:30] + "...",
                        "accepted": True,
                    },
                    remediation=(
                        "Always issue a new session ID upon successful authentication. "
                        "Invalidate the old session ID."
                    ),
                    cwe_id="CWE-384",
                    module_name=self.name,
                    confidence=0.85,
                    tags=["session", "fixation"],
                ))
        except Exception:
            pass

        return findings

    def _test_session_invalidation(
        self, target: str, http_client: Any, report: ScanReport,
    ) -> list[Finding]:
        """FR-ST-003: Test if session is properly invalidated after logout."""
        findings: list[Finding] = []

        # Discover logout endpoint
        probe_body = report.metadata.get("probe_body", "")
        logout_urls: list[str] = []

        for match in re.finditer(
            r'href=["\']([^"\']*logout[^"\']*)["\']',
            probe_body,
            re.IGNORECASE,
        ):
            logout_urls.append(match.group(1))
        for match in re.finditer(
            r'href=["\']([^"\']*sign[_-]?out[^"\']*)["\']',
            probe_body,
            re.IGNORECASE,
        ):
            logout_urls.append(match.group(1))

        if not logout_urls:
            # Try common logout paths
            logout_urls = ["/logout", "/signout", "/sign-out", "/auth/logout"]

        for logout_url in logout_urls[:2]:
            try:
                # Get current cookies
                probe_cookies = report.metadata.get("probe_cookies", {})
                # Make a request before logout to establish session
                resp_before = http_client.get("/")
                # Perform logout
                resp_logout = http_client.get(logout_url)
                # Try to use same cookies after logout
                resp_after = http_client.get("/")
                # If both before and after give similar responses with same cookies,
                # session may not be invalidated
                if (
                    resp_before.status_code == resp_after.status_code == 200
                    and len(resp_after.text) == len(resp_before.text)
                ):
                    findings.append(Finding(
                        title="Session Not Invalidated on Logout",
                        description=(
                            f"After requesting {logout_url}, the session appeared to remain active. "
                            "The server does not properly invalidate sessions on logout."
                        ),
                        severity=Severity.HIGH,
                        evidence={
                            "logout_url": logout_url,
                            "before_status": resp_before.status_code,
                            "after_status": resp_after.status_code,
                            "response_same_length": len(resp_after.text) == len(resp_before.text),
                        },
                        remediation="Destroy the session server-side on logout. "
                        "Clear the session cookie with Set-Cookie: session=; Max-Age=0.",
                        cwe_id="CWE-613",
                        module_name=self.name,
                        confidence=0.7,
                        tags=["session", "invalidation"],
                    ))
                    break  # Found one, no need to check more
            except Exception:
                pass

        return findings

    def _check_csrf_tokens(self, report: ScanReport) -> list[Finding]:
        """FR-ST-004: Check for CSRF tokens on state-changing forms."""
        findings: list[Finding] = []
        forms = report.metadata.get("probe_forms", [])
        if not forms:
            forms = report.metadata.get("forms", [])

        for form in forms:
            method = form.get("method", "GET").upper()
            if method in ("POST", "PUT", "DELETE", "PATCH"):
                inputs = form.get("inputs", [])
                has_csrf = any(
                    "csrf" in (inp.get("name") or "").lower()
                    or "xsrf" in (inp.get("name") or "").lower()
                    or "_token" == (inp.get("name") or "").lower()
                    for inp in inputs
                )
                if not has_csrf:
                    findings.append(Finding(
                        title=f"Missing CSRF Token on {method} Form",
                        description=(
                            f"Form at action='{form.get('action', '/')}' with method={method} "
                            "has no CSRF token. This makes it vulnerable to cross-site "
                            "request forgery attacks."
                        ),
                        severity=Severity.MEDIUM,
                        evidence={
                            "form_action": form.get("action", ""),
                            "form_method": method,
                            "input_names": [inp.get("name") for inp in inputs],
                        },
                        remediation="Add a CSRF token to all state-changing forms. "
                        "Use framework-provided CSRF protection.",
                        cwe_id="CWE-352",
                        module_name=self.name,
                        confidence=0.85,
                        tags=["session", "csrf"],
                    ))

        return findings

    def _check_url_session_ids(self, report: ScanReport) -> list[Finding]:
        """FR-ST-006: Check for session IDs in URL query parameters."""
        findings: list[Finding] = []
        probe_body = report.metadata.get("probe_body", "")

        url_sessions = find_session_ids_in_content(probe_body)
        for entry in url_sessions:
            findings.append(Finding(
                title="Session ID in URL",
                description=(
                    f"Session token '{entry['token_name']}' found in URL. "
                    "Session IDs in URLs are logged in server logs, browser history, "
                    "and leaked via Referer headers."
                ),
                severity=Severity.HIGH,
                evidence={
                    "token_name": entry["token_name"],
                    "token_value": "[REDACTED]",
                },
                remediation="Use HttpOnly, Secure cookies for session tokens. "
                "Never pass session IDs in URL parameters.",
                cwe_id="CWE-598",
                module_name=self.name,
                confidence=0.98,
                tags=["session", "url-token"],
            ))

        return findings

    def _analyze_entropy(
        self, cookie_analyses: list[CookieAnalysis], probe_cookies: dict[str, str],
    ) -> list[Finding]:
        """FR-ST-007: Analyze session ID entropy."""
        findings: list[Finding] = []
        for analysis in cookie_analyses:
            if analysis.is_session_cookie and analysis.value:
                entropy_result = analyze_session_id_entropy(analysis.value)
                if entropy_result.get("assessment") == "weak":
                    findings.append(Finding(
                        title="Weak Session ID Entropy",
                        description=(
                            f"Session cookie '{analysis.name}' has low entropy "
                            f"({entropy_result.get('entropy', 0):.1f} bits, "
                            f"length={entropy_result.get('length', 0)}). "
                            f"This makes session IDs predictable."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=entropy_result,
                        remediation=(
                            "Use a cryptographically secure random number generator (CSPRNG) "
                            "to generate session IDs with at least 128 bits of entropy."
                        ),
                        cwe_id="CWE-330",
                        module_name=self.name,
                        confidence=0.8,
                        tags=["session", "entropy"],
                    ))

        return findings

    def _check_cookie_scope(
        self, cookie_analyses: list[CookieAnalysis], target: str,
    ) -> list[Finding]:
        """FR-ST-005: Check for overly broad cookie scope."""
        findings: list[Finding] = []

        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname or ""

        for analysis in cookie_analyses:
            # Check for overly broad domain
            if analysis.domain:
                domain_parts = analysis.domain.lstrip(".").split(".")
                host_parts = hostname.split(".")

                # If cookie domain is a parent domain (fewer parts), it leaks to subdomains
                if len(domain_parts) < len(host_parts) and analysis.is_session_cookie:
                    findings.append(Finding(
                        title="Broad Cookie Domain Scope",
                        description=(
                            f"Session cookie '{analysis.name}' has Domain={analysis.domain}, "
                            f"which is broader than the current host ({hostname}). "
                            "This cookie will be sent to subdomains, increasing attack surface."
                        ),
                        severity=Severity.MEDIUM,
                        evidence={
                            "cookie_name": analysis.name,
                            "cookie_domain": analysis.domain,
                            "host": hostname,
                        },
                        remediation="Set cookie Domain to the most specific hostname possible. "
                        "Avoid using a leading dot or parent domains.",
                        module_name=self.name,
                        confidence=0.9,
                        tags=["session", "scope"],
                    ))

            # Check for root path
            if analysis.path in ("/", "") and analysis.is_session_cookie:
                pass  # Root path is normal for session cookies

        return findings
