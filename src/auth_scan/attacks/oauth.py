"""OAuth 2.0 / OpenID Connect flow testing module."""

from __future__ import annotations

import logging
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

# Common OAuth/OIDC discovery paths
OAUTH_WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/.well-known/webfinger",
    "/oauth",
    "/oauth2",
    "/oidc",
    "/auth",
    "/authorize",
    "/token",
]

# OAuth-related keywords in page content
OAUTH_KEYWORDS = [
    "oauth",
    "oidc",
    "openid",
    "openid-connect",
    "authorization_endpoint",
    "token_endpoint",
    "client_id",
    "redirect_uri",
    "response_type",
    "grant_type",
    "authorization_code",
    "pkce",
    "code_challenge",
]

_log = logging.getLogger(__name__)


class OAuthTester(BaseAttackModule):
    """Test OAuth 2.0 / OIDC flows for common misconfigurations.

    Covers:
    - OAuth/OIDC endpoint discovery
    - Missing state parameter (CSRF)
    - Open redirect_uri validation
    - response_type=token (implicit flow)
    - Missing PKCE for public clients
    - Client secret exposure
    """

    name = "oauth"
    description = "Test OAuth 2.0 / OpenID Connect flows for misconfigurations"
    version = "1.0.0"
    priority = 40

    def run(
        self,
        target: str,
        http_client: Any,
        report: ScanReport,
        config: Any,
    ) -> ModuleResult:
        result = ModuleResult()

        # Detect OAuth presence
        oauth_endpoints = self._discover_oauth_endpoints(target, http_client, report)
        if not oauth_endpoints:
            result.findings.append(
                Finding(
                    title="No OAuth/OIDC Endpoints Found",
                    description="No OAuth 2.0 or OpenID Connect endpoints were detected.",
                    severity=Severity.INFO,
                    module_name=self.name,
                    tags=["oauth", "discovery"],
                )
            )
            return result

        auth_url = oauth_endpoints.get("authorization_endpoint", "")
        oauth_endpoints.get("token_endpoint", "")

        # Test missing state parameter (CSRF)
        result.findings.extend(self._test_missing_state(auth_url, http_client, target))

        # Test redirect_uri validation (open redirect)
        result.findings.extend(self._test_redirect_uri(auth_url, http_client, target))

        # Test implicit flow
        result.findings.extend(self._test_implicit_flow(auth_url, http_client, target))

        # Test missing PKCE
        result.findings.extend(self._test_missing_pkce(auth_url, http_client, target))

        # Test client secret exposure
        result.findings.extend(self._check_client_secret_exposure(report, target))

        # Test scope escalation
        result.findings.extend(self._test_scope_escalation(auth_url, http_client, target, config))

        return result

    def _discover_oauth_endpoints(
        self,
        target: str,
        http_client: Any,
        report: ScanReport,
    ) -> dict[str, str]:
        """Discover OAuth/OIDC endpoints from probe data and well-known paths."""
        endpoints: dict[str, str] = {}

        # Check page content for OAuth references
        probe_body = report.metadata.get("probe_body", "")
        probe_headers = report.metadata.get("probe_headers", {})

        # Check all headers for OAuth-related headers
        for key, value in probe_headers.items():
            if any(kw in key.lower() or kw in str(value).lower() for kw in OAUTH_KEYWORDS):
                endpoints["detected_in_headers"] = key

        # Check page source for oauth links. Previously the optional quote
        # character was being captured as group 1 and used as the dict key,
        # so discovered endpoints landed under "" / "'" / '"' and were never
        # consumed by downstream tests. Capture the endpoint *name* and the
        # URL as named groups, tolerating both JSON (`"name": "url"`) and
        # JavaScript (`name = url` or `name: 'url'`) forms.
        for match in re.finditer(
            r"(?P<name>authorization_endpoint|token_endpoint|userinfo_endpoint|issuer)"
            r'["\']?\s*[:=]\s*["\']?(?P<url>https?://[^\s"\'<,]+)',
            probe_body,
        ):
            endpoints[match.group("name")] = match.group("url").rstrip(",;)")

        # Check well-known paths
        for well_known in OAUTH_WELL_KNOWN_PATHS:
            try:
                url = urljoin(target + "/", well_known.lstrip("/"))
                resp = http_client.get(well_known)
                if resp.status_code == 200:
                    content_type = resp.headers.get("Content-Type", "")
                    if "json" in content_type:
                        try:
                            data = resp.json()
                            if isinstance(data, dict):
                                for key in [
                                    "authorization_endpoint",
                                    "token_endpoint",
                                    "userinfo_endpoint",
                                    "issuer",
                                    "jwks_uri",
                                    "registration_endpoint",
                                    "end_session_endpoint",
                                ]:
                                    if key in data and isinstance(data[key], str):
                                        endpoints[key] = data[key]
                        except Exception as exc:
                            _log.debug("swallowed: %s", exc)
                    else:
                        endpoints[well_known] = url
            except Exception as exc:
                _log.debug("swallowed: %s", exc)

        # Also check the path discovery results
        path_results = report.metadata.get("path_results", {})
        for path, data in path_results.items():
            if data.get("status") in (200, 301, 302) and any(
                kw in path.lower() for kw in ["oauth", "oidc", "openid", "well-known"]
            ):
                endpoints[path] = urljoin(target + "/", path.lstrip("/"))

        return endpoints

    def _test_missing_state(
        self,
        auth_url: str,
        http_client: Any,
        target: str,
    ) -> list[Finding]:
        """Test if the authorization endpoint accepts requests without a state parameter."""
        findings: list[Finding] = []
        if not auth_url:
            return findings

        try:
            # Request without state parameter
            params = {
                "client_id": "test-client",
                "redirect_uri": urljoin(target + "/", "/callback"),
                "response_type": "code",
                "scope": "openid profile",
            }
            resp = http_client.get(auth_url, params=params)
            # If server returns 200/302 without requiring state, flag it
            if resp.status_code in (200, 302, 303):
                # Check if response body mentions state or CSRF
                body_lower = resp.text.lower()
                if "state" not in body_lower and "csrf" not in body_lower:
                    findings.append(
                        Finding(
                            title="OAuth Missing State Parameter (CSRF)",
                            description=(
                                "The OAuth authorization endpoint accepted a request "
                                "without a 'state' parameter. This enables CSRF attacks "
                                "during the OAuth flow, allowing an attacker to bind a "
                                "victim's authorization to their own account."
                            ),
                            severity=Severity.HIGH,
                            evidence={
                                "authorization_url": auth_url,
                                "params_sent": list(params.keys()),
                            },
                            remediation=(
                                "Always include a random, unguessable 'state' parameter "
                                "in authorization requests and validate it in the callback."
                            ),
                            cwe_id="CWE-352",
                            module_name=self.name,
                            confidence=0.8,
                            tags=["oauth", "csrf", "state"],
                        )
                    )
        except Exception as exc:
            _log.debug("swallowed: %s", exc)

        return findings

    def _test_redirect_uri(
        self,
        auth_url: str,
        http_client: Any,
        target: str,
    ) -> list[Finding]:
        """Test redirect_uri validation with an attacker-controlled URL."""
        findings: list[Finding] = []
        if not auth_url:
            return findings

        test_uris = [
            "https://attacker.com/callback",
            "https://evil.com",
            "//attacker.com/callback",
            "https://{}.attacker.com".format(
                target.replace("https://", "").replace("http://", "").split(":")[0]
            ),
        ]

        for evil_uri in test_uris:
            try:
                params = {
                    "client_id": "test-client",
                    "redirect_uri": evil_uri,
                    "response_type": "code",
                    "scope": "openid",
                    "state": "test-state-12345",
                }
                resp = http_client.get(auth_url, params=params, allow_redirects=False)
                if resp.status_code in (302, 303):
                    location = resp.headers.get("Location", resp.headers.get("location", ""))
                    if "attacker.com" in location or "evil.com" in location:
                        findings.append(
                            Finding(
                                title="OAuth Open Redirect in redirect_uri",
                                description=(
                                    f"The authorization server accepted and redirected to "
                                    f"an arbitrary redirect_uri: {evil_uri}. "
                                    "This allows attackers to steal authorization codes."
                                ),
                                severity=Severity.CRITICAL,
                                evidence={
                                    "redirect_uri": evil_uri,
                                    "redirected_to": location,
                                },
                                remediation=(
                                    "Strictly validate redirect_uri against a whitelist. "
                                    "Use exact matching, not substring checks."
                                ),
                                cwe_id="CWE-601",
                                cvss_score=8.1,
                                module_name=self.name,
                                confidence=0.95,
                                tags=["oauth", "open-redirect", "critical"],
                            )
                        )
                        break
            except Exception as exc:
                _log.debug("swallowed: %s", exc)

        return findings

    def _test_implicit_flow(
        self,
        auth_url: str,
        http_client: Any,
        target: str,
    ) -> list[Finding]:
        """Test if implicit flow (response_type=token) is supported."""
        findings: list[Finding] = []
        if not auth_url:
            return findings

        try:
            params = {
                "client_id": "test-client",
                "redirect_uri": urljoin(target + "/", "/callback"),
                "response_type": "token",
                "scope": "openid profile",
            }
            resp = http_client.get(auth_url, params=params)
            if resp.status_code in (200, 302):
                findings.append(
                    Finding(
                        title="OAuth Implicit Flow Supported",
                        description=(
                            "The authorization server supports 'response_type=token' "
                            "(implicit flow). Implicit flow exposes access tokens in "
                            "URL fragments and should be replaced with authorization "
                            "code flow with PKCE."
                        ),
                        severity=Severity.MEDIUM,
                        evidence={"response_type": "token", "status": resp.status_code},
                        remediation=(
                            "Disable implicit flow. Use authorization code flow with PKCE for all clients."
                        ),
                        module_name=self.name,
                        confidence=0.85,
                        tags=["oauth", "implicit-flow"],
                    )
                )
        except Exception as exc:
            _log.debug("swallowed: %s", exc)

        return findings

    def _test_missing_pkce(
        self,
        auth_url: str,
        http_client: Any,
        target: str,
    ) -> list[Finding]:
        """Test if PKCE is required for public clients."""
        findings: list[Finding] = []
        if not auth_url:
            return findings

        try:
            # Request without code_challenge (PKCE)
            params = {
                "client_id": "test-public-client",
                "redirect_uri": urljoin(target + "/", "/callback"),
                "response_type": "code",
                "scope": "openid",
            }
            resp = http_client.get(auth_url, params=params)
            if resp.status_code in (302, 303, 200):
                # Check if the response indicates PKCE is required
                body_lower = resp.text.lower()
                if "code_challenge" not in body_lower and "pkce" not in body_lower:
                    findings.append(
                        Finding(
                            title="OAuth PKCE Not Enforced",
                            description=(
                                "The authorization server did not require PKCE "
                                "(code_challenge) for the authorization request. "
                                "PKCE is mandatory for public clients."
                            ),
                            severity=Severity.HIGH,
                            evidence={"pkce_required": False},
                            remediation=(
                                "Enforce PKCE for all public clients. Require "
                                "code_challenge and code_challenge_method=S256."
                            ),
                            cwe_id="CWE-862",
                            module_name=self.name,
                            confidence=0.75,
                            tags=["oauth", "pkce"],
                        )
                    )
        except Exception as exc:
            _log.debug("swallowed: %s", exc)

        return findings

    def _check_client_secret_exposure(
        self,
        report: ScanReport,
        target: str,
    ) -> list[Finding]:
        """Check for client secrets leaked in page source."""
        findings: list[Finding] = []
        probe_body = report.metadata.get("probe_body", "")

        secret_patterns = [
            (r'client_?secret["\s:=]+["\']([^"\']+)["\']', "Client Secret"),
            (r'oauth_?secret["\s:=]+["\']([^"\']+)["\']', "OAuth Secret"),
            (r'client_?id["\s:=]+["\']([^"\']+)["\']', "Client ID"),
        ]

        for pattern, label in secret_patterns:
            for _match in re.finditer(pattern, probe_body, re.IGNORECASE):
                findings.append(
                    Finding(
                        title=f"OAuth {label} in Client-Side Code",
                        description=(
                            f"An OAuth {label.lower()} was found in the page source. "
                            "Secrets in client-side code can be extracted by anyone."
                        ),
                        severity=Severity.CRITICAL,
                        evidence={"type": label, "found_in": "page source"},
                        remediation=(
                            f"Remove the {label.lower()} from client-side code. "
                            "Use a backend proxy for OAuth token exchanges."
                        ),
                        cwe_id="CWE-798",
                        module_name=self.name,
                        confidence=0.95,
                        tags=["oauth", "secret-exposure"],
                    )
                )

        return findings

    def _test_scope_escalation(
        self,
        auth_url: str,
        http_client: Any,
        target: str,
        config: Any,
    ) -> list[Finding]:
        """Test if scope escalation is possible."""
        findings: list[Finding] = []
        if not auth_url:
            return findings

        # Plain-text scope. The previous default was pre-URL-encoded
        # ("admin%20profile..."), which then got URL-encoded again by
        # ``requests`` into "admin%2520..." — corrupting the request and
        # producing both false negatives (server rejects the malformed
        # value) and false positives (server echoes it back unchanged).
        escalated_scopes = getattr(config, "oauth_scope", "admin profile email openid")
        if isinstance(escalated_scopes, str) and not escalated_scopes:
            escalated_scopes = "admin profile email openid"

        try:
            params = {
                "client_id": "test-client",
                "redirect_uri": urljoin(target + "/", "/callback"),
                "response_type": "code",
                "scope": escalated_scopes,
                "state": "scope-test",
            }
            resp = http_client.get(auth_url, params=params)
            if resp.status_code in (200, 302, 303):
                resp.headers.get("Location", resp.headers.get("location", ""))
                body_lower = resp.text.lower()
                # If the server accepts our scope without complaint
                if "invalid_scope" not in body_lower and "invalid scope" not in body_lower:
                    findings.append(
                        Finding(
                            title="OAuth Scope Escalation Possible",
                            description=(
                                f"The server accepted an authorization request with "
                                f"scope '{escalated_scopes}' without rejecting it. "
                                "This may allow privilege escalation."
                            ),
                            severity=Severity.MEDIUM,
                            evidence={"scope_tested": escalated_scopes, "status": resp.status_code},
                            remediation=(
                                "Validate scopes server-side. Only grant scopes that "
                                "the requesting client is authorized to request."
                            ),
                            module_name=self.name,
                            confidence=0.6,
                            tags=["oauth", "scope-escalation"],
                        )
                    )
        except Exception as exc:
            _log.debug("swallowed: %s", exc)

        return findings
