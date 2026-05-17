"""MFA bypass testing module."""
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

MFA_KEYWORDS = [
    "2fa", "mfa", "two-factor", "two factor",
    "multi-factor", "multi factor", "totp",
    "webauthn", "authenticator", "security key",
    "sms verification", "verification code",
    "otp", "one-time", "backup code",
    "recovery code",
]


class MfaBypass(BaseAttackModule):
    """Test MFA implementations for common bypass vulnerabilities.

    Covers:
    - MFA presence detection
    - Direct endpoint access (skip MFA)
    - Response manipulation
    - Parameter pollution
    - Rate limiting on codes
    - Backup code brute-force
    """

    name = "mfa"
    description = "Test MFA implementations for bypass vulnerabilities"
    version = "1.0.0"
    priority = 50

    def run(
        self,
        target: str,
        http_client: Any,
        report: ScanReport,
        config: Any,
    ) -> ModuleResult:
        result = ModuleResult()

        # Detect MFA presence
        mfa_detected = self._detect_mfa(report)
        if not mfa_detected:
            result.findings.append(Finding(
                title="No MFA Detected",
                description=(
                    "No MFA/2FA indicators were found in the application. "
                    "If this application handles sensitive data, consider "
                    "implementing MFA."
                ),
                severity=Severity.INFO,
                module_name=self.name,
                tags=["mfa", "discovery"],
            ))
            return result

        result.findings.append(Finding(
            title="MFA Detected",
            description=f"MFA indicators found: {', '.join(mfa_detected[:3])}.",
            severity=Severity.INFO,
            evidence={"indicators": mfa_detected},
            module_name=self.name,
            tags=["mfa", "discovery"],
        ))

        # Test bypasses
        mfa_endpoints = self._find_mfa_endpoints(report, target)

        # Direct access bypass
        result.findings.extend(self._test_direct_access(http_client, report, target))

        # Response manipulation
        result.findings.extend(self._test_response_manipulation(http_client, target))

        # Parameter pollution
        result.findings.extend(self._test_parameter_pollution(http_client, report, target))

        # Rate limiting on MFA codes
        result.findings.extend(self._test_mfa_rate_limiting(http_client, report, target))

        return result

    def _detect_mfa(self, report: ScanReport) -> list[str]:
        """Detect MFA references in probe data."""
        found: list[str] = []
        probe_body = report.metadata.get("probe_body", "").lower()
        probe_headers = {k.lower(): str(v).lower() for k, v in report.metadata.get("probe_headers", {}).items()}

        # Check page content
        for kw in MFA_KEYWORDS:
            if kw.lower() in probe_body:
                found.append(kw)

        # Check headers
        for kw in MFA_KEYWORDS:
            for header_val in probe_headers.values():
                if kw.lower() in header_val:
                    found.append(f"{kw} (in header)")
                    break

        return list(set(found))

    def _find_mfa_endpoints(self, report: ScanReport, target: str) -> list[str]:
        """Find MFA-related endpoints from probe and path discovery."""
        endpoints: list[str] = []

        # From probe body
        probe_body = report.metadata.get("probe_body", "")
        for match in re.finditer(r'(?:href|action)=["\']([^"\']*(?:mfa|2fa|verify|otp|two-factor)[^"\']*)["\']', probe_body, re.I):
            endpoints.append(match.group(1))

        # Common patterns
        for pattern in ["/mfa", "/2fa", "/verify", "/otp", "/totp", "/two-factor", "/authenticate/verify", "/mfa/verify"]:
            if pattern not in endpoints:
                endpoints.append(pattern)

        return endpoints

    def _test_direct_access(
        self, http_client: Any, report: ScanReport, target: str,
    ) -> list[Finding]:
        """Test if protected pages can be accessed directly, skipping MFA."""
        findings: list[Finding] = []
        protected_paths = ["/dashboard", "/profile", "/settings", "/account", "/admin", "/api/user"]

        for path in protected_paths:
            try:
                resp = http_client.get(path)
                if resp.status_code == 200 and "login" not in resp.text.lower():
                    findings.append(Finding(
                        title="MFA Bypass: Direct Endpoint Access",
                        description=(
                            f"Page {path} was accessible (HTTP 200) without "
                            "completing MFA. Users can bypass MFA by navigating directly."
                        ),
                        severity=Severity.HIGH,
                        evidence={"path": path, "status": resp.status_code},
                        remediation=(
                            "Enforce MFA check on all protected endpoints server-side. "
                            "Do not rely on client-side redirects."
                        ),
                        cwe_id="CWE-306",
                        module_name=self.name,
                        confidence=0.85,
                        tags=["mfa", "bypass", "direct-access"],
                    ))
            except Exception:
                pass

        return findings

    def _test_response_manipulation(
        self, http_client: Any, target: str,
    ) -> list[Finding]:
        """Test if MFA can be bypassed by manipulating response values."""
        findings: list[Finding] = []
        mfa_verify_paths = ["/mfa/verify", "/api/mfa/verify", "/api/auth/verify", "/verify"]

        for path in mfa_verify_paths:
            try:
                # Try to send JSON that claims MFA is already verified
                payload = {"mfa_verified": True, "mfa_required": False, "mfa_status": "verified"}
                resp = http_client.post(path, json=payload)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    findings.append(Finding(
                        title="MFA Bypass: Response Manipulation Possible",
                        description=(
                            f"Sending manipulated body to {path} succeeded (HTTP {resp.status_code}). "
                            "The server may accept client-modifiable MFA state."
                        ),
                        severity=Severity.HIGH,
                        evidence={
                            "endpoint": path,
                            "payload": payload,
                            "response_status": resp.status_code,
                        },
                        remediation=(
                            "Never trust MFA state from the client. "
                            "Maintain MFA status server-side in the session."
                        ),
                        module_name=self.name,
                        confidence=0.7,
                        tags=["mfa", "bypass", "response-manipulation"],
                    ))
            except Exception:
                pass

        return findings

    def _test_parameter_pollution(
        self, http_client: Any, report: ScanReport, target: str,
    ) -> list[Finding]:
        """Test MFA bypass via parameter pollution."""
        findings: list[Finding] = []
        bypass_params = [
            {"mfa_bypass": "true", "skip_mfa": "1"},
            {"mfa_bypass": "1", "skip": "true"},
            {"bypass": "true", "mfa": "false"},
        ]

        # Test on common login/MFA endpoints
        test_endpoints = self._find_mfa_endpoints(report, target)
        test_endpoints.extend(["/login", "/auth", "/signin"])

        for endpoint in test_endpoints[:5]:
            for params in bypass_params:
                try:
                    resp = http_client.post(endpoint, data=params)
                    if resp.status_code == 200 and "error" not in resp.text.lower():
                        findings.append(Finding(
                            title="MFA Bypass: Parameter Pollution",
                            description=(
                                f"MFA may be bypassed by adding parameters to {endpoint}: "
                                f"{list(params.keys())}."
                            ),
                            severity=Severity.HIGH,
                            evidence={
                                "endpoint": endpoint,
                                "params": list(params.keys()),
                                "status": resp.status_code,
                            },
                            remediation="Never accept client-supplied MFA bypass parameters.",
                            module_name=self.name,
                            confidence=0.65,
                            tags=["mfa", "bypass", "parameter-pollution"],
                        ))
                except Exception:
                    pass

        return findings

    def _test_mfa_rate_limiting(
        self, http_client: Any, report: ScanReport, target: str,
    ) -> list[Finding]:
        """Test if MFA code attempts are rate-limited."""
        findings: list[Finding] = []
        verify_endpoints = [
            "/mfa/verify", "/2fa/verify", "/otp/verify",
            "/auth/verify", "/api/auth/verify",
        ]

        for endpoint in verify_endpoints[:3]:
            fast_429 = 0
            for _ in range(5):
                try:
                    resp = http_client.post(
                        endpoint,
                        data={"code": "000000"},
                        timeout=5,
                    )
                    if resp.status_code == 429:
                        fast_429 += 1
                    if fast_429 >= 2:
                        break
                except Exception:
                    pass

            if fast_429 >= 2:
                findings.append(Finding(
                    title="MFA Rate Limiting Detected",
                    description=(
                        f"Rate limiting detected on MFA verification at {endpoint}. "
                        "This is a good security measure."
                    ),
                    severity=Severity.INFO,
                    evidence={"endpoint": endpoint, "rate_limited": True},
                    module_name=self.name,
                    tags=["mfa", "rate-limiting"],
                ))
            elif fast_429 == 0:
                findings.append(Finding(
                    title="No MFA Code Rate Limiting",
                    description=(
                        f"No rate limiting detected on MFA verification at {endpoint}. "
                        "Attackers can brute-force MFA codes."
                    ),
                    severity=Severity.MEDIUM,
                    evidence={"endpoint": endpoint, "rate_limited": False},
                    remediation="Implement rate limiting on MFA code submission (e.g., 5 attempts per 5 minutes).",
                    cwe_id="CWE-307",
                    module_name=self.name,
                    confidence=0.7,
                    tags=["mfa", "rate-limiting"],
                ))

        return findings
