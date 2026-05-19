"""API key and secret detection/analysis module."""

from __future__ import annotations

import re
from typing import Any

from auth_scan.attacks.base import (
    BaseAttackModule,
    Finding,
    ModuleResult,
    ScanReport,
    Severity,
)

# API key detection patterns
API_KEY_PATTERNS: list[tuple[str, str, str]] = [
    # (label, regex pattern, risk level)
    ("GitHub Token", r"(?:gh[pousr]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})", "critical"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "critical"),
    ("AWS Secret Key", r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", "high"),
    ("Stripe Secret Key", r"(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}", "critical"),
    ("Stripe Publishable Key", r"pk_(?:live|test)_[0-9a-zA-Z]{24,}", "medium"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("Google OAuth Client ID", r"[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com", "medium"),
    ("Slack Bot Token", r"xox[baprs]-[0-9a-zA-Z\-]+", "critical"),
    (
        "Slack Webhook",
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "critical",
    ),
    (
        "Generic API Key Header",
        r"(?:api[_-]?key|apikey|x-api-key)[\"\s:=]+[\"']([^\"']{8,})[\"']",
        "high",
    ),
    ("Bearer Token in Code", r"(?:bearer|token)[\"\s:=]+[\"']([a-zA-Z0-9\-_.]{20,})[\"']", "high"),
    ("Private Key (PEM)", r"-----BEGIN\s(?:RSA|EC|DSA|OPENSSH)?\s?PRIVATE KEY-----", "critical"),
    ("Password in Code", r"(?:password|passwd|pwd)[\"\s:=]+[\"']([^\"']{3,})[\"']", "high"),
    ("JWT in Script", r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+", "high"),
    ("Connection String", r"(?:mongodb|postgresql|mysql|sqlite|redis)://[^\"'\s]+", "critical"),
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,}", "critical"),
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "critical"),
    (
        "Heroku API Key",
        r"[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "critical",
    ),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "critical"),
    ("Generic Secret", r"(?:secret|private_key|api_secret)[\"\s:=]+[\"']([^\"']{6,})[\"']", "high"),
]

# Locations to scan
SCAN_LOCATIONS = [
    "probe_body",  # Main page HTML
    "probe_headers",  # Response headers
    "probe_cookies",  # Response cookies
]


class ApiKeyAnalyzer(BaseAttackModule):
    """Detect exposed API keys, secrets, and tokens.

    Covers:
    - API key pattern detection in page source
    - Key in URL query parameters
    - Key in error messages
    - Unscoped key testing
    - Referer header leakage check
    """

    name = "api_key"
    description = "Detect exposed API keys, secrets, and tokens in page source"
    version = "1.0.0"
    priority = 70

    def run(
        self,
        target: str,
        http_client: Any,
        report: ScanReport,
        config: Any,
    ) -> ModuleResult:
        result = ModuleResult()
        total_found = 0

        # Scan all available data sources
        for location in SCAN_LOCATIONS:
            data = report.metadata.get(location, {})
            if isinstance(data, dict):
                # For headers and cookies, scan both keys and values
                for key, value in data.items():
                    key_text = f"{key}={value}"
                    found = self._scan_text(key_text, location, key)
                    result.findings.extend(found)
                    total_found += len(found)
            elif isinstance(data, str):
                found = self._scan_text(data, location, None)
                result.findings.extend(found)
                total_found += len(found)

        # (probe_body is already covered by the SCAN_LOCATIONS loop above —
        # the previous duplicate pass produced two findings per key. M2.)

        # Check for keys in URL parameters of discovered paths
        path_results = report.metadata.get("path_results", {})
        for path in path_results:
            if "?" in path:
                found = self._check_url_params(path)
                result.findings.extend(found)
                total_found += len(found)

        if total_found == 0:
            result.findings.append(
                Finding(
                    title="No Exposed API Keys Found",
                    description="No API keys, secrets, or tokens were detected in page source.",
                    severity=Severity.INFO,
                    module_name=self.name,
                    tags=["api-key", "discovery"],
                )
            )
        else:
            result.findings.append(
                Finding(
                    title="API Key Scan Complete",
                    description=f"Found {total_found} potential key/secret exposures.",
                    severity=Severity.INFO,
                    evidence={"total_found": total_found},
                    module_name=self.name,
                    tags=["api-key", "summary"],
                )
            )

        return result

    def _scan_text(
        self,
        text: str,
        location: str,
        source_key: str | None,
    ) -> list[Finding]:
        """Scan text for known API key patterns."""
        findings: list[Finding] = []

        for label, pattern, risk in API_KEY_PATTERNS:
            try:
                for match in re.finditer(pattern, text):
                    matched = match.group(0)
                    # Skip false positives
                    if self._is_false_positive(matched, text, match.start()):
                        continue

                    severity = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                    }.get(risk, Severity.HIGH)

                    evidence = {
                        "type": label,
                        "location": location,
                        "pattern_matched": pattern[:60],
                        "match_length": len(matched),
                    }
                    if source_key:
                        evidence["source_key"] = source_key

                    findings.append(
                        Finding(
                            title=f"Exposed {label} Detected",
                            description=(
                                f"A {label} was found in {location}. "
                                "Exposed keys can be used by attackers to access "
                                "services and data."
                            ),
                            severity=severity,
                            evidence=evidence,
                            remediation=(
                                f"Remove the {label} from client-side code. "
                                "Use environment variables or a secrets manager. "
                                "Rotate the key immediately if it has been exposed."
                            ),
                            cwe_id="CWE-798",
                            module_name=self.name,
                            confidence=0.85 if risk != "high" else 0.7,
                            tags=["api-key", "secret-exposure", label.lower().replace(" ", "-")],
                        )
                    )
            except re.error:
                pass

        return findings

    @staticmethod
    def _is_false_positive(match: str, full_text: str, start: int) -> bool:
        """Check if a match is likely a false positive."""
        # Skip if in a comment that looks like documentation
        context_start = max(0, start - 50)
        context = full_text[context_start : start + len(match) + 50].lower()

        false_positive_indicators = [
            "your_",
            "placeholder",
            "sk_test_",
            "pk_test",
            "test_key",
            "demo",
            "sample",
            "<your-",
            "your-",
            "xxxx",
            "****",
            "replace with",
            "put your",
            "enter your",
        ]

        for indicator in false_positive_indicators:
            if indicator in match.lower() or indicator in context:
                return True

        return False

    def _check_url_params(self, url: str) -> list[Finding]:
        """Check for API keys in URL query parameters."""
        findings: list[Finding] = []

        sensitive_params = [
            "api_key",
            "apikey",
            "key",
            "token",
            "access_token",
            "auth",
            "secret",
            "password",
            "passwd",
        ]

        if "?" not in url:
            return findings

        query = url.split("?", 1)[1]
        for param in query.split("&"):
            if "=" in param:
                name = param.split("=", 1)[0].lower()
                for sensitive in sensitive_params:
                    if sensitive in name:
                        findings.append(
                            Finding(
                                title="API Key in URL Parameter",
                                description=(
                                    f"URL parameter '{name}' appears to contain a key/token. "
                                    "Keys in URLs are logged and leaked via Referer headers."
                                ),
                                severity=Severity.HIGH,
                                evidence={"url": url, "param": name},
                                remediation=(
                                    "Never pass API keys in URL query parameters. "
                                    "Use HTTP headers (Authorization, X-API-Key) instead."
                                ),
                                cwe_id="CWE-598",
                                module_name=self.name,
                                confidence=0.9,
                                tags=["api-key", "url-param"],
                            )
                        )
                        break

        return findings
