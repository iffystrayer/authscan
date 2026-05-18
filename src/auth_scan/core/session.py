"""Session, token, and cookie analysis utilities."""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class TokenInfo:
    """Decoded JWT or generic token information."""

    raw: str
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    algorithm: str | None = None
    is_jwt: bool = False
    expires: datetime | None = None
    not_before: datetime | None = None
    issues: list[str] = field(default_factory=list)
    location: str = ""  # "header", "cookie", "body"
    source_name: str = ""  # cookie name, header name, etc.

    @classmethod
    def from_string(cls, raw: str, location: str = "", source_name: str = "") -> TokenInfo:
        """Parse a token string, attempting JWT decode."""
        token = cls(raw=raw, location=location, source_name=source_name)
        token._try_decode_jwt()
        return token

    def _try_decode_jwt(self) -> None:
        """Attempt to decode as JWT without cryptographic verification."""
        parts = self.raw.split(".")
        if len(parts) != 3:
            return

        self.is_jwt = True
        try:
            self.header = self._b64decode_json(parts[0])
            self.algorithm = self.header.get("alg")
            self.payload = self._b64decode_json(parts[1])

            # Expiration
            exp = self.payload.get("exp")
            if exp:
                self.expires = datetime.fromtimestamp(exp, tz=timezone.utc)
                if self.expires < datetime.now(timezone.utc):
                    self.issues.append("Token is expired")

            # Not before
            nbf = self.payload.get("nbf")
            if nbf:
                self.not_before = datetime.fromtimestamp(nbf, tz=timezone.utc)
                if self.not_before > datetime.now(timezone.utc):
                    self.issues.append("Token is not yet valid (nbf in future)")

            # Check recommended claims
            for claim in ["sub", "iat", "jti"]:
                if claim not in self.payload:
                    self.issues.append(f"Missing recommended claim: {claim}")

        except Exception as e:
            self.issues.append(f"Failed to decode JWT: {e}")

    @staticmethod
    def _b64decode_json(data: str) -> dict[str, Any]:
        """Base64url-decode and parse JSON."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        decoded = base64.urlsafe_b64decode(data)
        return json.loads(decoded)

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        if self.expires is None:
            return False
        return self.expires < datetime.now(timezone.utc)

    def has_sensitive_data(self) -> list[str]:
        """Check payload for sensitive data patterns. Returns list of issues."""
        issues: list[str] = []
        payload_str = json.dumps(self.payload).lower()

        # PII patterns
        sensitive_keys = [
            "password",
            "passwd",
            "secret",
            "apikey",
            "api_key",
            "token",
            "creditcard",
            "credit_card",
            "ssn",
            "social_security",
        ]
        for key, _value in self.payload.items():
            key_lower = key.lower()
            for sensitive in sensitive_keys:
                if sensitive in key_lower:
                    issues.append(f"Sensitive key in JWT payload: {key}")
                    break

        # Email regex
        email_pattern = re.compile(
            r'["\']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?',
        )
        if email_pattern.search(payload_str):
            issues.append("Email address found in JWT payload")

        # Possible internal IDs
        for key, value in self.payload.items():
            if isinstance(value, (int, str)) and key.lower() in (
                "user_id",
                "uid",
                "id",
                "account_id",
                "internal_id",
                "role",
            ):
                issues.append(f"Potentially sensitive '{key}' in JWT payload: {value}")

        return issues


@dataclass
class CookieAnalysis:
    """Security analysis of a single cookie."""

    name: str
    value: str
    http_only: bool = False
    secure: bool = False
    same_site: str = ""  # Strict, Lax, None, or empty for not set
    domain: str = ""
    path: str = "/"
    max_age: int | None = None
    expires: str = ""
    issues: list[str] = field(default_factory=list)
    is_session_cookie: bool = False

    @classmethod
    def from_set_cookie(cls, cookie_name: str, cookie_value: str) -> CookieAnalysis:
        """Create from a cookie name and raw value for basic inspection."""
        cookie = cls(name=cookie_name, value=cookie_value)
        parts = cookie_value.split("; ")
        if len(parts) > 1:
            for attr in parts[1:]:
                attr_lower = attr.lower().strip()
                if attr_lower == "httponly":
                    cookie.http_only = True
                elif attr_lower == "secure":
                    cookie.secure = True
                elif attr_lower.startswith("samesite="):
                    cookie.same_site = attr.split("=", 1)[1]
                elif attr_lower.startswith("domain="):
                    cookie.domain = attr.split("=", 1)[1]
                elif attr_lower.startswith("path="):
                    cookie.path = attr.split("=", 1)[1]
                elif attr_lower.startswith("max-age="):
                    try:
                        cookie.max_age = int(attr.split("=", 1)[1])
                    except ValueError:
                        pass
                elif attr_lower.startswith("expires="):
                    cookie.expires = attr.split("=", 1)[1]

        cookie._analyze()
        return cookie

    @classmethod
    def from_requests_cookie(
        cls,
        name: str,
        value: str,
        rest: dict[str, str] | None = None,
    ) -> CookieAnalysis:
        """Create from a requests library cookie object's attributes."""
        rest = rest or {}
        cookie = cls(
            name=name,
            value=value,
            http_only=rest.get("httponly", False)
            if isinstance(rest.get("httponly"), bool)
            else rest.get("httponly", "").lower() == "true",
            secure=rest.get("secure", False)
            if isinstance(rest.get("secure"), bool)
            else rest.get("secure", "").lower() == "true",
            same_site=rest.get("samesite", ""),
            domain=rest.get("domain", ""),
            path=rest.get("path", "/"),
            expires=str(rest.get("expires", "")),
        )
        try:
            if rest.get("max_age"):
                cookie.max_age = int(rest["max_age"])
        except (ValueError, TypeError):
            pass
        cookie._analyze()
        return cookie

    def _analyze(self) -> None:
        """Run security analysis on the cookie attributes."""
        name_lower = self.name.lower()
        self.is_session_cookie = any(
            hint in name_lower for hint in ["session", "auth", "token", "jwt", "sid", "sess"]
        )

        if not self.http_only and self.is_session_cookie:
            self.issues.append(
                f"Session cookie '{self.name}' missing HttpOnly flag — accessible via JavaScript"
            )
        elif not self.http_only:
            self.issues.append(f"Cookie '{self.name}' missing HttpOnly flag")

        if not self.secure:
            self.issues.append(f"Cookie '{self.name}' missing Secure flag — transmitted over HTTP")

        if not self.same_site:
            self.issues.append(f"Cookie '{self.name}' missing SameSite attribute — susceptible to CSRF")
        elif self.same_site.lower() == "none" and not self.secure:
            self.issues.append(
                f"Cookie '{self.name}' has SameSite=None without Secure — will be rejected by browsers"
            )

        # Broad domain
        if self.domain and not self.domain.startswith("."):
            if len(self.domain.split(".")) == 2:  # e.g., "example.com"
                self.issues.append(
                    f"Cookie '{self.name}' has broad Domain={self.domain} — may leak to subdomains"
                )


def check_security_headers(headers: dict[str, str], is_https: bool) -> dict[str, Any]:
    """Check for presence of recommended security headers.

    Returns a dict mapping header name to a dict with 'present', 'value', and 'issue'.
    """
    header_lower = {k.lower(): k for k in headers}
    values = {k.lower(): v for k, v in headers.items()}

    checks = {
        "Strict-Transport-Security": {
            "present": "strict-transport-security" in header_lower,
            "value": values.get("strict-transport-security", ""),
            "required": is_https,
            "message": "Missing HSTS header — MiTM risk",
            "severity": "medium",
        },
        "X-Content-Type-Options": {
            "present": "x-content-type-options" in header_lower,
            "value": values.get("x-content-type-options", ""),
            "required": True,
            "message": "Missing X-Content-Type-Options — MIME sniffing risk",
            "severity": "low",
        },
        "X-Frame-Options": {
            "present": "x-frame-options" in header_lower,
            "value": values.get("x-frame-options", ""),
            "required": True,
            "message": "Missing X-Frame-Options — clickjacking risk",
            "severity": "low",
        },
        "Content-Security-Policy": {
            "present": "content-security-policy" in header_lower,
            "value": values.get("content-security-policy", ""),
            "required": True,
            "message": "Missing Content-Security-Policy — XSS and data injection risk",
            "severity": "medium",
        },
        "Referrer-Policy": {
            "present": "referrer-policy" in header_lower,
            "value": values.get("referrer-policy", ""),
            "required": True,
            "message": "Missing Referrer-Policy — may leak URL data in Referer header",
            "severity": "low",
        },
        "Permissions-Policy": {
            "present": "permissions-policy" in header_lower,
            "value": values.get("permissions-policy", ""),
            "required": True,
            "message": "Missing Permissions-Policy — browser features unrestricted",
            "severity": "low",
        },
    }

    return checks


SESSION_ID_PATTERNS = [
    re.compile(r"[?&;](?:sessionid|sid|jsessionid|phpsessid|aspsessionid)=([^&\s]+)", re.I),
    re.compile(r"[?&;](?:auth|token|access_token)=([^&\s]+)", re.I),
]


def find_session_ids_in_content(content: str) -> list[dict[str, str]]:
    """Search HTML content for session IDs in URLs (href, form actions, etc.).

    Returns a list of dicts with 'url' and 'token_name'.
    """
    results: list[dict[str, str]] = []
    for pattern in SESSION_ID_PATTERNS:
        for match in pattern.finditer(content):
            results.append(
                {
                    "url": match.string[max(0, match.start() - 50) : match.end() + 50].strip(),
                    "token_name": match.group(0).split("=")[0].lstrip("?&"),
                    "token_value": match.group(1),
                }
            )
    return results


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def analyze_session_id_entropy(session_id: str) -> dict[str, Any]:
    """Analyze a session ID for entropy and randomness indicators.

    Returns a dict with:
        length: length of the session ID
        charset_size: number of unique characters
        charset_type: "hex", "alphanumeric", "base64", "mixed"
        entropy: Shannon entropy
        max_entropy: maximum possible entropy for this length
        entropy_ratio: entropy / max_entropy (0.0-1.0)
        assessment: "good", "moderate", "weak"
    """
    if not session_id:
        return {"error": "Empty session ID"}

    length = len(session_id)
    unique_chars = set(session_id)
    charset_size = len(unique_chars)

    # Determine charset type
    if all(c in "0123456789abcdefABCDEF" for c in unique_chars):
        charset_type = "hex"
        charset_max = 16
    elif all(c in "0123456789abcdefABCDEF-_" for c in unique_chars):
        charset_type = "base64url"
        charset_max = 64
    elif all(c.isalnum() for c in unique_chars):
        charset_type = "alphanumeric"
        charset_max = 62
    else:
        charset_type = "mixed"
        charset_max = 95  # printable ASCII

    entropy = shannon_entropy(session_id)
    max_entropy = math.log2(min(charset_max, charset_size))

    if max_entropy > 0:
        entropy / (max_entropy * length / length) if max_entropy else 0
    else:
        pass

    # Heuristic assessment
    if entropy < 3.0 or length < 16:
        assessment = "weak"
    elif entropy >= 3.0 and length >= 16:
        assessment = "good"
    else:
        assessment = "moderate"

    return {
        "length": length,
        "charset_size": charset_size,
        "charset_type": charset_type,
        "entropy": round(entropy, 2),
        "max_possible_entropy_per_char": round(max_entropy, 2),
        "assessment": assessment,
        "recommendation": (
            "Use at least 128 bits of entropy (e.g., 32 hex chars, 22 base64 chars) with a CSPRNG."
        ),
    }
