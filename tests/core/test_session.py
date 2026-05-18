"""Tests for session analysis utilities."""

from __future__ import annotations

import base64
import json

from auth_scan.core.session import (
    CookieAnalysis,
    TokenInfo,
    analyze_session_id_entropy,
    check_security_headers,
    find_session_ids_in_content,
    shannon_entropy,
)


class TestTokenInfo:
    """Tests for JWT token decoding."""

    def test_decode_valid_jwt(self, sample_jwt_token: str) -> None:
        token = TokenInfo.from_string(sample_jwt_token)
        assert token.is_jwt
        assert token.algorithm == "HS256"
        assert token.payload.get("sub") == "testuser"

    def test_decode_alg_none_jwt(self, sample_jwt_none: str) -> None:
        token = TokenInfo.from_string(sample_jwt_none)
        assert token.is_jwt
        assert token.algorithm == "none"
        assert token.payload.get("role") == "admin"

    def test_non_jwt_string(self) -> None:
        token = TokenInfo.from_string("not-a-jwt")
        assert not token.is_jwt

    def test_expired_token_detection(self) -> None:
        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
            .rstrip(b"=")
            .decode()
        )
        payload = (
            base64.urlsafe_b64encode(
                json.dumps({"sub": "user", "exp": 1}).encode()  # way in the past
            )
            .rstrip(b"=")
            .decode()
        )
        expired = f"{header}.{payload}.sig"
        token = TokenInfo.from_string(expired)
        assert token.is_jwt
        assert token.is_expired
        assert any("expired" in i.lower() for i in token.issues)

    def test_sensitive_data_detection(self) -> None:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = (
            base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "sub": "user",
                        "email": "admin@example.com",
                        "password": "secret123",
                    }
                ).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        token = TokenInfo.from_string(f"{header}.{payload}.sig")
        issues = token.has_sensitive_data()
        assert len(issues) >= 2
        assert any("password" in i.lower() for i in issues)

    def test_missing_recommended_claims(self) -> None:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = (
            base64.urlsafe_b64encode(
                json.dumps({"sub": "user"}).encode()  # missing iat, jti
            )
            .rstrip(b"=")
            .decode()
        )
        token = TokenInfo.from_string(f"{header}.{payload}.sig")
        assert any("iat" in i for i in token.issues)
        assert any("jti" in i for i in token.issues)


class TestCookieAnalysis:
    """Tests for cookie security analysis."""

    def test_session_cookie_httponly_missing(self) -> None:
        cookie = CookieAnalysis(
            name="sessionid",
            value="abc123",
            http_only=False,
            secure=True,
            same_site="Lax",
        )
        cookie._analyze()
        assert any("HttpOnly" in i for i in cookie.issues)
        assert cookie.is_session_cookie

    def test_cookie_secure_missing(self) -> None:
        cookie = CookieAnalysis(
            name="auth",
            value="token123",
            secure=False,
        )
        cookie._analyze()
        assert any("Secure" in i for i in cookie.issues)

    def test_cookie_missing_samesite(self) -> None:
        cookie = CookieAnalysis(
            name="sessionid",
            value="abc",
            http_only=True,
            secure=True,
        )
        cookie._analyze()
        assert any("SameSite" in i for i in cookie.issues)

    def test_cookie_samesite_none_without_secure(self) -> None:
        cookie = CookieAnalysis(
            name="token",
            value="xyz",
            secure=False,
            same_site="None",
        )
        cookie._analyze()
        assert any("SameSite=None without Secure" in i for i in cookie.issues)

    def test_broad_domain_cookie(self) -> None:
        cookie = CookieAnalysis(
            name="sessionid",
            value="abc",
            domain="example.com",
        )
        cookie._analyze()
        assert any("Domain" in i for i in cookie.issues)


class TestSecurityHeaders:
    """Tests for security header checking."""

    def test_missing_all_https(self) -> None:
        headers = {"Content-Type": "text/html"}
        checks = check_security_headers(headers, is_https=True)
        assert not checks["Strict-Transport-Security"]["present"]
        assert not checks["Content-Security-Policy"]["present"]
        assert not checks["X-Frame-Options"]["present"]

    def test_all_headers_present(self) -> None:
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        }
        checks = check_security_headers(headers, is_https=True)
        for check in checks.values():
            assert check["present"], f"{check} should be present"

    def test_hsts_not_required_on_http(self) -> None:
        headers = {"Content-Type": "text/html"}
        checks = check_security_headers(headers, is_https=False)
        assert not checks["Strict-Transport-Security"]["required"]


class TestEntropyAnalysis:
    """Tests for entropy analysis."""

    def test_shannon_entropy_maximum(self) -> None:
        # 16 unique chars each appearing once = max entropy for length
        data = "abcdefghijklmnop"
        entropy = shannon_entropy(data)
        assert entropy == 4.0  # log2(16) = 4

    def test_shannon_entropy_minimum(self) -> None:
        # All same character = 0 entropy
        data = "aaaaaaaa"
        entropy = shannon_entropy(data)
        assert entropy == 0.0

    def test_session_id_entropy_weak(self) -> None:
        result = analyze_session_id_entropy("12345")
        assert result["assessment"] == "weak"
        assert result["length"] < 16

    def test_session_id_entropy_hex(self) -> None:
        result = analyze_session_id_entropy("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
        assert result["charset_type"] in ("hex", "alphanumeric")
        assert result["length"] >= 16

    def test_session_id_entropy_empty(self) -> None:
        result = analyze_session_id_entropy("")
        assert "error" in result


class TestSessionIdDetection:
    """Tests for session ID detection in content."""

    def test_session_id_in_url(self) -> None:
        content = '<a href="/login?sessionid=abc123def456">Login</a>'
        results = find_session_ids_in_content(content)
        assert len(results) >= 1
        assert results[0]["token_name"].lower() == "sessionid"

    def test_jsessionid_in_url(self) -> None:
        content = '<form action="/app;jsessionid=xyz789">'
        results = find_session_ids_in_content(content)
        assert len(results) >= 1

    def test_no_session_id(self) -> None:
        content = '<a href="/login">Login</a>'
        results = find_session_ids_in_content(content)
        assert len(results) == 0
