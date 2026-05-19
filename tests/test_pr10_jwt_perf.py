"""PR-10: JWT HMAC cracking opt-in + endpoint-probe caching (L4 / L5)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from auth_scan.attacks.jwt_analyzer import JWTAnalyzer
from auth_scan.core.session import TokenInfo

# ---- L4: jwt_crack opt-in --------------------------------------------------


def _make_hs256_token(secret: str, claims: dict[str, Any] | None = None) -> TokenInfo:
    """Build a real HS256 JWT signed with ``secret``."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = claims or {"sub": "test"}

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header_b64 = b64(json.dumps(header).encode())
    payload_b64 = b64(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    raw = f"{header_b64}.{payload_b64}.{b64(sig)}"
    return TokenInfo.from_string(raw)


class TestJwtCrackOptIn:
    def test_disabled_by_default(self) -> None:
        """Cracking is off until config.jwt_crack is True (L4)."""
        analyzer = JWTAnalyzer()
        token = _make_hs256_token("password123")

        class _Cfg:
            pass

        findings = analyzer._crack_hmac_secret(token, _Cfg())
        assert findings == []

    def test_enabled_can_crack(self) -> None:
        analyzer = JWTAnalyzer()
        analyzer.JWT_SECRET_WORDLIST = ["wrong1", "wrong2", "letmein", "wrong3"]
        token = _make_hs256_token("letmein")

        class _Cfg:
            jwt_crack = True
            jwt_crack_max_attempts = 100

        findings = analyzer._crack_hmac_secret(token, _Cfg())
        assert any("Cracked" in f.title for f in findings)

    def test_max_attempts_caps_the_loop(self) -> None:
        analyzer = JWTAnalyzer()
        analyzer.JWT_SECRET_WORDLIST = [f"wrong_{i}" for i in range(50)] + ["real"]
        token = _make_hs256_token("real")

        class _Cfg:
            jwt_crack = True
            jwt_crack_max_attempts = 10

        findings = analyzer._crack_hmac_secret(token, _Cfg())
        assert findings == []  # cap hides the secret

    def test_non_hs_algorithm_skipped(self) -> None:
        analyzer = JWTAnalyzer()
        analyzer.JWT_SECRET_WORDLIST = ["should-not-matter"]
        token = _make_hs256_token("x")
        token.algorithm = "RS256"

        class _Cfg:
            jwt_crack = True
            jwt_crack_max_attempts = 5000

        findings = analyzer._crack_hmac_secret(token, _Cfg())
        assert findings == []


# ---- L5: endpoint-probe caching -------------------------------------------


class _R:
    def __init__(self, status: int, body: str) -> None:
        self.status_code = status
        self.text = body


class TestEndpointCache:
    def test_cached_get_uses_cache_after_first_call(self) -> None:
        analyzer = JWTAnalyzer()
        analyzer._response_cache = {}  # type: ignore[attr-defined]
        calls: list[tuple[str, frozenset]] = []

        class _Client:
            def get(self, url, headers=None):
                calls.append((url, frozenset((headers or {}).items())))
                return _R(200, "hi")

        client = _Client()
        r1 = analyzer._cached_get(client, "/api/x", {"Authorization": "Bearer t"})
        r2 = analyzer._cached_get(client, "/api/x", {"Authorization": "Bearer t"})
        assert r1 is r2
        assert len(calls) == 1

    def test_different_headers_are_distinct_cache_keys(self) -> None:
        analyzer = JWTAnalyzer()
        analyzer._response_cache = {}  # type: ignore[attr-defined]
        calls: list[tuple[str, frozenset]] = []

        class _Client:
            def get(self, url, headers=None):
                calls.append((url, frozenset((headers or {}).items())))
                return _R(200, "ok")

        client = _Client()
        analyzer._cached_get(client, "/api/x", {"Authorization": "Bearer t1"})
        analyzer._cached_get(client, "/api/x", {"Authorization": "Bearer t2"})
        assert len(calls) == 2

    def test_errors_cached_as_none(self) -> None:
        analyzer = JWTAnalyzer()
        analyzer._response_cache = {}  # type: ignore[attr-defined]
        calls: list[str] = []

        class _Client:
            def get(self, url, headers=None):
                calls.append(url)
                raise RuntimeError("nope")

        client = _Client()
        r = analyzer._cached_get(client, "/api/x")
        assert r is None
        r2 = analyzer._cached_get(client, "/api/x")
        assert r2 is None
        assert len(calls) == 1

    def test_falls_through_without_cache_attr(self) -> None:
        """Defensive: helper still works if ``_response_cache`` is missing."""
        analyzer = JWTAnalyzer()
        # No ``_response_cache`` assignment — simulates calling outside run().

        class _Client:
            def get(self, url, headers=None):
                return _R(200, "ok")

        out = analyzer._cached_get(_Client(), "/api/x")
        assert out.status_code == 200
