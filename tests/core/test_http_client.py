"""Tests for HTTP client."""
from __future__ import annotations

import responses

from auth_scan.core.http_client import HTTPClient, RateLimiter, ScopeEnforcer


class TestRateLimiter:
    """Tests for the token-bucket rate limiter."""

    def test_initial_acquire_is_instant(self) -> None:
        limiter = RateLimiter(rate=10.0)
        delay = limiter.acquire()
        assert delay == 0.0

    def test_acquire_exhausts_tokens(self) -> None:
        limiter = RateLimiter(rate=10.0)
        delays = []
        for _ in range(20):
            delays.append(limiter.acquire())
        # First 10 should be instant, later should need waiting
        assert delays[0] == 0.0
        assert delays[9] == 0.0
        assert any(d > 0 for d in delays[10:])

    def test_high_rate_always_instant(self) -> None:
        limiter = RateLimiter(rate=1000.0)
        for _ in range(100):
            assert limiter.acquire() == 0.0


class TestScopeEnforcer:
    """Tests for scope enforcement."""

    def test_no_rules_allows_all(self) -> None:
        enforcer = ScopeEnforcer()
        assert enforcer.is_allowed("https://anything.com/path")

    def test_allowlist_blocks_unlisted(self) -> None:
        enforcer = ScopeEnforcer(allowlist=["example.com"])
        assert enforcer.is_allowed("https://example.com/page")
        assert not enforcer.is_allowed("https://other.com/page")

    def test_denylist_takes_precedence(self) -> None:
        enforcer = ScopeEnforcer(allowlist=["example.com"], denylist=["evil.example.com"])
        assert enforcer.is_allowed("https://example.com/page")
        assert not enforcer.is_allowed("https://evil.example.com/page")

    def test_subdomain_match(self) -> None:
        enforcer = ScopeEnforcer(allowlist=[".example.com"])
        assert enforcer.is_allowed("https://sub.example.com/page")
        assert enforcer.is_allowed("https://example.com/page")

    def test_ip_match(self) -> None:
        enforcer = ScopeEnforcer(allowlist=["192.168.1.1"])
        assert enforcer.is_allowed("https://192.168.1.1/page")
        assert not enforcer.is_allowed("https://192.168.1.2/page")


class TestHTTPClient:
    """Tests for the HTTP client with mocked responses."""

    @responses.activate
    def test_get_request(self) -> None:
        responses.add(responses.GET, "https://example.com/test", json={"ok": True}, status=200)
        client = HTTPClient(base_url="https://example.com")
        resp = client.get("/test")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    @responses.activate
    def test_request_id_header(self) -> None:
        def verify_header(request):
            assert "X-Request-ID" in request.headers
            return (200, {}, '{"ok": true}')

        responses.add_callback(responses.GET, "https://example.com/api", callback=verify_header)
        client = HTTPClient(base_url="https://example.com")
        resp = client.get("/api")
        assert resp.status_code == 200

    @responses.activate
    def test_proxy_configuration(self) -> None:
        responses.add(responses.GET, "https://example.com/", json={"ok": True})
        client = HTTPClient(base_url="https://example.com", proxy="http://127.0.0.1:8080")
        assert "http://127.0.0.1:8080" in str(client.session.proxies)

    @responses.activate
    def test_rate_limit_is_applied(self) -> None:
        responses.add(responses.GET, "https://example.com/test", json={"ok": True})
        client = HTTPClient(base_url="https://example.com", rate_limit=5.0)
        resp = client.get("/test")
        assert resp.status_code == 200
        assert len(client.request_history) == 1

    @responses.activate
    def test_timeout_error_handling(self) -> None:
        import requests as req
        from auth_scan.core.exceptions import HttpError

        def slow_response(request):
            raise req.exceptions.Timeout("timed out")

        responses.add_callback(responses.GET, "https://example.com/slow", callback=slow_response)
        client = HTTPClient(base_url="https://example.com", timeout=1)
        try:
            client.get("/slow")
            assert False, "Should have raised HttpError"
        except HttpError:
            assert len(client.request_history) == 1
            assert "Timeout" in client.request_history[0].error

    @responses.activate
    def test_connection_error_handling(self) -> None:
        import requests as req
        from auth_scan.core.exceptions import HttpError

        def conn_refused(request):
            raise req.exceptions.ConnectionError("Connection refused")

        responses.add_callback(responses.GET, "https://example.com/", callback=conn_refused)
        client = HTTPClient(base_url="https://example.com")
        try:
            client.get("/")
            assert False, "Should have raised HttpError"
        except HttpError as e:
            assert "Connection failed" in str(e)

    @responses.activate
    def test_scope_blocked_request(self) -> None:
        from auth_scan.core.exceptions import ScopeError

        client = HTTPClient(
            base_url="https://example.com",
            scope_allow=["example.com"],
        )
        try:
            client.get("https://evil.com/data")
            assert False, "Should have raised ScopeError"
        except ScopeError as e:
            assert "blocked by scope" in str(e)

    @responses.activate
    def test_head_request(self) -> None:
        responses.add(responses.HEAD, "https://example.com/", status=200, headers={"X-Test": "yes"})
        client = HTTPClient(base_url="https://example.com")
        resp = client.head("/")
        assert resp.status_code == 200
        assert resp.headers["X-Test"] == "yes"

    @responses.activate
    def test_request_history_tracking(self) -> None:
        responses.add(responses.GET, "https://example.com/page1", json={"page": 1})
        responses.add(responses.GET, "https://example.com/page2", json={"page": 2})
        client = HTTPClient(base_url="https://example.com")
        client.get("/page1")
        client.get("/page2")
        assert len(client.request_history) == 2
        assert client.request_history[0].status_code == 200
        assert client.request_history[1].status_code == 200
