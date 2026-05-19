"""OAuth discovery regex + scope encoding (PR-4: H6/H7).

H6: the page-source regex for discovering OAuth endpoints was capturing
the optional quote character as group 1 and using it as the dict key,
so legitimately-discovered endpoints landed under '' / "'" / '"' and
were never consumed downstream.

H7: the default OAuth scope value was pre-URL-encoded
("admin%20profile%20email%20openid"). ``requests`` then encoded it
again, producing "admin%2520..." on the wire, which corrupted scope
escalation tests.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import responses

from auth_scan.attacks.base import ScanReport
from auth_scan.attacks.oauth import OAuthTester


class TestOauthEndpointDiscoveryRegex:
    """H6: keys must be the endpoint *name*, not the captured quote char."""

    def _discover(self, body: str) -> dict[str, str]:
        # Drive only the page-source discovery branch by passing a minimal
        # report. We don't care about probe headers or path-discovery for
        # this assertion; we just want to see the regex-derived keys.
        tester = OAuthTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = body

        # Stub HTTP client — discovery should not need it for this branch.
        class _DummyClient:
            def get(self, *a, **kw):  # pragma: no cover - shouldn't be hit
                raise AssertionError("discovery should not call http for regex branch")

        return tester._discover_oauth_endpoints(
            target="https://example.com",
            http_client=_DummyClient(),
            report=report,
        )

    def test_double_quoted_endpoints(self) -> None:
        body = (
            '{"authorization_endpoint": "https://idp.example.com/authorize",'
            ' "token_endpoint": "https://idp.example.com/token",'
            ' "userinfo_endpoint": "https://idp.example.com/userinfo",'
            ' "issuer": "https://idp.example.com"}'
        )
        endpoints = self._discover(body)
        # The pre-fix bug used the captured quote char as the key.
        assert '"' not in endpoints
        assert "'" not in endpoints
        assert "" not in endpoints
        for name in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "issuer"):
            assert endpoints.get(name, "").startswith("https://idp.example.com"), endpoints

    def test_single_quoted_endpoints(self) -> None:
        body = "authorization_endpoint='https://idp.example.com/authorize'"
        endpoints = self._discover(body)
        assert endpoints.get("authorization_endpoint") == "https://idp.example.com/authorize"

    def test_unquoted_endpoints(self) -> None:
        body = "token_endpoint = https://idp.example.com/token"
        endpoints = self._discover(body)
        assert endpoints.get("token_endpoint") == "https://idp.example.com/token"

    def test_trailing_punctuation_stripped(self) -> None:
        body = '"authorization_endpoint": "https://idp.example.com/authorize",'
        endpoints = self._discover(body)
        # Comma/semicolon at the URL tail should not contaminate the value.
        assert endpoints.get("authorization_endpoint") == "https://idp.example.com/authorize"


class TestOauthScopeEncoding:
    """H7: default scope is plain text so requests handles encoding once."""

    @responses.activate
    def test_default_scope_is_single_encoded(self) -> None:
        captured: dict[str, str] = {}

        def callback(request):
            captured["query"] = urlparse(request.url).query
            return (302, {"Location": "https://example.com/callback?code=x&state=scope-test"}, "")

        responses.add_callback(
            responses.GET,
            "https://idp.example.com/authorize",
            callback=callback,
        )

        tester = OAuthTester()

        # Minimal config object with no oauth_scope attribute -> default applies.
        class _Cfg:
            pass

        from auth_scan.core.http_client import HTTPClient

        client = HTTPClient(
            base_url="https://idp.example.com", rate_limit=100.0, allow_private_redirects=True
        )
        tester._test_scope_escalation(
            auth_url="https://idp.example.com/authorize",
            http_client=client,
            target="https://example.com",
            config=_Cfg(),
        )
        # The encoded query must contain "scope=admin+profile+email+openid"
        # (or %20). It must NOT contain double-encoding "%2520".
        q = captured["query"]
        assert "scope=" in q, q
        assert "%2520" not in q, f"double-encoded scope: {q}"
        parsed = parse_qs(q)
        # parse_qs decodes once — we must get the raw four scopes.
        assert parsed.get("scope") == ["admin profile email openid"], parsed

    @responses.activate
    def test_explicit_scope_override_via_config(self) -> None:
        captured: dict[str, str] = {}

        def callback(request):
            captured["query"] = urlparse(request.url).query
            return (200, {}, "")

        responses.add_callback(
            responses.GET,
            "https://idp.example.com/authorize",
            callback=callback,
        )

        tester = OAuthTester()

        class _Cfg:
            oauth_scope = "openid email"

        from auth_scan.core.http_client import HTTPClient

        client = HTTPClient(
            base_url="https://idp.example.com", rate_limit=100.0, allow_private_redirects=True
        )
        tester._test_scope_escalation(
            auth_url="https://idp.example.com/authorize",
            http_client=client,
            target="https://example.com",
            config=_Cfg(),
        )
        q = captured["query"]
        assert "%2520" not in q
        assert parse_qs(q).get("scope") == ["openid email"]
