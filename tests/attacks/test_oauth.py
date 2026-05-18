"""Tests for OAuth tester module."""

from __future__ import annotations

import responses

from auth_scan.attacks.base import ScanReport
from auth_scan.attacks.oauth import OAuthTester
from auth_scan.core.config import ScanConfig
from auth_scan.core.http_client import HTTPClient


class TestOAuthTester:
    """Tests for the OAuth tester module."""

    def test_discover_from_well_known(self) -> None:
        tester = OAuthTester()
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://example.com/.well-known/openid-configuration",
                json={
                    "issuer": "https://example.com",
                    "authorization_endpoint": "https://example.com/oauth/authorize",
                    "token_endpoint": "https://example.com/oauth/token",
                },
                status=200,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            endpoints = tester._discover_oauth_endpoints("https://example.com", client, report)
            assert "authorization_endpoint" in endpoints
            assert endpoints["authorization_endpoint"] == "https://example.com/oauth/authorize"

        run()

    def test_no_oauth_endpoints(self) -> None:
        tester = OAuthTester()
        report = ScanReport(target="https://example.com")
        config = ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = tester.run("https://example.com", client, report, config)
            assert any("No OAuth" in f.title for f in result.findings)

        run()

    def test_missing_state_detection(self) -> None:
        tester = OAuthTester()

        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://example.com/oauth/authorize",
                body="Login page",
                status=200,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_missing_state(
                "https://example.com/oauth/authorize", client, "https://example.com"
            )
            assert len(findings) >= 1
            assert any("state" in f.title.lower() or "CSRF" in f.title for f in findings)

        run()

    def test_open_redirect_detection(self) -> None:
        tester = OAuthTester()

        @responses.activate
        def run():
            def redirect_callback(request):
                # Simulate server redirecting to attacker
                return (302, {"Location": "https://evil.com/callback?code=test"}, "")

            responses.add_callback(
                responses.GET,
                "https://example.com/oauth/authorize",
                callback=redirect_callback,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_redirect_uri(
                "https://example.com/oauth/authorize", client, "https://example.com"
            )
            assert len(findings) >= 1
            assert any("redirect" in f.title.lower() for f in findings)

        run()

    def test_client_secret_detection(self) -> None:
        tester = OAuthTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = 'var CLIENT_SECRET = "abc123secret";'

        findings = tester._check_client_secret_exposure(report, "https://example.com")
        assert len(findings) >= 1

    def test_implicit_flow_detection(self) -> None:
        tester = OAuthTester()

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/oauth/authorize", status=200)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_implicit_flow(
                "https://example.com/oauth/authorize", client, "https://example.com"
            )
            assert len(findings) >= 1
            assert any("implicit" in f.title.lower() for f in findings)

        run()

    def test_pkce_not_required(self) -> None:
        tester = OAuthTester()

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/oauth/authorize", status=302)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_missing_pkce(
                "https://example.com/oauth/authorize", client, "https://example.com"
            )
            assert len(findings) >= 1
            assert any("PKCE" in f.title for f in findings)

        run()
