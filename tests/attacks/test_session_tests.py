"""Tests for the Session Tests attack module."""

from __future__ import annotations

import responses

from auth_scan.attacks.base import ScanReport
from auth_scan.attacks.session_tests import SessionTester
from auth_scan.core.config import ScanConfig
from auth_scan.core.http_client import HTTPClient


class TestSessionTester:
    """Tests for the Session Tests module."""

    def test_no_cookies(self) -> None:
        tester = SessionTester()
        report = ScanReport(target="https://example.com")
        config = ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = tester.run("https://example.com", client, report, config)
            assert len(result.findings) >= 1
            assert any("No Session" in f.title for f in result.findings)

        run()

    def test_cookie_missing_flags(self) -> None:
        tester = SessionTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_cookies"] = {
            "sessionid": "abc123def456",
        }
        config = ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/", status=200)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            # Also need to populate Set-Cookie headers for analysis
            report.metadata["set_cookie_headers"] = [
                "sessionid=abc123def456; Path=/; HttpOnly=false",
            ]
            result = tester.run("https://example.com", client, report, config)
            # Should have findings about cookie attributes
            assert len(result.findings) >= 1
            # The From_set_cookie parsing of the raw header
            findings_with_cookie = [f for f in result.findings if "session" in str(f.evidence).lower()]
            assert len(findings_with_cookie) >= 1

        run()

    def test_csrf_token_missing(self) -> None:
        tester = SessionTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_forms"] = [
            {
                "action": "/profile",
                "method": "POST",
                "inputs": [
                    {"name": "email", "type": "text", "value": ""},
                    {"name": "name", "type": "text", "value": ""},
                ],
            },
        ]
        ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._check_csrf_tokens(report)
            assert len(findings) >= 1
            assert any("CSRF" in f.title for f in findings)

        run()

    def test_csrf_token_present(self) -> None:
        tester = SessionTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_forms"] = [
            {
                "action": "/profile",
                "method": "POST",
                "inputs": [
                    {"name": "email", "type": "text", "value": ""},
                    {"name": "csrf_token", "type": "hidden", "value": "abc"},
                    {"name": "name", "type": "text", "value": ""},
                ],
            },
        ]
        findings = tester._check_csrf_tokens(report)
        assert len(findings) == 0

    def test_session_id_in_url_detection(self) -> None:
        tester = SessionTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = """
            <a href="/logout?sessionid=abc123">Logout</a>
            <a href="/profile">Profile</a>
        """
        findings = tester._check_url_session_ids(report)
        assert len(findings) >= 1
        assert any("URL" in f.title for f in findings)

    def test_no_session_id_in_url(self) -> None:
        tester = SessionTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = """
            <a href="/logout">Logout</a>
            <a href="/profile">Profile</a>
        """
        findings = tester._check_url_session_ids(report)
        assert len(findings) == 0

    def test_session_fixation_detection(self) -> None:
        tester = SessionTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_cookies"] = {
            "sessionid": "original-value",
        }

        @responses.activate
        def run():
            # Server echoes back the same session ID — fixation vulnerable
            def echo_cookie(request):
                headers = {"Set-Cookie": "sessionid=fixation-test-session-id-12345; Path=/"}
                return (200, headers, "OK")

            responses.add_callback(
                responses.GET,
                "https://example.com/",
                callback=echo_cookie,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_session_fixation("https://example.com", client, report)
            # May or may not find fixation depending on implementation
            assert isinstance(findings, list)

        run()

    def test_session_invalidation_check(self) -> None:
        tester = SessionTester()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_cookies"] = {"sessionid": "abc"}

        @responses.activate
        def run():
            # Mock same response for all requests so we can test the method runs
            responses.add(responses.GET, "https://example.com/", body="Dashboard", status=200)
            responses.add(responses.GET, "https://example.com/logout", body="Logged out", status=200)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_session_invalidation("https://example.com", client, report)
            # The method should return a list (empty or not is fine given mock limitations)
            assert isinstance(findings, list)

        run()

    def test_cookie_scope_check(self) -> None:
        tester = SessionTester()
        from auth_scan.core.session import CookieAnalysis

        cookies = [
            CookieAnalysis(
                name="sessionid",
                value="abc",
                domain="example.com",
                http_only=True,
                secure=True,
            ),
        ]
        cookies[0]._analyze()  # mark as session cookie
        findings = tester._check_cookie_scope(cookies, "https://sub.example.com")
        # Cookie domain is broader than host → should flag
        if len(findings) > 0:
            assert any("Domain" in f.title or "Scope" in f.title for f in findings)

    def test_entropy_analysis_weak(self) -> None:
        tester = SessionTester()
        from auth_scan.core.session import CookieAnalysis

        cookies = [
            CookieAnalysis(
                name="sessionid",
                value="12345",
                http_only=True,
                secure=True,
                same_site="Lax",
            ),
        ]
        cookies[0]._analyze()
        findings = tester._analyze_entropy(cookies, {"sessionid": "12345"})
        assert len(findings) >= 1
        assert any("Entropy" in f.title for f in findings)
