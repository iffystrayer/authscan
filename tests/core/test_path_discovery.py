"""Tests for path discovery."""

from __future__ import annotations

import responses

from auth_scan.core.http_client import HTTPClient
from auth_scan.core.path_discovery import AUTH_PATHS, discover_paths, report_discoveries


class TestPathDiscovery:
    """Tests for path discovery functionality."""

    def test_auth_paths_not_empty(self) -> None:
        assert len(AUTH_PATHS) > 50

    def test_discover_paths(self) -> None:
        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", status=200)
            responses.add(responses.GET, "https://example.com/admin", status=403)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            results = discover_paths(client, paths=["/login", "/admin"], timeout_per=3)
            assert len(results) == 2
            assert results["/login"]["status"] == 200
            assert results["/login"]["interesting"] is True
            assert results["/admin"]["status"] == 403
            assert results["/admin"]["interesting"] is True

        run()

    def test_discover_404_not_interesting(self) -> None:
        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/nonexistent", status=404)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            results = discover_paths(client, paths=["/nonexistent"], timeout_per=3)
            assert results["/nonexistent"]["interesting"] is False

        run()

    def test_report_discoveries_suppresses_expected_auth_endpoint_200(self) -> None:
        """A 200 on /login etc. is normal app structure, not a finding (PR-13).

        Before PR-13 every 200 from AUTH_PATHS emitted an INFO finding, which
        on vuln_app produced 11 noise items in a 26-finding report. The fix
        suppresses expected endpoints; raw data still lives in
        report.metadata['path_results'] for operators who want it.
        """
        findings: list = []
        results = {"/login": {"status": 200, "length": 500, "headers": {}, "interesting": True}}
        report_discoveries(findings, results)
        assert findings == []

    def test_report_discoveries_sensitive_path_200_is_high(self) -> None:
        """A 200 on /.env IS a finding — HIGH severity, with remediation."""
        from auth_scan.attacks.base import Severity

        findings: list = []
        results = {"/.env": {"status": 200, "length": 200, "headers": {}, "interesting": True}}
        report_discoveries(findings, results)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "/.env" in findings[0].title
        assert findings[0].remediation

    def test_report_discoveries_admin_panel_200_is_medium(self) -> None:
        """A 200 on /phpmyadmin is sensitive but not VCS/secret-grade."""
        from auth_scan.attacks.base import Severity

        findings: list = []
        results = {"/phpmyadmin": {"status": 200, "length": 1000, "headers": {}, "interesting": True}}
        report_discoveries(findings, results)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_report_discoveries_oidc_discovery_endpoint_is_info(self) -> None:
        """OIDC/OAuth metadata endpoints are recorded as INFO discoveries."""
        from auth_scan.attacks.base import Severity

        findings: list = []
        results = {
            "/.well-known/openid-configuration": {
                "status": 200,
                "length": 500,
                "headers": {},
                "interesting": True,
            }
        }
        report_discoveries(findings, results)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "metadata" in findings[0].tags or "discovery" in findings[0].tags

    def test_report_discoveries_unknown_path_200_emitted_as_info(self) -> None:
        """Paths NOT in expected/sensitive/discovery lists still surface as INFO."""
        from auth_scan.attacks.base import Severity

        findings: list = []
        results = {"/some/random/path": {"status": 200, "length": 50, "headers": {}, "interesting": True}}
        report_discoveries(findings, results)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_report_discoveries_same_origin_redirect_suppressed(self) -> None:
        """A 302 to the same origin is normal auth-flow plumbing, not a finding."""
        findings: list = []
        results = {
            "/dashboard": {
                "status": 302,
                "length": 0,
                "headers": {"Location": "https://example.com/login"},
                "interesting": True,
            }
        }
        report_discoveries(findings, results, target_url="https://example.com")
        assert findings == []

    def test_report_discoveries_offsite_redirect_is_emitted(self) -> None:
        """A 302 to a different host is genuinely interesting."""
        findings: list = []
        results = {
            "/sso": {
                "status": 302,
                "length": 0,
                "headers": {"Location": "https://idp.other-domain.com/oauth/authorize"},
                "interesting": True,
            }
        }
        report_discoveries(findings, results, target_url="https://example.com")
        assert len(findings) == 1
        assert "Off-Origin" in findings[0].title

    def test_report_discoveries_401(self) -> None:
        """401 always emitted — proves a protected resource exists."""
        findings: list = []
        results = {"/api/admin": {"status": 401, "length": 100, "headers": {}, "interesting": True}}
        report_discoveries(findings, results)
        assert len(findings) == 1
        assert "401" in findings[0].title

    def test_report_discoveries_403_emitted_as_low(self) -> None:
        from auth_scan.attacks.base import Severity

        findings: list = []
        results = {"/admin/secret": {"status": 403, "length": 100, "headers": {}, "interesting": True}}
        report_discoveries(findings, results)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_report_discoveries_empty_means_no_finding(self) -> None:
        """No interesting paths -> no findings (used to emit a 'no interesting'
        placeholder that just added noise to clean scans)."""
        findings: list = []
        report_discoveries(findings, {})
        assert findings == []

    def test_report_discoveries_full_vuln_app_shape(self) -> None:
        """Sanity: simulate vuln_app's 11-noisy-finding scenario and confirm
        the new filter keeps only the genuinely-interesting subset."""
        results = {
            # Expected auth endpoints — all should be suppressed.
            "/login": {"status": 200, "length": 500, "headers": {}, "interesting": True},
            "/register": {"status": 200, "length": 500, "headers": {}, "interesting": True},
            "/logout": {"status": 302, "length": 0, "headers": {"Location": "/login"}, "interesting": True},
            "/profile": {"status": 200, "length": 500, "headers": {}, "interesting": True},
            "/dashboard": {"status": 200, "length": 500, "headers": {}, "interesting": True},
            # Real findings — should all be kept.
            "/.env": {"status": 200, "length": 100, "headers": {}, "interesting": True},
            "/admin": {"status": 401, "length": 50, "headers": {}, "interesting": True},
        }
        findings: list = []
        report_discoveries(findings, results, target_url="https://example.com")
        # Exactly the two real findings, no noise.
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert any("/.env" in t for t in titles)
        assert any("/admin" in t and "401" in t for t in titles)
