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

    def test_report_discoveries_200(self) -> None:
        findings: list = []
        results = {"/login": {"status": 200, "length": 500, "headers": {}, "interesting": True}}
        report_discoveries(findings, results)
        assert len(findings) >= 1
        assert any("200" in f.title for f in findings)

    def test_report_discoveries_401(self) -> None:
        findings: list = []
        results = {"/api/admin": {"status": 401, "length": 100, "headers": {}, "interesting": True}}
        report_discoveries(findings, results)
        assert len(findings) >= 1
        assert any("401" in f.title for f in findings)
