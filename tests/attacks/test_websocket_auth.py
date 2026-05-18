"""Tests for WebSocket auth module."""

from __future__ import annotations

from auth_scan.attacks.base import ScanReport
from auth_scan.attacks.websocket_auth import WebSocketAuth


class TestWebSocketAuth:
    """Tests for the WebSocket auth module."""

    def test_discover_ws_in_page(self) -> None:
        tester = WebSocketAuth()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = """
            <script>
                var socket = new WebSocket("wss://example.com/ws/chat");
            </script>
        """
        endpoints = tester._discover_ws_endpoints(report, "https://example.com")
        assert len(endpoints) >= 1
        assert any("wss://" in url for url in endpoints.values())

    def test_discover_ws_relative_path(self) -> None:
        tester = WebSocketAuth()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = """
            var ws = new WebSocket("/ws/echo");
        """
        endpoints = tester._discover_ws_endpoints(report, "https://example.com")
        assert len(endpoints) >= 1
        assert any("wss://example.com" in url for url in endpoints.values())

    def test_no_ws_found(self) -> None:
        tester = WebSocketAuth()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = "<html><body>Hello</body></html>"
        endpoints = tester._discover_ws_endpoints(report, "https://example.com")
        assert len(endpoints) == 0

    def test_token_in_url_detection(self) -> None:
        tester = WebSocketAuth()
        endpoints = {
            "test": "wss://example.com/ws?token=abc123&other=value",
        }
        findings = tester._test_token_in_url(endpoints)
        assert len(findings) >= 1
        assert any("token" in f.title.lower() or "URL" in f.title for f in findings)

    def test_cross_origin_flag(self) -> None:
        tester = WebSocketAuth()
        endpoints = {
            "test": "wss://example.com/ws",
        }
        findings = tester._test_cross_origin_ws(endpoints)
        assert len(findings) >= 1
        assert any("Origin" in f.title or "origin" in f.title.lower() for f in findings)
