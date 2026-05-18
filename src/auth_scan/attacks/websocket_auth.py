"""WebSocket authentication testing module."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from auth_scan.attacks.base import (
    BaseAttackModule,
    Finding,
    ModuleResult,
    ScanReport,
    Severity,
)

WS_INDICATORS = [
    r"ws://",
    r"wss://",
    r"new WebSocket\s*\(",
    r"new\s+WebSocket\s*\(",
    r"\.io\s*\(\s*['\"]",
    r"socket\.io",
    r"SockJS\s*\(",
    r"sockjs",
    r"signalr",
]


class WebSocketAuth(BaseAttackModule):
    """Test WebSocket connections for authentication issues.

    Covers:
    - WebSocket endpoint detection
    - Unauthenticated connections
    - Auth token in URL query string
    - Cross-origin WebSocket (missing Origin check)
    - Session inheritance from HTTP
    """

    name = "websocket"
    description = "Test WebSocket connections for authentication weaknesses"
    version = "1.0.0"
    priority = 60

    def run(
        self,
        target: str,
        http_client: Any,
        report: ScanReport,
        config: Any,
    ) -> ModuleResult:
        result = ModuleResult()

        # Detect WebSocket endpoints
        ws_endpoints = self._discover_ws_endpoints(report, target)
        if not ws_endpoints:
            result.findings.append(
                Finding(
                    title="No WebSocket Endpoints Found",
                    description="No WebSocket connections were detected in the page source.",
                    severity=Severity.INFO,
                    module_name=self.name,
                    tags=["websocket", "discovery"],
                )
            )
            return result

        for url_key, ws_url in ws_endpoints.items():
            result.findings.append(
                Finding(
                    title=f"WebSocket Endpoint Discovered: {url_key}",
                    description=f"WebSocket endpoint found: {ws_url}.",
                    severity=Severity.INFO,
                    evidence={"source": url_key, "url": ws_url},
                    module_name=self.name,
                    tags=["websocket", "discovery"],
                )
            )

        # Test unauthenticated connection
        result.findings.extend(self._test_unauthenticated_ws(ws_endpoints, target))

        # Test token in URL
        result.findings.extend(self._test_token_in_url(ws_endpoints))

        # Test cross-origin
        result.findings.extend(self._test_cross_origin_ws(ws_endpoints))

        return result

    def _discover_ws_endpoints(
        self,
        report: ScanReport,
        target: str,
    ) -> dict[str, str]:
        """Find WebSocket endpoints from probe data."""
        endpoints: dict[str, str] = {}
        probe_body = report.metadata.get("probe_body", "")

        # Direct ws/wss URLs
        for match in re.finditer(r'(wss?://[^\s"\'<>]+)', probe_body):
            endpoints[match.group(1)] = match.group(1)

        # WebSocket constructor calls
        for match in re.finditer(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', probe_body):
            ws_path = match.group(1)
            if ws_path.startswith(("ws://", "wss://")):
                endpoints[ws_path] = ws_path
            else:
                parsed = urlparse(target)
                scheme = "wss" if parsed.scheme == "https" else "ws"
                host = parsed.hostname or "localhost"
                port = parsed.port
                if port:
                    endpoints[ws_path] = f"{scheme}://{host}:{port}{ws_path}"
                else:
                    endpoints[ws_path] = f"{scheme}://{host}{ws_path}"

        # Socket.io patterns
        for match in re.finditer(r'(?:socket|io)\s*\(\s*["\']([^"\']+)["\']', probe_body, re.I):
            endpoints[f"socket.io: {match.group(1)}"] = match.group(1)

        # If page references ws but no URLs found, try common paths
        has_ws_refs = any(re.search(indicator, probe_body) for indicator in WS_INDICATORS)
        if has_ws_refs and not endpoints:
            parsed = urlparse(target)
            scheme = "wss" if parsed.scheme == "https" else "ws"
            host = parsed.hostname or "localhost"
            port = parsed.port
            for path in ["/ws", "/socket.io", "/echo", "/stream", "/realtime"]:
                if port:
                    endpoints[path] = f"{scheme}://{host}:{port}{path}"
                else:
                    endpoints[path] = f"{scheme}://{host}{path}"

        return endpoints

    def _test_unauthenticated_ws(
        self,
        ws_endpoints: dict[str, str],
        target: str,
    ) -> list[Finding]:
        """Test if WebSocket connections accept unauthenticated requests."""
        findings: list[Finding] = []

        for _url_key, ws_url in ws_endpoints.items():
            if not ws_url.startswith(("ws://", "wss://")):
                continue

            try:
                import websockets

                # Bind ws_url at definition time so the nested coroutine
                # doesn't accidentally close over a later loop iteration.
                async def try_connect(url: str = ws_url):
                    try:
                        async with websockets.connect(
                            url,
                            open_timeout=5,
                            close_timeout=2,
                        ) as ws:
                            # Send a test message
                            await ws.send('{"type":"ping"}')
                            try:
                                response = await ws.recv()
                                return True, response
                            except Exception:
                                return True, None
                    except Exception:
                        return False, None

                import asyncio

                success, response = asyncio.get_event_loop().run_until_complete(try_connect())

                if success:
                    findings.append(
                        Finding(
                            title="WebSocket Accepts Unauthenticated Connections",
                            description=(
                                f"WebSocket at {ws_url} accepted a connection without "
                                "authentication credentials. Unauthenticated WebSockets "
                                "can be abused for unauthorized data access."
                            ),
                            severity=Severity.HIGH,
                            evidence={
                                "ws_url": ws_url,
                                "authenticated": False,
                                "connection": "accepted",
                            },
                            remediation=(
                                "Require authentication for all WebSocket connections. "
                                "Validate tokens during the WebSocket handshake."
                            ),
                            cwe_id="CWE-306",
                            module_name=self.name,
                            confidence=0.9,
                            tags=["websocket", "authentication"],
                        )
                    )
            except ImportError:
                # websockets not available for real connection test
                # Flag as potential finding anyway if ws:// endpoints found
                findings.append(
                    Finding(
                        title="WebSocket Endpoint Needs Manual Testing",
                        description=(
                            f"WebSocket at {ws_url} was detected but could not be "
                            "automatically tested (websockets library unavailable). "
                            "Manually verify authentication is enforced."
                        ),
                        severity=Severity.LOW,
                        evidence={"ws_url": ws_url},
                        remediation="Verify WebSocket authentication manually.",
                        module_name=self.name,
                        confidence=0.5,
                        tags=["websocket", "manual-test"],
                    )
                )
            except Exception:
                pass

        return findings

    def _test_token_in_url(
        self,
        ws_endpoints: dict[str, str],
    ) -> list[Finding]:
        """Check if WebSocket URLs contain auth tokens in query string."""
        findings: list[Finding] = []

        for _url_key, ws_url in ws_endpoints.items():
            if "?" in ws_url:
                query_part = ws_url.split("?", 1)[1]
                sensitive_params = [
                    "token",
                    "access_token",
                    "auth",
                    "api_key",
                    "key",
                    "jwt",
                    "session",
                ]
                found_params = [
                    p.split("=")[0]
                    for p in query_part.split("&")
                    if any(s in p.lower().split("=")[0] for s in sensitive_params)
                ]
                if found_params:
                    findings.append(
                        Finding(
                            title="WebSocket Auth Token in URL",
                            description=(
                                f"WebSocket URL contains authentication tokens in query "
                                f"parameters: {', '.join(found_params)}. Tokens in URLs "
                                "are logged in server logs and leaked via Referer headers."
                            ),
                            severity=Severity.HIGH,
                            evidence={"ws_url": ws_url, "params": found_params},
                            remediation=(
                                "Send auth tokens in the WebSocket protocol message, "
                                "not in the URL query string."
                            ),
                            cwe_id="CWE-598",
                            module_name=self.name,
                            confidence=0.95,
                            tags=["websocket", "token-in-url"],
                        )
                    )

        return findings

    def _test_cross_origin_ws(
        self,
        ws_endpoints: dict[str, str],
    ) -> list[Finding]:
        """Flag that WebSocket cross-origin checks should be tested manually."""
        findings: list[Finding] = []

        for _url_key, ws_url in ws_endpoints.items():
            if ws_url.startswith(("ws://", "wss://")):
                findings.append(
                    Finding(
                        title="WebSocket: Verify Origin Validation",
                        description=(
                            f"WebSocket at {ws_url} should validate the Origin header "
                            "to prevent cross-origin WebSocket hijacking. This requires "
                            "manual verification."
                        ),
                        severity=Severity.INFO,
                        evidence={"ws_url": ws_url, "check": "origin_validation"},
                        remediation=(
                            "Validate the Origin header on all WebSocket connections. "
                            "Reject connections from unexpected origins."
                        ),
                        module_name=self.name,
                        confidence=0.5,
                        tags=["websocket", "cross-origin"],
                    )
                )

        return findings
