"""HTTPS-to-HTTP fallback safety (PR-3: H3/H4).

Pre-PR-3 behaviour:
  * `probe()` caught only `HttpError`, but `self.session.get(...)` raises
    `requests.exceptions.RequestException` subclasses (Timeout,
    ConnectionError, SSLError, etc.). The fallback path was effectively
    unreachable for the failures it was meant to handle.
  * When it *did* run, the fallback silently downgraded HTTPS → HTTP with
    no warning and no finding.

This module exercises both behaviours end-to-end.
"""

from __future__ import annotations

import pytest
import requests
import responses

from auth_scan.core.exceptions import HttpError
from auth_scan.core.http_client import HTTPClient


def _conn_err(message: str) -> requests.exceptions.ConnectionError:
    """Build a real requests ConnectionError; responses raises whatever we hand it."""
    return requests.exceptions.ConnectionError(message)


class TestProbeExceptionHandling:
    """H3: probe must catch RequestException, not only HttpError."""

    @responses.activate
    def test_probe_failure_without_fallback_raises_httperror(self) -> None:
        # responses.add with a body that raises an exception simulates
        # an underlying connection failure.
        responses.add(
            responses.GET,
            "https://example.com",
            body=_conn_err("simulated DNS failure"),
        )
        client = HTTPClient(
            base_url="https://example.com",
            rate_limit=100.0,
            allow_http_fallback=False,
        )
        with pytest.raises(HttpError, match="HTTPS probe failed"):
            client.probe()

    @responses.activate
    def test_probe_does_not_fall_back_when_opt_in_disabled(self) -> None:
        """Default behaviour: HTTPS failure does not silently retry over HTTP."""
        responses.add(
            responses.GET,
            "https://example.com",
            body=_conn_err("boom"),
        )
        # Even if the HTTP endpoint would have succeeded, we should not try it.
        responses.add(
            responses.GET,
            "http://example.com",
            body="ok",
            status=200,
        )
        client = HTTPClient(
            base_url="https://example.com",
            rate_limit=100.0,
            allow_http_fallback=False,
        )
        with pytest.raises(HttpError):
            client.probe()


class TestHttpFallbackOptIn:
    """H4: fallback only runs when opt-in, and surfaces as a finding."""

    @responses.activate
    def test_fallback_attempted_when_allowed(self) -> None:
        responses.add(
            responses.GET,
            "https://example.com",
            body=_conn_err("tls broken"),
        )
        responses.add(
            responses.GET,
            "http://example.com",
            body="<html>plain</html>",
            status=200,
        )
        client = HTTPClient(
            base_url="https://example.com",
            rate_limit=100.0,
            allow_http_fallback=True,
        )
        probe = client.probe()
        assert probe.http_fallback_attempted is True
        assert probe.final_url.rstrip("/") == "http://example.com"
        # The redirect_chain records the downgrade for the report.
        assert any("https://example.com -> http://example.com" in hop for hop in probe.redirect_chain)

    @responses.activate
    def test_fallback_failure_still_raises(self) -> None:
        """If both HTTPS and HTTP fail, raise HttpError (don't return junk)."""
        responses.add(
            responses.GET,
            "https://example.com",
            body=_conn_err("tls broken"),
        )
        responses.add(
            responses.GET,
            "http://example.com",
            body=_conn_err("network down"),
        )
        client = HTTPClient(
            base_url="https://example.com",
            rate_limit=100.0,
            allow_http_fallback=True,
        )
        with pytest.raises(HttpError, match="Failed to probe target"):
            client.probe()

    @responses.activate
    def test_no_fallback_for_http_target(self) -> None:
        """An HTTP target that fails has nothing to fall back to."""
        responses.add(
            responses.GET,
            "http://example.com",
            body=_conn_err("boom"),
        )
        client = HTTPClient(
            base_url="http://example.com",
            rate_limit=100.0,
            allow_http_fallback=True,
        )
        with pytest.raises(HttpError):
            client.probe()

    @responses.activate
    def test_fallback_attempted_false_when_https_succeeds(self) -> None:
        """Happy path: no fallback recorded if HTTPS works."""
        responses.add(
            responses.GET,
            "https://example.com",
            body="<html>secure</html>",
            status=200,
        )
        client = HTTPClient(
            base_url="https://example.com",
            rate_limit=100.0,
            allow_http_fallback=True,
        )
        probe = client.probe()
        assert probe.http_fallback_attempted is False
        # requests appends a trailing slash on bare hosts; either is fine.
        assert probe.final_url.rstrip("/") == "https://example.com"


class TestEngineSurfacesFallbackAsFinding:
    """H4 integration: ScanEngine adds the MEDIUM finding from the probe."""

    @responses.activate
    def test_scanner_fallback_finding_emitted(self) -> None:
        from auth_scan.core.config import ScanConfig
        from auth_scan.core.engine import ScanEngine

        responses.add(
            responses.GET,
            "https://example.com",
            body=_conn_err("tls broken"),
        )
        responses.add(
            responses.GET,
            "http://example.com",
            body="<html>ok</html>",
            status=200,
        )
        cfg = ScanConfig(
            target="https://example.com",
            modules=["probe"],
            rate_limit=100,
            timeout=5,
            allow_http_fallback=True,
        )
        engine = ScanEngine(cfg)
        report = engine.run()
        titles = [f.title for f in report.findings]
        assert any("Scanner HTTPS-to-HTTP Fallback" in t for t in titles), titles

    @responses.activate
    def test_no_fallback_finding_when_https_works(self) -> None:
        from auth_scan.core.config import ScanConfig
        from auth_scan.core.engine import ScanEngine

        responses.add(
            responses.GET,
            "https://example.com",
            body="<html>secure</html>",
            status=200,
        )
        cfg = ScanConfig(
            target="https://example.com",
            modules=["probe"],
            rate_limit=100,
            timeout=5,
            allow_http_fallback=True,
        )
        engine = ScanEngine(cfg)
        report = engine.run()
        titles = [f.title for f in report.findings]
        assert "Scanner HTTPS-to-HTTP Fallback" not in titles
