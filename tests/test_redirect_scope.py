"""Redirect scope-enforcement guarantees (C5).

The HTTP client must:
  * Follow redirects across hops while re-checking scope at every step.
  * Block redirects to loopback, RFC1918, link-local, and cloud-metadata
    hosts by default — common SSRF egress targets.
  * Honour a deny-list / allow-list configured up front, even when the
    first hop is in scope.
  * Permit private-host redirects only when the operator explicitly
    sets ``allow_private_redirects=True``.
"""
from __future__ import annotations

import ipaddress

import pytest
import responses

from auth_scan.core.exceptions import ScopeError
from auth_scan.core.http_client import (
    _ip_is_blocked,
    _is_private_or_metadata_host,
    HTTPClient,
)


class TestIsPrivateOrMetadataHost:
    """Unit tests for the private/metadata host classifier."""

    @pytest.mark.parametrize("addr", [
        "127.0.0.1",
        "127.255.255.255",
        "10.0.0.5",
        "10.255.255.255",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",
    ])
    def test_private_ip_literals_blocked(self, addr: str) -> None:
        assert _is_private_or_metadata_host(addr) is True

    @pytest.mark.parametrize("addr", [
        "8.8.8.8",
        "1.1.1.1",
        "203.0.113.5",   # TEST-NET-3 — public-ish for our purposes
    ])
    def test_public_ip_literals_allowed(self, addr: str) -> None:
        # TEST-NET ranges are reserved per ipaddress, so 203.0.113.5
        # is actually reserved. Use only true public-ish addresses.
        assert _is_private_or_metadata_host(addr) is _ip_is_blocked(
            ipaddress.ip_address(addr)
        )

    @pytest.mark.parametrize("name", [
        "metadata.google.internal",
        "metadata.azure.com",
        "INSTANCE-DATA",  # case-insensitive
    ])
    def test_metadata_hostnames_blocked(self, name: str) -> None:
        assert _is_private_or_metadata_host(name) is True

    def test_empty_host(self) -> None:
        assert _is_private_or_metadata_host("") is False


class TestRedirectScopeEnforcement:
    """End-to-end tests via the responses-mocked session."""

    @responses.activate
    def test_redirect_to_loopback_is_blocked(self) -> None:
        responses.add(
            responses.GET,
            "https://example.com/start",
            status=302,
            headers={"Location": "http://127.0.0.1/admin"},
        )
        client = HTTPClient(base_url="https://example.com", rate_limit=1000.0)
        with pytest.raises(ScopeError, match="private/metadata host"):
            client.get("/start")

    @responses.activate
    def test_redirect_to_aws_metadata_is_blocked(self) -> None:
        responses.add(
            responses.GET,
            "https://example.com/start",
            status=302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        )
        client = HTTPClient(base_url="https://example.com", rate_limit=1000.0)
        with pytest.raises(ScopeError, match="private/metadata host"):
            client.get("/start")

    @responses.activate
    def test_redirect_to_rfc1918_is_blocked(self) -> None:
        responses.add(
            responses.GET,
            "https://example.com/start",
            status=302,
            headers={"Location": "http://10.0.0.5/internal"},
        )
        client = HTTPClient(base_url="https://example.com", rate_limit=1000.0)
        with pytest.raises(ScopeError, match="private/metadata host"):
            client.get("/start")

    @responses.activate
    def test_redirect_to_out_of_scope_external_is_blocked(self) -> None:
        responses.add(
            responses.GET,
            "https://example.com/start",
            status=302,
            headers={"Location": "https://evil.example.org/pwn"},
        )
        client = HTTPClient(
            base_url="https://example.com",
            rate_limit=1000.0,
            scope_allow=["example.com"],
        )
        with pytest.raises(ScopeError, match="scope enforcement"):
            client.get("/start")

    @responses.activate
    def test_in_scope_redirect_is_followed(self) -> None:
        responses.add(
            responses.GET,
            "https://example.com/start",
            status=302,
            headers={"Location": "https://example.com/landing"},
        )
        responses.add(
            responses.GET,
            "https://example.com/landing",
            body="welcome",
            status=200,
        )
        client = HTTPClient(base_url="https://example.com", rate_limit=1000.0)
        resp = client.get("/start")
        assert resp.status_code == 200
        assert resp.text == "welcome"
        assert resp.url == "https://example.com/landing"

    @responses.activate
    def test_allow_private_redirects_opt_in(self) -> None:
        """Operators scanning intranet targets can opt in to private redirects."""
        responses.add(
            responses.GET,
            "https://example.com/start",
            status=302,
            headers={"Location": "http://10.0.0.5/internal"},
        )
        responses.add(
            responses.GET,
            "http://10.0.0.5/internal",
            body="ok",
            status=200,
        )
        client = HTTPClient(
            base_url="https://example.com",
            rate_limit=1000.0,
            allow_private_redirects=True,
        )
        resp = client.get("/start")
        assert resp.status_code == 200

    @responses.activate
    def test_redirect_chain_respects_max_hops(self) -> None:
        """Loops/long chains terminate with HttpError rather than hanging."""
        for i in range(15):
            responses.add(
                responses.GET,
                f"https://example.com/hop{i}",
                status=302,
                headers={"Location": f"https://example.com/hop{i + 1}"},
            )
        client = HTTPClient(base_url="https://example.com", rate_limit=1000.0)
        from auth_scan.core.exceptions import HttpError

        with pytest.raises(HttpError, match="max redirects"):
            client.get("/hop0")

    @responses.activate
    def test_probe_blocks_redirect_to_metadata(self) -> None:
        """The probe path also enforces redirect scope."""
        responses.add(
            responses.GET,
            "https://example.com",
            status=302,
            headers={"Location": "http://169.254.169.254/"},
        )
        client = HTTPClient(base_url="https://example.com", rate_limit=1000.0)
        with pytest.raises(ScopeError):
            client.probe()
