"""Tests for MFA bypass module."""
from __future__ import annotations

import responses

from auth_scan.attacks.base import ScanReport
from auth_scan.attacks.mfa import MfaBypass
from auth_scan.core.config import ScanConfig
from auth_scan.core.http_client import HTTPClient


class TestMfaBypass:
    """Tests for the MFA bypass module."""

    def test_detect_mfa_in_body(self) -> None:
        tester = MfaBypass()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = "Enable two-factor authentication for your account."
        report.metadata["probe_headers"] = {}
        found = tester._detect_mfa(report)
        assert len(found) >= 1

    def test_no_mfa_detected(self) -> None:
        tester = MfaBypass()
        report = ScanReport(target="https://example.com")
        config = ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = tester.run("https://example.com", client, report, config)
            assert any("No MFA" in f.title for f in result.findings)

        run()

    def test_mfa_detected_runs_tests(self) -> None:
        tester = MfaBypass()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = "Please enter your 2FA code to continue."
        report.metadata["probe_headers"] = {}
        config = ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/dashboard", status=200)
            responses.add(responses.POST, "https://example.com/mfa/verify", status=200)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = tester.run("https://example.com", client, report, config)
            assert len(result.findings) >= 1

        run()

    def test_direct_access_bypass(self) -> None:
        tester = MfaBypass()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = ""
        report.metadata["probe_headers"] = {}

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/dashboard", body="Dashboard", status=200)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_direct_access(client, report, "https://example.com")
            assert len(findings) >= 1
            assert any("Direct" in f.title or "bypass" in f.title.lower() for f in findings)

        run()

    def test_parameter_pollution(self) -> None:
        tester = MfaBypass()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = "Enter your MFA code"
        report.metadata["probe_headers"] = {}

        @responses.activate
        def run():
            responses.add(responses.POST, "https://example.com/mfa/verify", status=200)
            responses.add(responses.POST, "https://example.com/login", status=200)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_parameter_pollution(client, report, "https://example.com")
            assert isinstance(findings, list)

        run()

    def test_mfa_rate_limiting(self) -> None:
        tester = MfaBypass()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_body"] = ""
        report.metadata["probe_headers"] = {}

        @responses.activate
        def run():
            responses.add(responses.POST, "https://example.com/mfa/verify", status=401)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            findings = tester._test_mfa_rate_limiting(client, report, "https://example.com")
            assert len(findings) >= 1
            assert any("Rate" in f.title or "rate" in f.title for f in findings)

        run()
