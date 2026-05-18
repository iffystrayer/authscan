"""Tests for output reporters."""

from __future__ import annotations

import json

from auth_scan.attacks.base import ScanReport, Severity
from auth_scan.core.reporter import (
    HtmlReporter,
    JsonReporter,
    MarkdownReporter,
    Reporter,
    SarifReporter,
    _compute_summary,
)


class TestReportSummary:
    """Tests for summary computation."""

    def test_compute_empty_report(self) -> None:
        report = ScanReport(target="https://example.com")
        summary = _compute_summary(report)
        assert summary.total_findings == 0
        assert summary.risk_score == 0.0

    def test_compute_with_findings(self, sample_report: ScanReport) -> None:
        summary = _compute_summary(sample_report)
        assert summary.total_findings == 3
        assert summary.critical == 1
        assert summary.high == 1
        assert summary.medium == 1
        assert summary.risk_score > 0

    def test_top_recommendations(self, sample_report: ScanReport) -> None:
        summary = _compute_summary(sample_report)
        assert len(summary.top_recommendations) > 0
        assert any("JWT" in r for r in summary.top_recommendations)


class TestJsonReporter:
    """Tests for JSON reporter."""

    def test_json_output_valid(self, sample_report: ScanReport) -> None:
        reporter = JsonReporter()
        output = reporter.render(sample_report)
        data = json.loads(output)
        assert data["target"] == "https://example.com"
        assert len(data["findings"]) == 3
        assert data["scan_id"] == sample_report.scan_id

    def test_json_output_redacted(self, sample_report: ScanReport) -> None:
        from auth_scan.attacks.base import Finding

        sample_report.add_finding(
            Finding(
                title="Password in Response",
                description="Found password field",
                severity=Severity.HIGH,
                evidence={"authorization": "Bearer secret-token"},
                module_name="probe",
            )
        )
        reporter = JsonReporter()
        output = reporter.render(sample_report, redact=True)
        data = json.loads(output)
        # Find the finding with the redacted evidence
        password_finding = [f for f in data["findings"] if "Password" in f["title"]]
        if password_finding:
            evidence = password_finding[0].get("evidence", {})
            auth_val = evidence.get("authorization", "")
            assert "REDACTED" in auth_val or auth_val == ""

    def test_json_output_no_redact(self, sample_report: ScanReport) -> None:
        from auth_scan.attacks.base import Finding

        sample_report.add_finding(
            Finding(
                title="Token Found",
                description="Auth token exposed",
                severity=Severity.HIGH,
                evidence={"authorization": "Bearer secret-token"},
                module_name="probe",
            )
        )
        reporter = JsonReporter()
        output = reporter.render(sample_report, redact=False)
        data = json.loads(output)
        token_finding = [f for f in data["findings"] if "Token" in f["title"]]
        if token_finding:
            evidence = token_finding[0].get("evidence", {})
            assert evidence.get("authorization") == "Bearer secret-token"


class TestMarkdownReporter:
    """Tests for Markdown reporter."""

    def test_markdown_has_sections(self, sample_report: ScanReport) -> None:
        reporter = MarkdownReporter()
        output = reporter.render(sample_report)
        assert "# auth-scan Security Assessment Report" in output
        assert "## Executive Summary" in output
        assert "## Findings" in output
        assert "Missing HSTS" in output
        assert "JWT alg=none" in output

    def test_markdown_empty_report(self) -> None:
        reporter = MarkdownReporter()
        report = ScanReport(target="https://safe.com")
        output = reporter.render(report)
        assert "Total" in output
        assert "0" in output


class TestHtmlReporter:
    """Tests for HTML reporter."""

    def test_html_standalone(self, sample_report: ScanReport) -> None:
        reporter = HtmlReporter()
        output = reporter.render(sample_report)
        assert "<!DOCTYPE html>" in output
        assert "<style>" in output  # embedded styles
        assert "auth-scan Security Assessment Report" in output
        assert "Missing HSTS" in output

    def test_html_has_severity_badges(self, sample_report: ScanReport) -> None:
        reporter = HtmlReporter()
        output = reporter.render(sample_report)
        assert "badge-critical" in output
        assert "badge-high" in output


class TestSarifReporter:
    """Tests for SARIF reporter."""

    def test_sarif_schema_compliance(self, sample_report: ScanReport) -> None:
        reporter = SarifReporter()
        output = reporter.render(sample_report)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1
        assert "tool" in data["runs"][0]
        assert data["runs"][0]["tool"]["driver"]["name"] == "auth-scan"

    def test_sarif_has_rules_and_results(self, sample_report: ScanReport) -> None:
        reporter = SarifReporter()
        output = reporter.render(sample_report)
        data = json.loads(output)
        run = data["runs"][0]
        assert len(run["results"]) == 3
        assert len(run["tool"]["driver"]["rules"]) == 3

    def test_sarif_severity_levels(self, sample_report: ScanReport) -> None:
        reporter = SarifReporter()
        output = reporter.render(sample_report)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        levels = {r["level"] for r in results}
        assert "error" in levels  # CRITICAL
        # HIGH should also be error in SARIF


class TestReporterIntegration:
    """Integration tests for the unified Reporter."""

    def test_terminal_render_does_not_crash(self, sample_report: ScanReport) -> None:
        reporter = Reporter(output_formats=["terminal"])
        result = reporter.render(sample_report, output_dir="/tmp/test-auth-scan")
        assert result["terminal"] == "stdout"

    def test_json_saved_to_file(self, sample_report: ScanReport, tmp_path) -> None:
        reporter = Reporter(output_formats=["json"])
        result = reporter.render(
            sample_report,
            output_dir=str(tmp_path),
            target="example.com",
        )
        assert result["json"].endswith(".json")
        import os

        assert os.path.exists(result["json"])

    def test_markdown_saved_to_file(self, sample_report: ScanReport, tmp_path) -> None:
        reporter = Reporter(output_formats=["markdown"])
        result = reporter.render(
            sample_report,
            output_dir=str(tmp_path),
            target="example.com",
        )
        assert result["markdown"].endswith(".md")
