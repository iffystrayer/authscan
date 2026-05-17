"""Multi-format reporter: terminal, JSON, Markdown, HTML, PDF, SARIF."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auth_scan.attacks.base import Finding, ScanReport, Severity


@dataclass
class ReportSummary:
    """Aggregated statistics for the executive summary."""

    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    risk_score: float
    duration_seconds: float
    endpoints_tested: int
    top_recommendations: list[str]


def _compute_summary(report: ScanReport, endpoints_tested: int = 0) -> ReportSummary:
    """Compute summary statistics from a ScanReport."""
    counts = {sev: len(report.findings_by_severity(sev)) for sev in Severity}

    # Top recommendations: highest severity findings first
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    recommendations: list[str] = []
    for sev in severity_order:
        for finding in report.findings:
            if finding.severity == sev and finding.remediation and len(recommendations) < 5:
                recommendations.append(f"{finding.severity.icon} {finding.title}: {finding.remediation}")

    duration = 0.0
    if report.completed_at:
        duration = (report.completed_at - report.started_at).total_seconds()

    return ReportSummary(
        total_findings=len(report.findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
        risk_score=report.risk_score,
        duration_seconds=duration,
        endpoints_tested=endpoints_tested,
        top_recommendations=recommendations,
    )


class TerminalReporter:
    """Rich-formatted terminal output."""

    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color

    def render(self, report: ScanReport, endpoints_tested: int = 0) -> None:
        """Render scan results to the terminal using Rich."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        console = Console(no_color=not self.use_color)
        summary = _compute_summary(report, endpoints_tested)

        # Header
        console.print()
        console.print(Panel.fit(
            "[bold blue]auth-scan[/bold blue] v0.1.0 — Web Authentication Security Scanner",
            border_style="blue",
        ))

        console.print(f"Target: {report.target}")
        console.print(f"Started: {report.started_at.isoformat()}")
        console.print()

        if not report.findings:
            console.print(Panel("[green]No vulnerabilities found.[/green]", title="Scan Complete"))
            return

        # Findings table
        table = Table(title="Scan Results", show_lines=True, expand=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Title", width=30)
        table.add_column("Description", width=40)
        table.add_column("Module", width=12)

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
        )

        for finding in sorted_findings:
            sev_style = finding.severity.color
            table.add_row(
                f"[{sev_style}]{finding.severity.icon} {finding.severity.name}[/{sev_style}]",
                finding.title,
                finding.description[:200],
                finding.module_name or "-",
            )

        console.print(table)
        console.print()

        # Summary panel
        summary_text = Text()
        if summary.critical:
            summary_text.append(f"💀 CRITICAL: {summary.critical}  ", style="bold red")
        if summary.high:
            summary_text.append(f"🔴 HIGH: {summary.high}  ", style="red")
        if summary.medium:
            summary_text.append(f"🟠 MEDIUM: {summary.medium}  ", style="yellow")
        if summary.low:
            summary_text.append(f"🟡 LOW: {summary.low}  ", style="blue")
        if summary.info:
            summary_text.append(f"ℹ️ INFO: {summary.info}  ", style="dim")
        summary_text.append(f"\nTotal: {summary.total_findings}")
        summary_text.append(f"\nRisk Score: {summary.risk_score}/100")

        console.print(Panel(summary_text, title="Summary"))
        console.print()

        # Recommendations
        if summary.top_recommendations:
            console.print("[bold]Top Recommendations:[/bold]")
            for i, rec in enumerate(summary.top_recommendations[:5], 1):
                console.print(f"  {i}. {rec}")
            console.print()

        # Footer
        console.print(f"Exit code: {report.exit_code}")


class JsonReporter:
    """JSON machine-readable output."""

    def render(self, report: ScanReport, redact: bool = True) -> str:
        """Render report to JSON string."""
        return report.to_json(redact=redact)


class MarkdownReporter:
    """Consultant-grade Markdown report."""

    def render(self, report: ScanReport, endpoints_tested: int = 0) -> str:
        """Render report to Markdown string."""
        summary = _compute_summary(report, endpoints_tested)
        lines: list[str] = []

        lines.append(f"# auth-scan Security Assessment Report")
        lines.append(f"")
        lines.append(f"**Target:** {report.target}")
        lines.append(f"**Scan ID:** {report.scan_id}")
        lines.append(f"**Started:** {report.started_at.isoformat()}")
        if report.completed_at:
            lines.append(f"**Completed:** {report.completed_at.isoformat()}")
        lines.append(f"**Duration:** {summary.duration_seconds:.1f}s")
        lines.append(f"**Risk Score:** {summary.risk_score}/100")
        lines.append(f"")

        # Executive summary
        lines.append(f"## Executive Summary")
        lines.append(f"")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        lines.append(f"| 💀 CRITICAL | {summary.critical} |")
        lines.append(f"| 🔴 HIGH     | {summary.high} |")
        lines.append(f"| 🟠 MEDIUM   | {summary.medium} |")
        lines.append(f"| 🟡 LOW      | {summary.low} |")
        lines.append(f"| ℹ️ INFO     | {summary.info} |")
        lines.append(f"| **Total**   | **{summary.total_findings}** |")
        lines.append(f"")

        if summary.top_recommendations:
            lines.append(f"### Top Recommendations")
            for i, rec in enumerate(summary.top_recommendations[:5], 1):
                lines.append(f"{i}. {rec}")
            lines.append(f"")

        # Findings detail
        lines.append(f"## Findings")
        lines.append(f"")

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
        )

        for i, finding in enumerate(sorted_findings, 1):
            lines.append(f"### {i}. {finding.severity.icon} {finding.title}")
            lines.append(f"")
            lines.append(f"| Attribute | Value |")
            lines.append(f"|-----------|-------|")
            lines.append(f"| Severity  | {finding.severity.value.upper()} |")
            lines.append(f"| Module    | {finding.module_name} |")
            lines.append(f"| Confidence | {finding.confidence:.0%} |")
            if finding.cwe_id:
                lines.append(f"| CWE       | {finding.cwe_id} |")
            if finding.cvss_score:
                lines.append(f"| CVSS      | {finding.cvss_score} |")
            lines.append(f"")
            lines.append(f"**Description:** {finding.description}")
            lines.append(f"")
            if finding.evidence:
                lines.append(f"**Evidence:**")
                lines.append(f"```json")
                import json
                lines.append(json.dumps(finding.evidence, indent=2))
                lines.append(f"```")
                lines.append(f"")
            if finding.remediation:
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append(f"")

        # Appendix
        lines.append(f"## Appendix: Scan Configuration")
        lines.append(f"")
        lines.append(f"```json")
        import json
        lines.append(json.dumps(report.config_snapshot, indent=2))
        lines.append(f"```")
        lines.append(f"")

        return "\n".join(lines)


class HtmlReporter:
    """Standalone HTML report via Jinja2."""

    HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>auth-scan Report — {{ report.target }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               line-height: 1.6; color: #333; max-width: 1000px; margin: 0 auto; padding: 2rem; }
        h1 { color: #1a56db; border-bottom: 3px solid #1a56db; padding-bottom: 0.5rem; }
        h2 { color: #1e40af; margin-top: 2rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.25rem; }
        h3 { color: #374151; margin-top: 1.5rem; }
        .meta { background: #f3f4f6; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
        .meta dl { display: grid; grid-template-columns: 150px 1fr; gap: 0.25rem; }
        .meta dt { font-weight: 600; color: #6b7280; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.5rem 0.75rem; text-align: left; border: 1px solid #e5e7eb; }
        th { background: #f9fafb; font-weight: 600; }
        .critical { background: #fef2f2; border-left: 4px solid #dc2626; }
        .high { background: #fff7ed; border-left: 4px solid #ea580c; }
        .medium { background: #fef9c3; border-left: 4px solid #ca8a04; }
        .low { background: #eff6ff; border-left: 4px solid #2563eb; }
        .info { background: #f9fafb; border-left: 4px solid #9ca3af; }
        .finding { margin: 1rem 0; padding: 1rem; border-radius: 4px; }
        .badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px;
                 font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
        .badge-critical { background: #dc2626; color: white; }
        .badge-high { background: #ea580c; color: white; }
        .badge-medium { background: #ca8a04; color: white; }
        .badge-low { background: #2563eb; color: white; }
        .badge-info { background: #9ca3af; color: white; }
        .evidence { background: #1f2937; color: #e5e7eb; padding: 1rem; border-radius: 4px;
                     overflow-x: auto; font-family: monospace; font-size: 0.875rem; }
    </style>
</head>
<body>
    <h1>auth-scan Security Assessment Report</h1>

    <div class="meta">
        <dl>
            <dt>Target</dt><dd>{{ report.target }}</dd>
            <dt>Scan ID</dt><dd>{{ report.scan_id }}</dd>
            <dt>Started</dt><dd>{{ report.started_at.isoformat() }}</dd>
            {% if report.completed_at %}
            <dt>Completed</dt><dd>{{ report.completed_at.isoformat() }}</dd>
            {% endif %}
            <dt>Duration</dt><dd>{{ summary.duration_seconds }}s</dd>
            <dt>Risk Score</dt><dd>{{ summary.risk_score }}/100</dd>
        </dl>
    </div>

    <h2>Executive Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td>💀 CRITICAL</td><td>{{ summary.critical }}</td></tr>
        <tr><td>🔴 HIGH</td><td>{{ summary.high }}</td></tr>
        <tr><td>🟠 MEDIUM</td><td>{{ summary.medium }}</td></tr>
        <tr><td>🟡 LOW</td><td>{{ summary.low }}</td></tr>
        <tr><td>ℹ️ INFO</td><td>{{ summary.info }}</td></tr>
        <tr><td><strong>Total</strong></td><td><strong>{{ summary.total_findings }}</strong></td></tr>
    </table>

    {% if summary.top_recommendations %}
    <h3>Top Recommendations</h3>
    <ol>
        {% for rec in summary.top_recommendations[:5] %}
        <li>{{ rec }}</li>
        {% endfor %}
    </ol>
    {% endif %}

    <h2>Findings</h2>
    {% for finding in sorted_findings %}
    {% set severity_class = finding.severity.value %}
    <div class="finding {{ severity_class }}">
        <h3>
            <span class="badge badge-{{ severity_class }}">{{ finding.severity.value.upper() }}</span>
            {{ finding.severity.icon }} {{ finding.title }}
        </h3>
        <table>
            <tr><td>Module</td><td>{{ finding.module_name }}</td></tr>
            <tr><td>Confidence</td><td>{{ "%.0f"|format(finding.confidence * 100) }}%</td></tr>
            {% if finding.cwe_id %}
            <tr><td>CWE</td><td>{{ finding.cwe_id }}</td></tr>
            {% endif %}
            {% if finding.cvss_score %}
            <tr><td>CVSS</td><td>{{ finding.cvss_score }}</td></tr>
            {% endif %}
        </table>
        <p><strong>Description:</strong> {{ finding.description }}</p>
        {% if finding.evidence %}
        <p><strong>Evidence:</strong></p>
        <pre class="evidence">{{ finding.evidence | tojson(indent=2) }}</pre>
        {% endif %}
        {% if finding.remediation %}
        <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>"""

    def render(self, report: ScanReport, endpoints_tested: int = 0) -> str:
        """Render report to standalone HTML using Jinja2."""
        try:
            from jinja2 import Template
        except ImportError:
            return "<html><body><h1>Jinja2 not available</h1></body></html>"

        summary = _compute_summary(report, endpoints_tested)

        severity_order = [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
        ]
        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
        )

        template = Template(self.HTML_TEMPLATE)
        return template.render(
            report=report,
            summary=summary,
            sorted_findings=sorted_findings,
        )


class PdfReporter:
    """PDF report via WeasyPrint (stub when not installed)."""

    def render(self, report: ScanReport, endpoints_tested: int = 0) -> bytes:
        """Render report to PDF bytes using WeasyPrint."""
        try:
            from weasyprint import HTML
        except ImportError:
            raise ImportError(
                "WeasyPrint is required for PDF output. Install with: pip install auth-scan[pdf]"
            )

        html_reporter = HtmlReporter()
        html_content = html_reporter.render(report, endpoints_tested)
        return HTML(string=html_content).write_pdf()


class SarifReporter:
    """SARIF v2.1.0 output for GitHub code scanning integration."""

    def render(self, report: ScanReport) -> str:
        """Render report to SARIF v2.1.0 JSON string."""
        import json

        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []

        seen_rules: dict[str, int] = {}

        for finding in report.findings:
            rule_id = f"AUTH-SCAN-{finding.module_name.upper()}-{_sanitize_rule_id(finding.title)}"
            if rule_id not in seen_rules:
                seen_rules[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.description[:200]},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": finding.remediation,
                        "markdown": f"**Remediation:** {finding.remediation}",
                    },
                    "properties": {
                        "security-severity": str(finding.cvss_score or finding.severity.numeric),
                        "tags": finding.tags,
                    },
                })

            results.append({
                "ruleId": rule_id,
                "ruleIndex": seen_rules[rule_id],
                "message": {"text": finding.description},
                "level": _severity_to_sarif_level(finding.severity),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.target},
                        "region": {"startLine": 1, "startColumn": 1},
                    },
                }],
                "properties": {
                    "confidence": str(finding.confidence),
                    "module": finding.module_name,
                },
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "auth-scan",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/auth-scan/auth-scan",
                        "rules": rules,
                    },
                },
                "results": results,
            }],
        }

        return json.dumps(sarif, indent=2)


def _sanitize_rule_id(title: str) -> str:
    """Convert a finding title to a safe rule ID component."""
    import re
    sanitized = re.sub(r"[^a-zA-Z0-9]+", "-", title).strip("-").upper()
    return sanitized[:50] if sanitized else "UNKNOWN"


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map Severity to SARIF level."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "warning",
        Severity.INFO: "note",
    }
    return mapping[severity]


class Reporter:
    """Unified reporter that dispatches to format-specific renderers."""

    def __init__(self, output_formats: list[str] | None = None, no_redact: bool = False) -> None:
        self.output_formats = output_formats or ["terminal"]
        self.no_redact = no_redact

    def render(
        self,
        report: ScanReport,
        endpoints_tested: int = 0,
        output_dir: str = "./scan-results",
        target: str = "",
    ) -> dict[str, str]:
        """Render and save reports in all configured formats.

        Returns a dict mapping format -> output path or content.
        """
        results: dict[str, str] = {}
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-T%H%M%SZ")
        safe_target = target.replace("https://", "").replace("http://", "").replace("/", "-")[:50]
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        for fmt in self.output_formats:
            try:
                if fmt == "terminal":
                    term = TerminalReporter()
                    term.render(report, endpoints_tested)
                    results["terminal"] = "stdout"

                elif fmt == "json":
                    json_rep = JsonReporter()
                    content = json_rep.render(report, redact=not self.no_redact)
                    path = Path(output_dir) / f"{safe_target}-{timestamp}.json"
                    path.write_text(content)
                    results["json"] = str(path)

                elif fmt == "markdown":
                    md_rep = MarkdownReporter()
                    content = md_rep.render(report, endpoints_tested)
                    path = Path(output_dir) / f"{safe_target}-{timestamp}.md"
                    path.write_text(content)
                    results["markdown"] = str(path)

                elif fmt == "html":
                    html_rep = HtmlReporter()
                    content = html_rep.render(report, endpoints_tested)
                    path = Path(output_dir) / f"{safe_target}-{timestamp}.html"
                    path.write_text(content)
                    results["html"] = str(path)

                elif fmt == "pdf":
                    pdf_rep = PdfReporter()
                    pdf_bytes = pdf_rep.render(report, endpoints_tested)
                    path = Path(output_dir) / f"{safe_target}-{timestamp}.pdf"
                    path.write_bytes(pdf_bytes)
                    results["pdf"] = str(path)

                elif fmt == "sarif":
                    sarif_rep = SarifReporter()
                    content = sarif_rep.render(report)
                    path = Path(output_dir) / f"{safe_target}-{timestamp}.sarif.json"
                    path.write_text(content)
                    results["sarif"] = str(path)

            except ImportError as e:
                from rich.console import Console
                Console(stderr=True).print(f"[yellow]Warning:[/yellow] {e}")
                results[fmt] = f"error: {e}"
            except Exception as e:
                from rich.console import Console
                Console(stderr=True).print(f"[red]Error generating {fmt} report:[/red] {e}")
                results[fmt] = f"error: {e}"

        return results
