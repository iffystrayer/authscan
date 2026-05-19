"""Multi-format reporter: terminal, JSON, Markdown, HTML, PDF, SARIF."""

from __future__ import annotations

import hashlib
import re as _re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auth_scan import __version__
from auth_scan.attacks.base import ScanReport, Severity, _redact_value


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

    def render(self, report: ScanReport, endpoints_tested: int = 0, redact: bool = True) -> None:
        """Render scan results to the terminal using Rich."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        console = Console(no_color=not self.use_color)
        summary = _compute_summary(report, endpoints_tested)

        # Header
        console.print()
        console.print(
            Panel.fit(
                f"[bold blue]auth-scan[/bold blue] v{__version__} — Web Authentication Security Scanner",
                border_style="blue",
            )
        )

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

        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
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

    def render(self, report: ScanReport, endpoints_tested: int = 0, redact: bool = True) -> str:
        """Render report to Markdown string."""
        summary = _compute_summary(report, endpoints_tested)
        lines: list[str] = []

        lines.append("# auth-scan Security Assessment Report")
        lines.append("")
        lines.append(f"**Target:** {report.target}")
        lines.append(f"**Scan ID:** {report.scan_id}")
        lines.append(f"**Started:** {report.started_at.isoformat()}")
        if report.completed_at:
            lines.append(f"**Completed:** {report.completed_at.isoformat()}")
        lines.append(f"**Duration:** {summary.duration_seconds:.1f}s")
        lines.append(f"**Risk Score:** {summary.risk_score}/100")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| 💀 CRITICAL | {summary.critical} |")
        lines.append(f"| 🔴 HIGH     | {summary.high} |")
        lines.append(f"| 🟠 MEDIUM   | {summary.medium} |")
        lines.append(f"| 🟡 LOW      | {summary.low} |")
        lines.append(f"| ℹ️ INFO     | {summary.info} |")
        lines.append(f"| **Total**   | **{summary.total_findings}** |")
        lines.append("")

        if summary.top_recommendations:
            lines.append("### Top Recommendations")
            for i, rec in enumerate(summary.top_recommendations[:5], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Findings detail
        lines.append("## Findings")
        lines.append("")

        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
        )

        import json

        for i, finding in enumerate(sorted_findings, 1):
            finding_dict = finding.to_dict(redact=redact)
            lines.append(f"### {i}. {finding.severity.icon} {finding.title}")
            lines.append("")
            lines.append("| Attribute | Value |")
            lines.append("|-----------|-------|")
            lines.append(f"| Severity  | {finding.severity.value.upper()} |")
            lines.append(f"| Module    | {finding.module_name} |")
            lines.append(f"| Confidence | {finding.confidence:.0%} |")
            if finding.cwe_id:
                lines.append(f"| CWE       | {finding.cwe_id} |")
            if finding.cvss_score:
                lines.append(f"| CVSS      | {finding.cvss_score} |")
            lines.append("")
            lines.append(f"**Description:** {finding_dict.get('description', '')}")
            lines.append("")
            evidence = finding_dict.get("evidence") or {}
            if evidence:
                lines.append("**Evidence:**")
                lines.append("```json")
                lines.append(json.dumps(evidence, indent=2))
                lines.append("```")
                lines.append("")
            remediation = finding_dict.get("remediation", "")
            if remediation:
                lines.append(f"**Remediation:** {remediation}")
                lines.append("")

        # Appendix
        lines.append("## Appendix: Scan Configuration")
        lines.append("")
        lines.append("```json")
        import json

        lines.append(json.dumps(report.config_snapshot, indent=2))
        lines.append("```")
        lines.append("")

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
    {% for item in finding_items %}
    {% set finding = item.finding %}
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
        <p><strong>Description:</strong> {{ item.description }}</p>
        {% if item.evidence %}
        <p><strong>Evidence:</strong></p>
        <pre class="evidence">{{ item.evidence | tojson(indent=2) }}</pre>
        {% endif %}
        {% if item.remediation %}
        <p><strong>Remediation:</strong> {{ item.remediation }}</p>
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>"""

    def render(
        self,
        report: ScanReport,
        endpoints_tested: int = 0,
        redact: bool = True,
    ) -> str:
        """Render report to standalone HTML using Jinja2."""
        try:
            from jinja2 import Template
        except ImportError:
            return "<html><body><h1>Jinja2 not available</h1></body></html>"

        summary = _compute_summary(report, endpoints_tested)

        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
        )

        # Pre-redact per-finding fields so the template never touches raw values.
        finding_items = []
        for f in sorted_findings:
            d = f.to_dict(redact=redact)
            finding_items.append(
                {
                    "finding": f,
                    "description": d.get("description", ""),
                    "remediation": d.get("remediation", ""),
                    "evidence": d.get("evidence") or {},
                }
            )

        template = Template(self.HTML_TEMPLATE)
        return template.render(
            report=report,
            summary=summary,
            finding_items=finding_items,
        )


class PdfReporter:
    """PDF report via WeasyPrint (stub when not installed)."""

    def render(self, report: ScanReport, endpoints_tested: int = 0, redact: bool = True) -> bytes:
        """Render report to PDF bytes using WeasyPrint."""
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise ImportError(
                "WeasyPrint is required for PDF output. Install with: pip install auth-scan[pdf]"
            ) from exc

        html_reporter = HtmlReporter()
        html_content = html_reporter.render(report, endpoints_tested, redact=redact)
        return HTML(string=html_content).write_pdf()


class SarifReporter:
    """SARIF v2.1.0 output for GitHub code scanning integration."""

    def render(self, report: ScanReport, redact: bool = True) -> str:
        """Render report to SARIF v2.1.0 JSON string."""
        import json

        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []

        seen_rules: dict[str, int] = {}

        def scrub(text: str) -> str:
            return _redact_value(text) if redact and isinstance(text, str) else text

        for finding in report.findings:
            rule_id = f"AUTH-SCAN-{finding.module_name.upper()}-{_sanitize_rule_id(finding.title)}"
            description = scrub(finding.description)
            remediation = scrub(finding.remediation)
            if rule_id not in seen_rules:
                seen_rules[rule_id] = len(rules)
                rules.append(
                    {
                        "id": rule_id,
                        "name": finding.title,
                        "shortDescription": {"text": description[:200]},
                        "fullDescription": {"text": description},
                        "help": {
                            "text": remediation,
                            "markdown": f"**Remediation:** {remediation}",
                        },
                        "properties": {
                            "security-severity": str(finding.cvss_score or finding.severity.numeric),
                            "tags": finding.tags,
                        },
                    }
                )

            results.append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": seen_rules[rule_id],
                    "message": {"text": description},
                    "level": _severity_to_sarif_level(finding.severity),
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": report.target},
                                "region": {"startLine": 1, "startColumn": 1},
                            },
                        }
                    ],
                    "properties": {
                        "confidence": str(finding.confidence),
                        "module": finding.module_name,
                    },
                }
            )

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "auth-scan",
                            "version": __version__,
                            "informationUri": "https://github.com/auth-scan/auth-scan",
                            "rules": rules,
                        },
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)


def _slugify_target(target: str) -> str:
    """Produce a filesystem-safe slug for a target URL (L9).

    The previous slug replaced ``://`` and ``/`` only, then truncated at
    50 chars. Query strings, fragments, percent-encoding, and Windows
    reserved characters all leaked through unchanged, sometimes
    producing colliding or unwritable filenames. The new slug:

      * Keeps ``[A-Za-z0-9._-]`` verbatim.
      * Replaces every other character with ``_`` (collapsing runs).
      * Strips trailing dots / underscores / hyphens.
      * Caps the readable portion at 80 chars.
      * Appends an 8-hex-digit SHA-1 suffix of the full original target
        so distinct targets that slug to the same prefix don't collide.

    Returns ``"target"`` if the input slugs to the empty string.
    """
    if not target:
        return "target"
    slug = _re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("._-")
    if not slug:
        slug = "target"
    suffix = hashlib.sha1(target.encode("utf-8")).hexdigest()[:8]
    return f"{slug[:80]}_{suffix}"


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
        output_file: str | None = None,
    ) -> dict[str, str]:
        """Render and save reports in all configured formats.

        When ``output_file`` is set (and there is exactly one non-terminal
        format), the report for that format is written to that exact path
        instead of the auto-named file under ``output_dir``. ``output_file``
        may be ``"-"`` to write to stdout. Validation of "exactly one
        format" happens in the CLI; here we just honor the override.

        Returns a dict mapping format -> output path (or ``"stdout"``).
        """
        results: dict[str, str] = {}
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-T%H%M%SZ")
        safe_target = _slugify_target(target)
        # Only create the directory when we're going to use it.
        if not output_file:
            Path(output_dir).mkdir(parents=True, exist_ok=True)

        def _write(fmt: str, default_name: str, content: str | bytes) -> str:
            """Write ``content`` for ``fmt`` honoring --output-file override."""
            if output_file:
                if output_file == "-":
                    if isinstance(content, bytes):
                        sys.stdout.buffer.write(content)
                    else:
                        sys.stdout.write(content)
                    return "stdout"
                target_path = Path(output_file)
                target_path.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, bytes):
                    target_path.write_bytes(content)
                else:
                    target_path.write_text(content)
                return str(target_path)
            path = Path(output_dir) / default_name
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content)
            return str(path)

        redact = not self.no_redact
        for fmt in self.output_formats:
            try:
                if fmt == "terminal":
                    term = TerminalReporter()
                    term.render(report, endpoints_tested, redact=redact)
                    results["terminal"] = "stdout"

                elif fmt == "json":
                    content = JsonReporter().render(report, redact=redact)
                    results["json"] = _write(fmt, f"{safe_target}-{timestamp}.json", content)

                elif fmt == "markdown":
                    content = MarkdownReporter().render(report, endpoints_tested, redact=redact)
                    results["markdown"] = _write(fmt, f"{safe_target}-{timestamp}.md", content)

                elif fmt == "html":
                    content = HtmlReporter().render(report, endpoints_tested, redact=redact)
                    results["html"] = _write(fmt, f"{safe_target}-{timestamp}.html", content)

                elif fmt == "pdf":
                    pdf_bytes = PdfReporter().render(report, endpoints_tested, redact=redact)
                    results["pdf"] = _write(fmt, f"{safe_target}-{timestamp}.pdf", pdf_bytes)

                elif fmt == "sarif":
                    content = SarifReporter().render(report, redact=redact)
                    results["sarif"] = _write(fmt, f"{safe_target}-{timestamp}.sarif.json", content)

            except ImportError as e:
                from rich.console import Console

                Console(stderr=True).print(f"[yellow]Warning:[/yellow] {e}")
                results[fmt] = f"error: {e}"
            except Exception as e:
                from rich.console import Console

                Console(stderr=True).print(f"[red]Error generating {fmt} report:[/red] {e}")
                results[fmt] = f"error: {e}"

        return results
