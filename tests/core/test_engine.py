"""Tests for the scan engine and ScanReport."""
from __future__ import annotations

from auth_scan.attacks.base import Finding, ScanReport, Severity
from auth_scan.core.config import ScanConfig


class TestScanReport:
    """Tests for the ScanReport accumulator."""

    def test_empty_report(self) -> None:
        report = ScanReport(target="https://example.com")
        assert report.status == "initialized"
        assert len(report.findings) == 0
        assert report.scan_id

    def test_add_finding(self) -> None:
        report = ScanReport(target="https://example.com")
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            module_name="test",
        )
        report.add_finding(finding)
        assert len(report.findings) == 1
        assert report.findings[0].timestamp is not None

    def test_findings_by_severity(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(title="C1", severity=Severity.CRITICAL, module_name="t"))
        report.add_finding(Finding(title="C2", severity=Severity.CRITICAL, module_name="t"))
        report.add_finding(Finding(title="H1", severity=Severity.HIGH, module_name="t"))
        criticals = report.findings_by_severity(Severity.CRITICAL)
        highs = report.findings_by_severity(Severity.HIGH)
        assert len(criticals) == 2
        assert len(highs) == 1

    def test_highest_severity(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(title="L1", severity=Severity.LOW, module_name="t"))
        report.add_finding(Finding(title="C1", severity=Severity.CRITICAL, module_name="t"))
        report.add_finding(Finding(title="M1", severity=Severity.MEDIUM, module_name="t"))
        assert report.get_highest_severity() == Severity.CRITICAL

    def test_highest_severity_empty(self) -> None:
        report = ScanReport(target="https://example.com")
        assert report.get_highest_severity() == Severity.INFO

    def test_risk_score(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(
            title="C1", severity=Severity.CRITICAL, module_name="t", cvss_score=9.8,
        ))
        assert report.risk_score > 0

    def test_exit_code_critical(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(title="C1", severity=Severity.CRITICAL, module_name="t"))
        assert report.exit_code == 4

    def test_exit_code_high(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(title="H1", severity=Severity.HIGH, module_name="t"))
        assert report.exit_code == 3

    def test_exit_code_medium(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(title="M1", severity=Severity.MEDIUM, module_name="t"))
        assert report.exit_code == 2

    def test_exit_code_low(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(title="L1", severity=Severity.LOW, module_name="t"))
        assert report.exit_code == 1

    def test_exit_code_none(self) -> None:
        report = ScanReport(target="https://example.com")
        assert report.exit_code == 0

    def test_to_dict(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(title="Test", severity=Severity.MEDIUM, module_name="p"))
        data = report.to_dict()
        assert data["target"] == "https://example.com"
        assert data["status"] == "initialized"
        assert len(data["findings"]) == 1
        assert "risk_score" in data

    def test_to_json(self) -> None:
        report = ScanReport(target="https://example.com")
        report.add_finding(Finding(title="Test", severity=Severity.MEDIUM, module_name="p"))
        json_str = report.to_json()
        assert "https://example.com" in json_str
        assert '"severity": "medium"' in json_str


class TestSeverityEnum:
    """Tests for the Severity enum."""

    def test_numeric_values(self) -> None:
        assert Severity.CRITICAL.numeric == 9.5
        assert Severity.HIGH.numeric == 8.0
        assert Severity.MEDIUM.numeric == 5.5
        assert Severity.LOW.numeric == 2.0
        assert Severity.INFO.numeric == 0.0

    def test_exit_codes(self) -> None:
        assert Severity.CRITICAL.exit_code == 4
        assert Severity.HIGH.exit_code == 3
        assert Severity.MEDIUM.exit_code == 2
        assert Severity.LOW.exit_code == 1
        assert Severity.INFO.exit_code == 0

    def test_icons(self) -> None:
        assert Severity.CRITICAL.icon == "💀"
        assert Severity.HIGH.icon == "🔴"
        assert Severity.MEDIUM.icon == "🟠"
        assert Severity.LOW.icon == "🟡"


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_has_id(self) -> None:
        f = Finding(title="Test", severity=Severity.HIGH, module_name="test")
        assert f.id
        assert len(f.id) > 0

    def test_finding_to_dict(self) -> None:
        f = Finding(
            title="Test Finding",
            severity=Severity.CRITICAL,
            description="A test finding",
            evidence={"key": "value"},
            remediation="Fix it",
            cwe_id="CWE-287",
            cvss_score=9.8,
            module_name="test",
            tags=["test", "critical"],
        )
        d = f.to_dict()
        assert d["title"] == "Test Finding"
        assert d["severity"] == "critical"
        assert d["cwe_id"] == "CWE-287"
        assert d["tags"] == ["test", "critical"]

    def test_finding_chain(self) -> None:
        f1 = Finding(title="Parent", severity=Severity.LOW, module_name="test")
        f2 = Finding(
            title="Child",
            severity=Severity.CRITICAL,
            module_name="test",
            chain_parent=f1.id,
        )
        f1.chain_children.append(f2.id)
        assert f2.chain_parent == f1.id
        assert f1.chain_children == [f2.id]
