"""CLI dispatch + module registry + output-file plumbing (PR-2: H1/H2/H5/M9).

These tests exercise the CLI -> config -> reporter wiring without making
real network requests. Each test isolates one contract:

  * H1: ``--modules all`` expands to every registered module name.
  * H2: ``--output <fmt> --output-file PATH`` writes to that exact path,
    not the auto-named file under ``--output-dir``.
  * H5: ``ScanConfig`` now declares ``jwt_wordlist``, ``no_discovery``,
    ``no_mfa``, ``oauth_scope``, and ``output_file`` (no dynamic attrs).
"""

from __future__ import annotations

import json

import pytest

from auth_scan.attacks.base import ScanReport
from auth_scan.core.config import ScanConfig
from auth_scan.core.engine import all_module_names, discover_modules
from auth_scan.core.reporter import Reporter

# ---- H1: canonical module registry -----------------------------------------


class TestModuleRegistry:
    def test_discover_modules_returns_built_in_set(self) -> None:
        names = set(discover_modules().keys())
        # The seven module names declared in pyproject entry_points must be present.
        for name in ("jwt", "brute", "session", "oauth", "mfa", "websocket", "api_key"):
            assert name in names, f"missing built-in module: {name}"

    def test_all_module_names_includes_probe_first(self) -> None:
        names = all_module_names()
        assert names[0] == "probe", "probe must lead the canonical list"
        for n in ("jwt", "brute", "session", "oauth", "mfa", "websocket", "api_key"):
            assert n in names, f"--modules all must include {n}"

    def test_all_module_names_has_no_duplicates(self) -> None:
        names = all_module_names()
        assert len(names) == len(set(names))


# ---- H5: ScanConfig fields exist -------------------------------------------


class TestScanConfigFields:
    def test_phase2_fields_present_with_safe_defaults(self) -> None:
        cfg = ScanConfig()
        # mypy-strict callers can now read these without getattr() gymnastics.
        assert cfg.jwt_wordlist == ""
        assert cfg.no_discovery is False
        assert cfg.no_mfa is False
        # Default OAuth scope is plain-text so requests can URL-encode it.
        assert cfg.oauth_scope == "admin profile email openid"
        assert cfg.output_file == ""

    def test_phase2_fields_via_yaml(self, tmp_path) -> None:
        from auth_scan.core.config import load_config

        cfg_path = tmp_path / "c.yml"
        cfg_path.write_text(
            "jwt_wordlist: /tmp/jwt.txt\nno_discovery: true\nno_mfa: true\noauth_scope: admin\n"
        )
        cfg = load_config(config_path=str(cfg_path))
        assert cfg.jwt_wordlist == "/tmp/jwt.txt"
        assert cfg.no_discovery is True
        assert cfg.no_mfa is True
        assert cfg.oauth_scope == "admin"


# ---- H2: --output-file routing ---------------------------------------------


@pytest.fixture
def sample_report() -> ScanReport:
    from auth_scan.attacks.base import Finding, Severity

    r = ScanReport(target="https://example.com", effective_target="https://example.com")
    r.add_finding(
        Finding(
            title="Sample",
            severity=Severity.INFO,
            module_name="probe",
            description="hello",
        )
    )
    return r


class TestOutputFileRouting:
    def test_json_to_explicit_path(self, sample_report: ScanReport, tmp_path) -> None:
        target_file = tmp_path / "results.json"
        rep = Reporter(output_formats=["json"], no_redact=False)
        saved = rep.render(
            sample_report,
            output_dir=str(tmp_path / "ignored"),
            target="example.com",
            output_file=str(target_file),
        )
        # The auto-named path under output_dir was not used.
        assert saved["json"] == str(target_file)
        assert target_file.exists()
        data = json.loads(target_file.read_text())
        assert data["target"] == "https://example.com"
        # output_dir wasn't created because --output-file is set
        assert not (tmp_path / "ignored").exists()

    def test_sarif_to_stdout_dash(self, sample_report: ScanReport, capsys) -> None:
        rep = Reporter(output_formats=["sarif"], no_redact=False)
        saved = rep.render(
            sample_report,
            target="example.com",
            output_file="-",
        )
        assert saved["sarif"] == "stdout"
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["$schema"].endswith("sarif-schema-2.1.0.json")

    def test_html_to_nested_path_creates_parent(self, sample_report: ScanReport, tmp_path) -> None:
        target_file = tmp_path / "deep" / "nested" / "report.html"
        rep = Reporter(output_formats=["html"], no_redact=False)
        saved = rep.render(
            sample_report,
            target="example.com",
            output_file=str(target_file),
        )
        assert saved["html"] == str(target_file)
        assert target_file.exists()
        assert "auth-scan Security Assessment Report" in target_file.read_text()

    def test_without_output_file_uses_output_dir(self, sample_report: ScanReport, tmp_path) -> None:
        rep = Reporter(output_formats=["json"], no_redact=False)
        saved = rep.render(
            sample_report,
            output_dir=str(tmp_path),
            target="example.com",
            output_file=None,
        )
        # auto-named under output_dir
        assert saved["json"].startswith(str(tmp_path))
        assert saved["json"].endswith(".json")


# ---- H2: CLI flag wiring (uses Click's CliRunner) --------------------------


class TestCliWiring:
    def test_output_file_requires_exactly_one_non_terminal_format(self, tmp_path) -> None:
        from click.testing import CliRunner

        from auth_scan.cli import main

        runner = CliRunner()
        # Two non-terminal formats + --output-file should be rejected.
        result = runner.invoke(
            main,
            [
                "https://example.com",
                "--output",
                "json",
                "--output",
                "html",
                "--output-file",
                str(tmp_path / "x.json"),
            ],
        )
        assert result.exit_code == 2, result.output
        assert "exactly one --output format" in result.output

    def test_modules_all_help_lists_choices(self) -> None:
        from click.testing import CliRunner

        from auth_scan.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        # Spot-check that the new modules appear in the help text.
        for name in ("oauth", "mfa", "websocket", "api_key", "all"):
            assert name in result.output
