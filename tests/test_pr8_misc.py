"""PR-8: monotonic risk score, pre-compiled API-key regex, single
version source (L1 / L2 / L7).
"""

from __future__ import annotations

import re

import responses

from auth_scan import __version__
from auth_scan.attacks.api_key import API_KEY_PATTERNS, COMPILED_API_KEY_PATTERNS
from auth_scan.attacks.base import Finding, ScanReport, Severity
from auth_scan.core.http_client import HTTPClient

# ---- L1: risk score monotonically nondecreasing ----------------------------


class TestRiskScoreMonotonic:
    def _add(self, r: ScanReport, sev: Severity, n: int = 1) -> None:
        for i in range(n):
            r.add_finding(
                Finding(
                    title=f"f{sev.value}-{i}",
                    severity=sev,
                    module_name="m",
                    evidence={"endpoint": f"/x{sev.value}{i}"},  # distinct dedup keys
                )
            )

    def test_empty_report_is_zero(self) -> None:
        assert ScanReport(target="t").risk_score == 0.0

    def test_each_added_finding_does_not_decrease_score(self) -> None:
        r = ScanReport(target="t")
        score = 0.0
        # Mix severities to defeat the old "divide by min(n,20)" formula
        # which was non-monotonic under exactly this pattern.
        sev_sequence = [Severity.CRITICAL] * 3 + [Severity.LOW] * 25 + [Severity.MEDIUM] * 5
        for i, sev in enumerate(sev_sequence):
            r.add_finding(
                Finding(
                    title="t",
                    severity=sev,
                    module_name="m",
                    evidence={"endpoint": f"/e{i}"},
                )
            )
            assert r.risk_score >= score, f"score regressed after appending {sev}: {score} -> {r.risk_score}"
            score = r.risk_score

    def test_score_saturates_at_100(self) -> None:
        r = ScanReport(target="t")
        # Six CRITICAL findings should already exceed the 100-cap.
        self._add(r, Severity.CRITICAL, 6)
        assert r.risk_score == 100.0

    def test_info_findings_do_not_inflate_score(self) -> None:
        r = ScanReport(target="t")
        self._add(r, Severity.INFO, 50)
        # Severity.numeric for INFO is 0, so total = 0.
        assert r.risk_score == 0.0


# ---- L2: API-key regex pre-compiled ---------------------------------------


class TestCompiledApiKeyPatterns:
    def test_compiled_count_matches_raw(self) -> None:
        assert len(COMPILED_API_KEY_PATTERNS) == len(API_KEY_PATTERNS)

    def test_compiled_entries_are_pattern_objects(self) -> None:
        for label, compiled, risk in COMPILED_API_KEY_PATTERNS:
            assert isinstance(label, str)
            assert isinstance(compiled, re.Pattern)
            assert risk in {"critical", "high", "medium"}

    def test_compiled_patterns_match_same_strings_as_raw(self) -> None:
        """Every raw pattern that fires on a known-positive string should
        also fire when consumed via the compiled tuple."""
        sample = "ghp_" + "a" * 36 + " AKIA" + "1234567890ABCDEF"
        raw_hits = sum(1 for _, p, _ in API_KEY_PATTERNS if re.search(p, sample))
        compiled_hits = sum(1 for _, p, _ in COMPILED_API_KEY_PATTERNS if p.search(sample))
        assert raw_hits == compiled_hits and compiled_hits >= 2


# ---- L7: single version source --------------------------------------------


class TestSingleVersionSource:
    def test_version_resolves_from_metadata(self) -> None:
        """``__version__`` must come from importlib.metadata, not a
        hardcoded literal. We don't depend on tomllib (stdlib only on
        3.11+) — instead verify the symbol matches the live metadata
        lookup and looks like a real semver."""
        import re as _re
        from importlib import metadata as _md

        assert __version__ == _md.version("auth-scan")
        assert _re.match(r"^\d+\.\d+\.\d+", __version__), __version__
        # And the old hardcoded fallback should not be in effect when the
        # package is properly installed.
        assert __version__ != "0.0.0+local"

    def test_terminal_reporter_uses_dynamic_version(self) -> None:
        """The hardcoded 'v0.1.0' literal in TerminalReporter is gone."""
        import inspect

        from auth_scan.core import reporter

        src = inspect.getsource(reporter)
        assert "v0.1.0" not in src

    def test_sarif_driver_version_matches_pkg_version(self) -> None:
        import json

        from auth_scan.core.reporter import SarifReporter

        report = ScanReport(target="https://example.com")
        report.add_finding(
            Finding(
                title="t",
                severity=Severity.INFO,
                module_name="m",
                evidence={"endpoint": "/x"},
            )
        )
        data = json.loads(SarifReporter().render(report))
        assert data["runs"][0]["tool"]["driver"]["version"] == __version__

    @responses.activate
    def test_user_agent_default_includes_version(self) -> None:
        captured: dict[str, str] = {}

        def cb(request):
            captured["ua"] = request.headers.get("User-Agent", "")
            return (200, {}, "ok")

        responses.add_callback(responses.GET, "https://example.com/", callback=cb)
        client = HTTPClient(base_url="https://example.com", rate_limit=100.0)
        client.get("/")
        assert captured["ua"] == f"auth-scan/{__version__}"
