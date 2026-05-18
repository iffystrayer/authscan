"""Tests for the OODA agentic engine."""

from __future__ import annotations

import responses

from auth_scan.attacks.base import Finding, ModuleResult, ScanReport, Severity
from auth_scan.core.agentic import OODAEngine
from auth_scan.core.attack_surface import AttackSurfaceModel
from auth_scan.core.config import ScanConfig
from auth_scan.core.http_client import HTTPClient


class TestObserve:
    """Tests for the Observe phase."""

    def test_observe_extracts_endpoints(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)

            result = ModuleResult(
                findings=[
                    Finding(
                        title="Path Discovered (200): /api",
                        severity=Severity.INFO,
                        evidence={"path": "/api", "status": 200},
                        module_name="path_discovery",
                        tags=["discovery", "paths"],
                    )
                ]
            )
            changes = ooda.observe(result, report)
            assert changes["new_endpoints"] >= 1
            assert "/api" in model.endpoints

        run()

    def test_observe_extracts_tokens(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)

            result = ModuleResult(
                findings=[
                    Finding(
                        title="JWT Discovered (HS256)",
                        severity=Severity.INFO,
                        evidence={"algorithm": "HS256", "location": "cookie"},
                        module_name="jwt",
                        tags=["jwt", "discovery"],
                    )
                ]
            )
            changes = ooda.observe(result, report)
            assert changes["new_tokens"] >= 1
            assert len(model.tokens) >= 1

        run()

    def test_observe_extracts_sessions(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)

            result = ModuleResult(
                findings=[
                    Finding(
                        title="Session Fixation Vulnerability",
                        severity=Severity.HIGH,
                        evidence={"cookie_name": "sessionid"},
                        module_name="session",
                        tags=["session", "fixation"],
                    )
                ]
            )
            changes = ooda.observe(result, report)
            assert changes["new_sessions"] >= 1

        run()

    def test_observe_detects_credentials(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)

            result = ModuleResult(
                findings=[
                    Finding(
                        title="Weak/Default Credentials Accepted",
                        severity=Severity.CRITICAL,
                        evidence={"username": "admin", "password": "admin"},
                        module_name="brute",
                        tags=["brute", "default-credentials"],
                    )
                ]
            )
            changes = ooda.observe(result, report)
            assert changes["credentials_found"] >= 1

        run()


class TestOrient:
    """Tests for the Orient phase."""

    def test_orient_updates_confidence(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        config = ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)
            assessment = ooda.orient()
            assert model.confidence > 0
            assert "confidence" in assessment
            assert "gaps" in assessment

        run()

    def test_orient_identifies_gaps(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        model.auth_mechanisms.add("oauth")
        config = ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)
            assessment = ooda.orient()
            assert any("oauth" in g for g in assessment["gaps"])

        run()


class TestDecide:
    """Tests for the Decide phase."""

    def test_decide_concludes_when_exhausted(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)
            ooda._modules_run = {"jwt", "session", "brute", "oauth", "mfa", "api_key"}
            ooda.model._mechanisms_tested = {"form", "jwt", "oauth", "mfa"}
            module_map = {}  # empty = exhaust
            decision = ooda.decide(module_map, report)
            assert decision["action"] == "conclude"

        run()

    def test_decide_prioritizes_oauth(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.auth_mechanisms.add("oauth")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)
            module_map = {"oauth": type("FakeOAuth", (), {"name": "oauth", "priority": 40})}
            decision = ooda.decide(module_map, report)
            assert decision["action"] == "run_module"
            assert decision["module"] == "oauth"

        run()

    def test_decide_prioritizes_untested_mechanism(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.auth_mechanisms.add("form")
        config = ScanConfig(target="https://example.com", modules=["brute"])
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)
            module_map = {"brute": type("FakeBrute", (), {"name": "brute", "priority": 30})}
            decision = ooda.decide(module_map, report)
            assert decision["action"] == "run_module"
            assert decision["module"] == "brute"

        run()


class TestRunLoop:
    """Tests for the full OODA loop."""

    def test_full_loop_runs_and_concludes(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        config = ScanConfig(
            target="https://example.com",
            modules=["jwt", "session"],
            confidence_threshold=0.5,
        )
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/api/profile", json={"ok": True})
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)

            # Minimal module map for test
            call_count = [0]

            class FakeJwtModule:
                name = "jwt"
                priority = 10

                def run(self, target, http_client, report, config):
                    call_count[0] += 1
                    return ModuleResult(
                        findings=[
                            Finding(
                                title="JWT Found",
                                severity=Severity.INFO,
                                evidence={"algorithm": "HS256", "location": "cookie"},
                                module_name="jwt",
                                tags=["jwt", "discovery"],
                            )
                        ]
                    )

            class FakeSessionModule:
                name = "session"
                priority = 20

                def run(self, target, http_client, report, config):
                    return ModuleResult(
                        findings=[
                            Finding(
                                title="Session Cookie Missing HttpOnly",
                                severity=Severity.HIGH,
                                evidence={"cookie_name": "sessionid"},
                                module_name="session",
                                remediation="Add HttpOnly flag.",
                                tags=["session", "cookies"],
                            )
                        ]
                    )

            module_map = {"jwt": FakeJwtModule, "session": FakeSessionModule}
            final_report = ooda.run_loop(module_map, report, max_cycles=5)

            # Modules should have been called
            assert call_count[0] >= 1
            # Decision trail populated
            assert len(final_report.decision_trail) > 0
            # Confidence updated
            assert model.confidence > 0

        run()

    def test_decision_trail_structure(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        config = ScanConfig(target="https://example.com", confidence_threshold=0.9)
        report = ScanReport(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)

            module_map = {}
            final_report = ooda.run_loop(module_map, report, max_cycles=3)

            trail = final_report.decision_trail
            # Should have observe entries from probe
            observe_entries = [d for d in trail if d["phase"] == "observe"]
            assert len(observe_entries) >= 1

            # Orient entries
            orient_entries = [d for d in trail if d["phase"] == "orient"]
            assert len(orient_entries) >= 1

            # Each entry has required fields
            for entry in trail:
                assert "cycle" in entry
                assert "phase" in entry
                assert "action" in entry
                assert "reasoning" in entry

        run()


class TestChainSynthesis:
    """Tests for exploit chain synthesis."""

    def test_user_enum_plus_weak_password(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        report.add_finding(
            Finding(
                title="User Enumeration Possible",
                severity=Severity.MEDIUM,
                confidence=0.7,
                module_name="brute",
                tags=["brute", "user-enumeration"],
            )
        )
        report.add_finding(
            Finding(
                title="Weak/Default Credentials Accepted",
                severity=Severity.CRITICAL,
                confidence=0.95,
                module_name="brute",
                tags=["brute", "default-credentials"],
            )
        )

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)
            chains = ooda.synthesize_chains(report)

            assert len(chains) >= 1
            takeover = [c for c in chains if "Account Takeover" in c.title]
            assert len(takeover) >= 1
            assert takeover[0].severity == Severity.CRITICAL
            assert "user_enumeration" in takeover[0].evidence.get("attack_path", "")

        run()

    def test_jwt_cracked_plus_sensitive_data(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        report.add_finding(
            Finding(
                title="JWT HMAC Secret Cracked",
                severity=Severity.CRITICAL,
                confidence=0.99,
                module_name="jwt",
                tags=["jwt", "cracking", "critical"],
            )
        )
        report.add_finding(
            Finding(
                title="Sensitive Data in JWT Payload",
                severity=Severity.HIGH,
                confidence=0.95,
                module_name="jwt",
                tags=["jwt", "sensitive-data"],
            )
        )

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)
            chains = ooda.synthesize_chains(report)

            forgery = [c for c in chains if "Token Forgery" in c.title]
            assert len(forgery) >= 1
            assert forgery[0].severity == Severity.CRITICAL

        run()

    def test_no_chains_without_children(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        config = ScanConfig(target="https://example.com")
        report = ScanReport(target="https://example.com")

        # Only user enum, no weak passwords
        report.add_finding(
            Finding(
                title="User Enumeration Possible",
                severity=Severity.MEDIUM,
                module_name="brute",
                tags=["brute", "user-enumeration"],
            )
        )

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            ooda = OODAEngine(model, config, client)
            chains = ooda.synthesize_chains(report)
            # No chain should be synthesized with only one finding
            takeover = [c for c in chains if "Account Takeover" in c.title]
            assert len(takeover) == 0

        run()
