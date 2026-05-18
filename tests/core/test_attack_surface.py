"""Tests for AttackSurfaceModel."""

from __future__ import annotations

from auth_scan.core.attack_surface import (
    AttackSurfaceModel,
    AuthEndpoint,
    ModelSession,
    ModelToken,
)


class TestAttackSurfaceModel:
    """Tests for the AttackSurfaceModel."""

    def test_initialization(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        assert model.target == "https://example.com"
        assert model.confidence == 0.0
        assert len(model.endpoints) == 0
        assert len(model.tokens) == 0
        assert len(model.sessions) == 0

    def test_add_endpoint(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        ep = AuthEndpoint(url="/login", method="POST", auth_mechanism="form")
        model.add_endpoint(ep)
        assert len(model.endpoints) == 1
        assert model.endpoints["/login"].auth_mechanism == "form"
        assert "form" in model.auth_mechanisms

    def test_add_duplicate_endpoint_merges(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.add_endpoint(AuthEndpoint(url="/api", method="GET", auth_mechanism=None))
        model.add_endpoint(
            AuthEndpoint(url="/api", method="POST", auth_mechanism="jwt", form_fields=["token"])
        )
        assert len(model.endpoints) == 1
        assert model.endpoints["/api"].auth_mechanism == "jwt"
        assert "token" in model.endpoints["/api"].form_fields

    def test_add_token(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        token = ModelToken(token_type="jwt", location="cookie:auth", algorithm="HS256")
        model.add_token(token)
        assert len(model.tokens) == 1
        assert model.tokens[0].algorithm == "HS256"

    def test_add_token_dedup(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.add_token(ModelToken(token_type="jwt", location="cookie:auth", algorithm="HS256"))
        model.add_token(ModelToken(token_type="jwt", location="cookie:auth", weaknesses=["expired"]))
        assert len(model.tokens) == 1
        assert "expired" in model.tokens[0].weaknesses

    def test_add_session(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        session = ModelSession(cookie_name="sessionid")
        model.add_session(session)
        assert len(model.sessions) == 1

    def test_confidence_probe_only(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        model.estimate_confidence()
        assert model.confidence == 0.15

    def test_confidence_increases_with_discovery(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        model.mark_mechanism_tested("form")
        model.mark_mechanism_tested("jwt")
        model.add_token(ModelToken(token_type="jwt", location="cookie:auth"))
        model.add_session(ModelSession(cookie_name="sid"))
        model.estimate_confidence()
        assert model.confidence > 0.15

    def test_confidence_penalty_for_failures(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        model.mark_module_failed("brute")
        model.mark_module_failed("oauth")
        model.estimate_confidence()
        assert model.confidence == 0.15 - 0.10  # 0.15 base - 2 × 0.05

    def test_confidence_capped_at_1(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.mark_module_run("probe")
        for i in range(20):
            model.mark_mechanism_tested(f"mech_{i}")
        for i in range(10):
            model.add_token(ModelToken(token_type="jwt", location=f"loc_{i}"))
        for i in range(10):
            model.add_session(ModelSession(cookie_name=f"cookie_{i}"))
        model.estimate_confidence()
        assert model.confidence <= 1.0
        assert model.confidence >= 0.95  # Should be near max

    def test_get_high_value_targets(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.add_endpoint(
            AuthEndpoint(url="/login", auth_mechanism="form", status=200, form_fields=["u", "p"])
        )
        model.add_endpoint(AuthEndpoint(url="/robots.txt", auth_mechanism=None, status=404))
        targets = model.get_high_value_targets()
        assert len(targets) >= 1
        # /login should be higher priority than /robots.txt
        assert targets[0] == "/login"

    def test_get_unprotected_endpoints(self) -> None:
        model = AttackSurfaceModel(target="https://example.com")
        model.add_endpoint(AuthEndpoint(url="/public", auth_mechanism="none"))
        model.add_endpoint(AuthEndpoint(url="/api", auth_mechanism="jwt"))
        unprotected = model.get_unprotected_endpoints()
        assert len(unprotected) == 1
        assert unprotected[0].url == "/public"
