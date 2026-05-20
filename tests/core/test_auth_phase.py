"""Integration tests for the engine's pre-scan auth phase (PR-16, P1 #5).

These tests exercise ``ScanEngine._apply_auth_phase`` directly rather than
the full ``run()`` lifecycle, because we want to assert exactly how the
phase mutates the HTTP client and the report — full scans add too much
noise for these contracts.

Coverage:
- bearer/basic header injection paths (no network, just header math)
- form login success path (cookies appear on the live session)
- form login failure path (HIGH finding added, scan continues)
- misconfiguration paths (missing creds → HIGH finding, no header injected)
"""

from __future__ import annotations

import responses

from auth_scan.attacks.base import Severity
from auth_scan.core.config import ScanConfig
from auth_scan.core.engine import ScanEngine


def _engine_with_initialised_client(**config_overrides) -> ScanEngine:
    """Build a ScanEngine and run only the bits we need for auth-phase tests.

    We do NOT run ``engine.run()`` because that drags in probe + modules and
    we only want to exercise ``_apply_auth_phase``.
    """
    cfg = ScanConfig(target="https://example.com", rate_limit=100)
    for k, v in config_overrides.items():
        setattr(cfg, k, v)
    engine = ScanEngine(cfg)
    engine._init_http_client()
    return engine


class TestBearerInjection:
    def test_bearer_injected_when_token_provided(self) -> None:
        engine = _engine_with_initialised_client(
            auth_type="bearer",
            auth_credentials={"token": "opaque-xyz"},
        )
        engine._apply_auth_phase()
        assert engine.http is not None
        assert engine.http.session.headers.get("Authorization") == "Bearer opaque-xyz"
        meta = engine.report.metadata["auth_phase"]
        assert meta["type"] == "bearer"
        assert meta["success"] is True

    def test_bearer_missing_token_adds_high_finding(self) -> None:
        engine = _engine_with_initialised_client(
            auth_type="bearer",
            auth_credentials={},
        )
        engine._apply_auth_phase()
        assert engine.http is not None
        assert "Authorization" not in engine.http.session.headers
        findings = [f for f in engine.report.findings if "Bearer Token Missing" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestBasicInjection:
    def test_basic_injected_when_user_and_password_provided(self) -> None:
        engine = _engine_with_initialised_client(
            auth_type="basic",
            auth_credentials={"username": "user", "password": "pass"},
        )
        engine._apply_auth_phase()
        assert engine.http is not None
        # base64("user:pass") == "dXNlcjpwYXNz"
        assert engine.http.session.headers.get("Authorization") == "Basic dXNlcjpwYXNz"

    def test_basic_missing_creds_adds_high_finding(self) -> None:
        engine = _engine_with_initialised_client(
            auth_type="basic",
            auth_credentials={"username": "only-user"},
        )
        engine._apply_auth_phase()
        assert engine.http is not None
        assert "Authorization" not in engine.http.session.headers
        findings = [f for f in engine.report.findings if "Basic Credentials Missing" in f.title]
        assert len(findings) == 1


class TestFormLogin:
    def test_successful_form_login_captures_cookie(self) -> None:
        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="ok",
                status=200,
                headers={"Set-Cookie": "session=abc; Path=/"},
            )

            engine = _engine_with_initialised_client(
                auth_type="form",
                auth_credentials={"username": "admin", "password": "admin"},
                login_url="https://example.com/login",
            )
            engine._apply_auth_phase()
            assert engine.http is not None
            # Cookie ended up on the live session — subsequent module
            # requests will carry it.
            assert engine.http.session.cookies.get("session") == "abc"
            # Report records success + an INFO finding so operators see it.
            meta = engine.report.metadata["auth_phase"]
            assert meta["type"] == "form"
            assert meta["success"] is True
            assert "session" in meta["cookies_captured"]
            assert any(f.title == "Authenticated Scan: Login Succeeded" for f in engine.report.findings)

        run()

    def test_failed_form_login_adds_high_finding_but_does_not_abort(self) -> None:
        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            # POST returns 200 with no new cookies — login didn't take.
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="<form>Bad password</form>",
                status=200,
            )

            engine = _engine_with_initialised_client(
                auth_type="form",
                auth_credentials={"username": "u", "password": "wrong"},
                login_url="https://example.com/login",
            )
            engine._apply_auth_phase()
            findings = [f for f in engine.report.findings if f.title == "Authenticated Scan: Login Failed"]
            assert len(findings) == 1
            assert findings[0].severity == Severity.HIGH
            # Engine did NOT abort — scan would continue against the
            # unauthenticated surface. ``status`` is still whatever
            # ``__init__`` set; we never touched ``run()``.
            assert engine.report.status == "initialized"

        run()

    def test_form_login_missing_url_adds_finding_and_skips_request(self) -> None:
        engine = _engine_with_initialised_client(
            auth_type="form",
            auth_credentials={"username": "u", "password": "p"},
            # login_url left empty
        )
        engine._apply_auth_phase()
        findings = [f for f in engine.report.findings if "Form Login Configuration Incomplete" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestNoAuth:
    def test_empty_auth_type_is_noop(self) -> None:
        engine = _engine_with_initialised_client()  # default auth_type=""
        engine._apply_auth_phase()
        assert engine.http is not None
        # No header, no findings, no metadata.
        assert "Authorization" not in engine.http.session.headers
        assert "auth_phase" not in engine.report.metadata
        assert engine.report.findings == []

    def test_unknown_auth_type_logs_low_finding(self) -> None:
        engine = _engine_with_initialised_client(auth_type="totally-fake")
        engine._apply_auth_phase()
        low = [f for f in engine.report.findings if "Unknown auth_type" in f.title]
        assert len(low) == 1
        assert low[0].severity == Severity.LOW
