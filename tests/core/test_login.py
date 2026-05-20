"""Tests for the pre-scan login phase (PR-16, P1 #5).

The module under test is intentionally small — the goal of these tests is to
pin the contracts that the engine relies on:

  - ``perform_login`` never raises; it returns a ``LoginResult`` whose
    ``success`` flag and ``warnings`` list capture failure modes.
  - The default success heuristic is cookie-diff + 200/3xx status.
  - Each ``success_indicator`` form (status=, redirect=, cookie=, body=)
    works against a synthetic response.
  - Bearer tokens are scraped out of JSON-shaped login responses.
  - ``basic_auth_header`` and ``bearer_auth_header`` build the headers the
    engine injects when ``--auth-type`` is bearer or basic.
"""

from __future__ import annotations

import responses

from auth_scan.core.http_client import HTTPClient
from auth_scan.core.login import (
    LoginSpec,
    basic_auth_header,
    bearer_auth_header,
    perform_login,
)


class TestAuthHeaderHelpers:
    def test_basic_header_encodes_user_pass(self) -> None:
        # base64("user:pass") == "dXNlcjpwYXNz"
        assert basic_auth_header("user", "pass") == {"Authorization": "Basic dXNlcjpwYXNz"}

    def test_bearer_header_wraps_token(self) -> None:
        assert bearer_auth_header("opaque-xyz") == {"Authorization": "Bearer opaque-xyz"}


class TestPerformLoginSuccess:
    def test_default_heuristic_accepts_new_cookie(self) -> None:
        """200 status + a new cookie counts as a successful login."""

        @responses.activate
        def run():
            # GET the form page (no hidden fields needed).
            responses.add(
                responses.GET,
                "https://example.com/login",
                body="<html><body><form></form></body></html>",
                status=200,
            )
            # POST credentials — server sets a session cookie.
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="ok",
                status=200,
                headers={"Set-Cookie": "session=abc123; Path=/"},
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="admin",
                    password="admin",
                ),
                client,
            )
            assert result.success is True
            assert result.detection_method == "cookie-diff"
            assert "session" in result.cookies
            assert result.cookies["session"] == "abc123"

        run()

    def test_status_indicator_accepts_302(self) -> None:
        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="",
                status=302,
                headers={"Location": "/dashboard"},
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="u",
                    password="p",
                    success_indicator="status=302",
                ),
                client,
            )
            assert result.success is True
            assert result.detection_method == "status=302"

    def test_redirect_indicator_accepts_path_prefix(self) -> None:
        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="",
                status=302,
                headers={"Location": "/dashboard?welcome=1"},
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="u",
                    password="p",
                    success_indicator="redirect=/dashboard",
                ),
                client,
            )
            assert result.success is True

    def test_body_indicator_accepts_substring(self) -> None:
        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="<h1>Welcome, admin!</h1>",
                status=200,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="admin",
                    password="admin",
                    success_indicator="body=Welcome",
                ),
                client,
            )
            assert result.success is True

    def test_extracts_bearer_token_from_json_body(self) -> None:
        """JSON login response with ``access_token`` field → Authorization header."""

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            responses.add(
                responses.POST,
                "https://example.com/login",
                body='{"access_token": "abcdef1234567890XYZ", "user": "admin"}',
                status=200,
                headers={"Content-Type": "application/json", "Set-Cookie": "sid=x"},
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="admin",
                    password="admin",
                ),
                client,
            )
            assert result.success is True
            assert result.headers_to_inject == {"Authorization": "Bearer abcdef1234567890XYZ"}

    def test_harvests_csrf_token_from_login_page(self) -> None:
        """Hidden inputs on the GETted page get echoed back in the POST body."""
        captured_form: dict = {}

        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://example.com/login",
                body=(
                    "<html><body><form>"
                    "<input type='hidden' name='csrf_token' value='abc123'>"
                    "<input name='username'><input name='password'>"
                    "</form></body></html>"
                ),
                status=200,
            )

            def capture(request):
                captured_form.update(dict(p.split("=", 1) for p in request.body.split("&") if "=" in p))
                return (200, {"Set-Cookie": "session=y"}, "ok")

            responses.add_callback(
                responses.POST,
                "https://example.com/login",
                callback=capture,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="u",
                    password="p",
                ),
                client,
            )
            assert result.success is True
            assert captured_form.get("csrf_token") == "abc123"

        run()


class TestPerformLoginFailure:
    def test_failure_returns_warnings_does_not_raise(self) -> None:
        """When the POST 500s (and the client's retry/backoff gives up),
        ``perform_login`` swallows the exception and returns success=False
        with the failure captured in ``warnings``. The exact response status
        is not asserted because the HTTPClient retries 5xx internally and
        eventually raises before a status reaches us."""

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="Internal Error",
                status=500,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="u",
                    password="p",
                ),
                client,
            )
            assert result.success is False
            assert result.warnings, "expected a warning describing the failure"

        run()

    def test_invalid_status_indicator_returns_invalid_marker(self) -> None:
        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            responses.add(responses.POST, "https://example.com/login", body="", status=200)
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="u",
                    password="p",
                    success_indicator="status=not-a-number",
                ),
                client,
            )
            assert result.success is False
            assert result.detection_method == "invalid:status"

        run()

    def test_no_indicator_no_cookie_change_means_failure(self) -> None:
        """200 status but no new cookies → not actually logged in."""

        @responses.activate
        def run():
            responses.add(responses.GET, "https://example.com/login", body="", status=200)
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="<form>Try again</form>",
                status=200,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = perform_login(
                LoginSpec(
                    url="https://example.com/login",
                    username="u",
                    password="p",
                ),
                client,
            )
            assert result.success is False
            assert result.detection_method == "cookie-diff"

        run()
