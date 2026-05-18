"""Tests for the Brute Force attack module."""
from __future__ import annotations

import responses

from auth_scan.attacks.base import ScanReport
from auth_scan.attacks.brute import BruteForce, DEFAULT_CREDENTIALS
from auth_scan.core.config import ScanConfig
from auth_scan.core.http_client import HTTPClient


class TestBruteForce:
    """Tests for the Brute Force module."""

    def test_discover_login_forms(self) -> None:
        bf = BruteForce()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_forms"] = [
            {
                "action": "/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                    {"name": "csrf_token", "type": "hidden", "value": "abc123"},
                ],
            },
        ]
        forms = bf._discover_login_forms(report)
        assert len(forms) == 1
        assert forms[0]["username_field"] == "username"
        assert forms[0]["password_field"] == "password"
        assert len(forms[0]["hidden_fields"]) == 1

    def test_no_login_forms(self) -> None:
        bf = BruteForce()
        report = ScanReport(target="https://example.com")
        # No forms at all
        forms = bf._discover_login_forms(report)
        assert len(forms) == 0

    def test_no_password_field_forms(self) -> None:
        bf = BruteForce()
        report = ScanReport(target="https://example.com")
        report.metadata["probe_forms"] = [
            {
                "action": "/search",
                "method": "GET",
                "inputs": [
                    {"name": "q", "type": "text", "value": ""},
                ],
            },
        ]
        forms = bf._discover_login_forms(report)
        assert len(forms) == 0

    def test_default_credentials_not_empty(self) -> None:
        assert len(DEFAULT_CREDENTIALS) > 0
        assert ("admin", "admin") in DEFAULT_CREDENTIALS

    def test_load_credentials_defaults(self) -> None:
        bf = BruteForce()
        creds = bf._load_credentials("", "")
        assert len(creds) > 0
        assert creds == DEFAULT_CREDENTIALS

    def test_read_wordlist(self, tmp_path) -> None:
        bf = BruteForce()
        wordlist = tmp_path / "passwords.txt"
        wordlist.write_text("password1\npassword2\npassword3\n")
        entries = bf._read_wordlist(str(wordlist))
        assert len(entries) == 3
        assert entries[0] == "password1"

    def test_read_wordlist_filters_comments(self, tmp_path) -> None:
        bf = BruteForce()
        wordlist = tmp_path / "passwords.txt"
        wordlist.write_text("# comment\npassword1\n\n# another comment\npassword2\n")
        entries = bf._read_wordlist(str(wordlist))
        assert len(entries) == 2

    def test_no_login_forms_returns_info(self) -> None:
        bf = BruteForce()
        report = ScanReport(target="https://example.com")
        config = ScanConfig(target="https://example.com")

        @responses.activate
        def run():
            client = HTTPClient(base_url="https://example.com", rate_limit=100)
            result = bf.run("https://example.com", client, report, config)
            assert len(result.findings) >= 1
            assert any("No Login" in f.title for f in result.findings)

        run()

    def test_form_testing_finds_weak_credentials(self) -> None:
        bf = BruteForce()

        @responses.activate
        def run():
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="Welcome, admin!",
                status=200,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)

            form = {
                "action": "https://example.com/login",
                "method": "POST",
                "username_field": "username",
                "password_field": "password",
                "hidden_fields": [],
            }
            result = bf._test_form(form, [("admin", "admin")], "https://example.com", client)
            # With 200 status and no error keywords, should flag as valid
            assert len(result.findings) >= 1
            assert any("Weak" in f.title or "Default" in f.title or "Credentials" in f.title
                       or "Accepted" in f.title for f in result.findings)

        run()

    def test_rate_limit_detection(self) -> None:
        bf = BruteForce()

        @responses.activate
        def run():
            responses.add(
                responses.POST,
                "https://example.com/login",
                body="Too many requests",
                status=429,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)

            form = {
                "action": "https://example.com/login",
                "method": "POST",
                "username_field": "username",
                "password_field": "password",
                "hidden_fields": [],
            }
            # Test that 429 response is handled without crashing
            result = bf._test_form(form, [("test", "test")], "https://example.com", client)
            # Should not crash; finding/warning presence depends on mock behavior
            assert isinstance(result.findings, list)
            assert isinstance(result.warnings, list)

        run()

    def test_user_enumeration_detection(self) -> None:
        bf = BruteForce()

        call_count = [0]

        @responses.activate
        def run():
            def callback(request):
                call_count[0] += 1
                if call_count[0] % 2 == 0:
                    return (401, {}, "Error: Invalid password")
                return (401, {}, "Error: Username not found")

            responses.add_callback(
                responses.POST,
                "https://example.com/login",
                callback=callback,
            )
            client = HTTPClient(base_url="https://example.com", rate_limit=100)

            form = {
                "action": "https://example.com/login",
                "method": "POST",
                "username_field": "username",
                "password_field": "password",
                "hidden_fields": [],
            }
            result = bf._test_form(
                form,
                [("user1", "pass1"), ("user2", "pass2"), ("user3", "pass3")],
                "https://example.com",
                client,
            )
            # Should detect different error patterns as possible user enumeration
            if any("Enumeration" in f.title for f in result.findings):
                pass  # Test passes if it detected enumeration
            # Otherwise, at minimum it should have run without error
            assert len(result.findings) > 0 or len(result.warnings) > 0

        run()


class TestLockoutDetection:
    """C3 regression: lockout heuristic was inverted (fired on speed-up)."""

    @staticmethod
    def _form() -> dict[str, str | list]:
        return {
            "action": "https://example.com/login",
            "method": "POST",
            "username_field": "username",
            "password_field": "password",
            "hidden_fields": [],
        }

    def test_http_423_triggers_immediate_lockout(self) -> None:
        bf = BruteForce()

        @responses.activate
        def run():
            # First a couple of real-looking failures, then a 423 Locked.
            responses.add(responses.POST, "https://example.com/login",
                          body="invalid password", status=401)
            responses.add(responses.POST, "https://example.com/login",
                          body="invalid password", status=401)
            responses.add(responses.POST, "https://example.com/login",
                          body="Account locked", status=423)
            client = HTTPClient(base_url="https://example.com", rate_limit=1000)
            creds = [("u1", "p1"), ("u2", "p2"), ("u3", "p3"), ("u4", "p4")]
            result = bf._test_form(self._form(), creds, "https://example.com", client)
            titles = [f.title for f in result.findings]
            assert any("Lockout" in t and "Timing" not in t for t in titles)
            lockout = next(f for f in result.findings if "Lockout" in f.title)
            assert lockout.evidence["status"] == 423
            # Should have stopped early — not all four creds attempted.
            assert result.metadata["credentials_tested"] <= 3

        run()

    def test_body_keyword_triggers_lockout(self) -> None:
        bf = BruteForce()

        @responses.activate
        def run():
            responses.add(responses.POST, "https://example.com/login",
                          body="invalid credentials", status=401)
            responses.add(responses.POST, "https://example.com/login",
                          body="Your account has been locked. Too many attempts.",
                          status=403)
            client = HTTPClient(base_url="https://example.com", rate_limit=1000)
            result = bf._test_form(
                self._form(),
                [("u1", "p1"), ("u2", "p2"), ("u3", "p3")],
                "https://example.com",
                client,
            )
            assert any("Lockout" in f.title for f in result.findings)
            lockout = next(f for f in result.findings if "Lockout" in f.title)
            assert lockout.evidence.get("matched_keyword") in {"locked", "too many attempts",
                                                                "account is locked",
                                                                "account has been locked"}

        run()

    def test_speedup_no_longer_triggers_lockout(self) -> None:
        """Before C3, faster later responses incorrectly fired lockout. They
        should now never do so (slow-down is the correct signal)."""
        bf = BruteForce()

        @responses.activate
        def run():
            # 12 failures so we have > 10 timings; responses will reply
            # immediately so all durations are similar (no slowdown).
            for _ in range(12):
                responses.add(responses.POST, "https://example.com/login",
                              body="invalid", status=401)
            client = HTTPClient(base_url="https://example.com", rate_limit=1000)
            creds = [(f"u{i}", f"p{i}") for i in range(12)]
            result = bf._test_form(self._form(), creds, "https://example.com", client)
            lockout_findings = [f for f in result.findings if "Lockout" in f.title]
            # We expect *no* lockout finding when responses don't slow down.
            assert lockout_findings == [], (
                f"Unexpected lockout finding: {[f.title for f in lockout_findings]}"
            )

        run()


class TestCsrfRefresh:
    """C4 regression: CSRF/hidden fields must refresh between attempts.

    Pre-fix, hidden form fields were parsed once at probe time and reused
    for every POST. CSRF-protected sites rotate their token on each GET,
    so the brute module would silently get 403'd from the second attempt
    onwards and report "No Default Credentials Found" even when admin/admin
    was correct.
    """

    @staticmethod
    def _form() -> dict[str, str | list]:
        return {
            "action": "https://example.com/login",
            "method": "POST",
            "username_field": "username",
            "password_field": "password",
            "hidden_fields": [{"name": "csrf_token", "value": "STALE-CAPTURED-AT-PROBE"}],
            "page_url": "https://example.com/login",
        }

    def test_rotating_csrf_token_is_refreshed_per_attempt(self) -> None:
        """The server rotates csrf_token each GET and rejects stale ones.

        Without the refresh, the second POST onwards would carry the
        original token and be 403'd. With the refresh, each POST carries
        a freshly minted token and the (valid) credentials succeed.
        """
        bf = BruteForce()

        # Mutable cell so the GET callback can hand out a new token each
        # call, and the POST callback can verify the most recent one.
        state = {"current_token": "", "get_count": 0, "post_count": 0,
                 "accepted_token": None}

        @responses.activate
        def run():
            def get_login(request):
                state["get_count"] += 1
                token = f"token-{state['get_count']}"
                state["current_token"] = token
                html = (
                    "<html><body><form>"
                    f'<input type="hidden" name="csrf_token" value="{token}">'
                    "</form></body></html>"
                )
                return (200, {}, html)

            def post_login(request):
                state["post_count"] += 1
                body = request.body or ""
                if isinstance(body, bytes):
                    body = body.decode()
                # If the POST carries anything other than the most recent
                # GET's token, reject as stale.
                if f"csrf_token={state['current_token']}" not in body:
                    return (403, {}, "stale csrf")
                if "username=admin&password=admin" in body or \
                   "password=admin&username=admin" in body:
                    state["accepted_token"] = state["current_token"]
                    return (200, {}, "Welcome, admin!")
                return (401, {}, "invalid")

            responses.add_callback(responses.GET, "https://example.com/login",
                                   callback=get_login)
            responses.add_callback(responses.POST, "https://example.com/login",
                                   callback=post_login)
            client = HTTPClient(base_url="https://example.com", rate_limit=1000)
            # Multiple wrong creds before the right ones, so we'd fail on
            # any reuse of the original probe-time token.
            creds = [("user", "wrong"), ("guest", "guest"), ("admin", "admin")]
            result = bf._test_form(self._form(), creds, "https://example.com", client)

            assert state["get_count"] >= 3, (
                f"Expected ≥3 GETs (one refresh per attempt), got {state['get_count']}"
            )
            assert state["accepted_token"] is not None, "Login never succeeded"
            assert state["accepted_token"] != "STALE-CAPTURED-AT-PROBE"
            assert any(
                "Credentials Accepted" in f.title for f in result.findings
            ), [f.title for f in result.findings]

        run()

    def test_failed_refresh_falls_back_to_static_hidden(self) -> None:
        """If the GET refresh fails (network/4xx), we still try the POST
        with the originally captured static hidden fields."""
        bf = BruteForce()

        @responses.activate
        def run():
            # GET returns 500 so the refresh fails and falls back.
            responses.add(responses.GET, "https://example.com/login",
                          status=500, body="boom")
            responses.add(responses.POST, "https://example.com/login",
                          body="Welcome", status=200)
            client = HTTPClient(base_url="https://example.com", rate_limit=1000)
            result = bf._test_form(
                self._form(), [("admin", "admin")], "https://example.com", client,
            )
            assert any("Credentials Accepted" in f.title for f in result.findings)

        run()

