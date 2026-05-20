"""Pre-scan login phase — authenticate against the target and capture a session.

P1 #5 (PR-16): without this, every attack module operates on the
unauthenticated probe response, so customer engagements past the login wall
collapse into a 1-finding scan ("missing security headers"). This module
performs a real form POST with the operator's credentials, captures the
resulting session (cookies + Authorization headers if the server hands a JWT
back), and the engine pushes that state into the live HTTP client before
any attack module runs.

Scope:
- Form-based login (GET the page for CSRF, POST credentials).
- Success detection: cookie-diff heuristic by default; optional operator
  override via ``success_indicator`` (status code, response-body substring,
  named cookie, or redirect-target URL prefix).

Out of scope for this PR (deferred to follow-ups):
- HAR file replay.
- Headless-browser / Playwright probes for SPAs.
- Multi-step flows (OAuth dance, captcha, MFA challenge response).
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger(__name__)


@dataclass
class LoginSpec:
    """Describes how to log into the target.

    Field names are deliberately verbose because operators will see them in
    YAML configs. ``url`` is the form-POST endpoint; if the form lives on a
    different page (common when the page is server-rendered), pass that as
    ``form_page_url`` so the GET pulls a fresh CSRF token.
    """

    url: str
    username: str
    password: str
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    # Page to GET for CSRF/hidden field extraction. Defaults to ``url`` when
    # empty — most login forms POST to the same path that renders them.
    form_page_url: str = ""
    # Additional static form fields (e.g. ``{"remember_me": "1"}``).
    extra_fields: dict[str, str] = field(default_factory=dict)
    # Success-detection override. One of:
    #   "status=302"           — exact status code after the POST
    #   "redirect=/dashboard"  — Location header starts with this path
    #   "cookie=session"       — named cookie appears in response
    #   "body=Welcome"         — substring present in response body
    # Empty = use the default cookie-diff heuristic.
    success_indicator: str = ""


@dataclass
class LoginResult:
    """Outcome of a login attempt — always returned, never raised.

    The engine decides whether to abort or continue with the unauthenticated
    surface based on ``success``. Even on failure, ``warnings`` and
    ``response_status`` are populated so the engine can emit a useful
    finding about *why* the login didn't take.
    """

    success: bool
    cookies: dict[str, str] = field(default_factory=dict)
    headers_to_inject: dict[str, str] = field(default_factory=dict)
    final_url: str = ""
    response_status: int = 0
    warnings: list[str] = field(default_factory=list)
    detection_method: str = ""  # how success was determined (for the report)


# Regex for "Bearer <token>" in response bodies/headers — we capture
# whatever the login response hands back so subsequent module requests can
# carry it as an Authorization header. JWT tokens are the common case but
# any opaque bearer works.
_BEARER_TOKEN_RE = re.compile(
    r"(?:access_token|token|bearer)[\"'\s:=]+([A-Za-z0-9_\-\.]{16,})",
    re.IGNORECASE,
)


def perform_login(spec: LoginSpec, http_client: Any) -> LoginResult:
    """Execute a form-based login and return the captured session.

    Steps:
    1. GET the form page (``form_page_url`` or ``url``) to harvest hidden
       inputs (CSRF token, etc.). Skipped if the GET fails — many APIs
       expose a JSON login endpoint that doesn't need a CSRF token.
    2. POST credentials + harvested hidden fields to ``url``.
    3. Determine success via ``success_indicator`` if set, otherwise via a
       cookie-diff against the pre-login state.
    4. On success, scrape Authorization-Bearer-style tokens from the
       response body/headers and surface them in ``headers_to_inject``.

    The function never raises — network errors are captured in
    ``warnings`` and returned as ``LoginResult(success=False, ...)``.
    """
    form_page = spec.form_page_url or spec.url
    pre_cookies = _snapshot_cookies(http_client)
    hidden_fields: dict[str, str] = {}
    warnings: list[str] = []

    # Step 1: harvest hidden fields (CSRF, etc.).
    try:
        from bs4 import BeautifulSoup

        page_resp = http_client.get(form_page)
        if page_resp.status_code < 400:
            try:
                soup = BeautifulSoup(page_resp.text, "lxml")
                for inp in soup.find_all("input"):
                    if inp.get("type", "").lower() == "hidden":
                        name = inp.get("name")
                        if name:
                            hidden_fields[name] = inp.get("value", "")
            except Exception as exc:
                warnings.append(f"could not parse login page HTML: {exc}")
        else:
            warnings.append(
                f"GET {form_page} returned {page_resp.status_code}; "
                "proceeding without CSRF token (this may be a JSON endpoint)"
            )
    except Exception as exc:
        warnings.append(f"could not fetch login page {form_page}: {exc}")

    # Step 2: POST credentials.
    form_data = {
        **hidden_fields,
        **spec.extra_fields,
        spec.username_field: spec.username,
        spec.password_field: spec.password,
    }

    try:
        if spec.method.upper() == "POST":
            resp = http_client.post(spec.url, data=form_data, allow_redirects=False)
        else:
            # GET-based login (rare, but some legacy systems do it).
            resp = http_client.get(spec.url, params=form_data, allow_redirects=False)
    except Exception as exc:
        warnings.append(f"login request failed: {exc}")
        return LoginResult(success=False, warnings=warnings)

    # Step 3: determine success.
    post_cookies = _snapshot_cookies(http_client)
    detection, success = _detect_success(spec.success_indicator, resp, pre_cookies, post_cookies)

    # Step 4: capture session state.
    new_cookies = {k: v for k, v in post_cookies.items() if pre_cookies.get(k) != v}
    headers_to_inject = _extract_bearer(resp)

    final_url = getattr(resp, "url", spec.url) or spec.url
    return LoginResult(
        success=success,
        cookies=new_cookies,
        headers_to_inject=headers_to_inject,
        final_url=final_url,
        response_status=getattr(resp, "status_code", 0),
        warnings=warnings,
        detection_method=detection,
    )


def _snapshot_cookies(http_client: Any) -> dict[str, str]:
    """Return the HTTP client's current cookie jar as a plain dict."""
    if not hasattr(http_client, "session"):
        return {}
    try:
        return dict(http_client.session.cookies)
    except Exception:
        return {}


def _detect_success(
    indicator: str,
    resp: Any,
    pre_cookies: dict[str, str],
    post_cookies: dict[str, str],
) -> tuple[str, bool]:
    """Return ``(detection_method, success)`` for the operator's success rule.

    Default (empty ``indicator``) uses the cookie-diff heuristic: any new
    cookie OR any cookie whose value changed counts as a successful login,
    provided the response status is in (200, 301, 302, 303).
    """
    status = getattr(resp, "status_code", 0)

    if indicator:
        if indicator.startswith("status="):
            try:
                expected = int(indicator.split("=", 1)[1])
            except ValueError:
                return "invalid:status", False
            return f"status={expected}", status == expected
        if indicator.startswith("redirect="):
            target = indicator.split("=", 1)[1]
            location = ""
            try:
                location = resp.headers.get("Location", "") or resp.headers.get("location", "")
            except Exception:
                pass
            return f"redirect={target}", location.startswith(target)
        if indicator.startswith("cookie="):
            name = indicator.split("=", 1)[1]
            return f"cookie={name}", name in post_cookies
        if indicator.startswith("body="):
            needle = indicator.split("=", 1)[1]
            try:
                body = getattr(resp, "text", "") or ""
            except Exception:
                body = ""
            return f"body={needle}", needle in body
        return f"unknown-indicator:{indicator}", False

    # Default heuristic: status looks like success AND we got a new/changed cookie.
    status_ok = status in (200, 301, 302, 303)
    cookies_changed = any(pre_cookies.get(k) != v for k, v in post_cookies.items())
    new_cookie_appeared = any(k not in pre_cookies for k in post_cookies)
    return (
        "cookie-diff",
        status_ok and (cookies_changed or new_cookie_appeared),
    )


def _extract_bearer(resp: Any) -> dict[str, str]:
    """Pull Authorization-Bearer-style tokens out of the login response.

    Looks at the response body (JSON or HTML) for ``access_token``/``token``
    field-like patterns. Returns ``{"Authorization": "Bearer <token>"}`` if
    one is found; empty dict otherwise. Worst case is a false positive on a
    page that mentions a 16+ char string — the header gets set but the
    server ignores it.
    """
    # First check if the response itself set an Authorization header (rare
    # but possible when proxies pass through). httpx-style responses expose
    # this via .headers; requests does too.
    try:
        headers = getattr(resp, "headers", {}) or {}
        bearer = headers.get("Authorization") or headers.get("authorization")
        if bearer and "bearer" in bearer.lower():
            return {"Authorization": bearer}
    except Exception:
        pass

    try:
        body = getattr(resp, "text", "") or ""
    except Exception:
        return {}

    match = _BEARER_TOKEN_RE.search(body)
    if match:
        token = match.group(1)
        return {"Authorization": f"Bearer {token}"}
    return {}


def basic_auth_header(username: str, password: str) -> dict[str, str]:
    """Build an HTTP Basic ``Authorization`` header value.

    Used by the engine when ``auth_type == 'basic'`` — no login phase
    needed, just inject the header before scan modules run.
    """
    raw = f"{username}:{password}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}


def bearer_auth_header(token: str) -> dict[str, str]:
    """Build a ``Bearer`` Authorization header for ``auth_type == 'bearer'``."""
    return {"Authorization": f"Bearer {token}"}
