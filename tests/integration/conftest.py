"""Session-scoped fixture that runs the vuln_app as a real Flask process.

Why a subprocess rather than ``flask.testing.test_client()``? The whole
point of this suite is to exercise the *real* HTTP path through
``HTTPClient`` — rate limiting, redirect scope, retry logic, body
capture. The in-process test client bypasses all of that.

The fixture is session-scoped so the cost (~1.5 s startup) is paid once
per ``pytest`` invocation regardless of how many integration tests run.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests


def _free_port() -> int:
    """Grab a TCP port the OS isn't using right now.

    There's an inherent TOCTOU race between releasing this port and the
    Flask subprocess binding to it, but it's the standard pattern and
    far less flaky than a hard-coded port across xdist workers.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_health(base_url: str, timeout: float = 10.0) -> None:
    """Poll ``GET /health`` until 200 or the deadline elapses."""
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = requests.get(f"{base_url}/health", timeout=1.0)
            if resp.status_code == 200:
                return
        except requests.RequestException as exc:
            last_exc = exc
        time.sleep(0.1)
    raise RuntimeError(f"vuln_app did not become healthy at {base_url} within {timeout}s: {last_exc!r}")


@pytest.fixture(scope="session")
def vuln_app_url() -> Iterator[str]:
    """Fork tests/fixtures/vuln_app/app.py and yield its base URL.

    Teardown SIGTERMs the child and waits up to 5 s before SIGKILL.
    """
    port = _free_port()
    app_path = Path(__file__).resolve().parents[1] / "fixtures" / "vuln_app" / "app.py"
    if not app_path.exists():
        pytest.skip(f"vuln_app not found at {app_path}")

    env = os.environ.copy()
    env["PORT"] = str(port)
    # Set FLASK_ENV=production to avoid the debug-mode reloader (which
    # spawns a child process and races our health check).
    env.setdefault("FLASK_ENV", "production")
    # Pop variables that Flask interprets as "I'm the reloader child" —
    # they suppress server startup and produce a silent process.
    env.pop("WERKZEUG_RUN_MAIN", None)
    env.pop("WERKZEUG_SERVER_FD", None)

    # Capture stdout+stderr so a startup failure isn't invisible — pytest
    # will surface them in the RuntimeError message if /health never
    # responds.
    proc = subprocess.Popen(  # noqa: S603 — local subprocess, audited args
        [sys.executable, str(app_path)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )

    base_url = f"http://127.0.0.1:{port}"
    try:
        try:
            _wait_for_health(base_url)
        except RuntimeError as exc:
            # Surface whatever Flask printed before it died.
            try:
                out = proc.stdout.read(4096).decode("utf-8", errors="replace") if proc.stdout else ""
            except Exception:
                out = "<unavailable>"
            raise RuntimeError(f"{exc}\nvuln_app output: {out!r}") from None
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


@pytest.fixture
def scan_engine_for(vuln_app_url: str):
    """Factory: build a fresh ``ScanEngine`` bound to the vuln_app URL.

    Tests typically need to tweak ``modules`` or add wordlists, so we
    return a callable rather than a pre-built engine.
    """
    from auth_scan.core.config import ScanConfig
    from auth_scan.core.engine import ScanEngine

    def _build(**overrides) -> ScanEngine:
        cfg = ScanConfig(
            target=vuln_app_url,
            modules=overrides.pop("modules", ["probe"]),
            # vuln_app is local — no need to throttle.
            rate_limit=100,
            timeout=10,
            # vuln_app binds to 127.0.0.1; without this opt-in the C5
            # redirect guard refuses to follow same-host redirects.
            allow_private_redirects=True,
        )
        for key, value in overrides.items():
            setattr(cfg, key, value)
        return ScanEngine(cfg)

    return _build
