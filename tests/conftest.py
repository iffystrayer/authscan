"""Shared pytest fixtures for auth-scan tests."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from auth_scan.attacks.base import ScanReport
from auth_scan.core.config import ScanConfig


@pytest.fixture(scope="session")
def vuln_app():
    """Start the vulnerable Flask test app and return a test client."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent / "fixtures" / "vuln_app"))
    from app import app

    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="session")
def vuln_app_url(vuln_app) -> str:
    """Base URL for the vulnerable app when running via Flask test client."""
    return "http://localhost"


@pytest.fixture
def config() -> ScanConfig:
    """Return a basic ScanConfig with default values."""
    return ScanConfig(
        target="https://example.com",
        modules=["probe", "jwt", "session", "brute"],
        rate_limit=100,  # No rate limiting in tests
        timeout=10,
    )


@pytest.fixture
def sample_report() -> ScanReport:
    """Return a ScanReport with some sample findings."""
    from auth_scan.attacks.base import Finding, Severity

    report = ScanReport(
        target="https://example.com",
        effective_target="https://example.com",
        status="completed",
    )
    report.add_finding(Finding(
        title="Missing HSTS Header",
        description="HSTS header not present.",
        severity=Severity.MEDIUM,
        module_name="probe",
        tags=["headers"],
        remediation="Add Strict-Transport-Security header.",
    ))
    report.add_finding(Finding(
        title="Session Cookie Missing HttpOnly",
        description="Session cookie has no HttpOnly flag.",
        severity=Severity.HIGH,
        module_name="session",
        tags=["session"],
        remediation="Set HttpOnly flag on session cookie.",
    ))
    report.add_finding(Finding(
        title="JWT alg=none Accepted",
        description="Server accepts unsigned JWTs.",
        severity=Severity.CRITICAL,
        module_name="jwt_analyzer",
        tags=["jwt", "critical"],
        remediation="Reject tokens with alg=none.",
    ))
    return report


@pytest.fixture
def sample_jwt_token() -> str:
    """Return a sample JWT for testing."""
    import base64
    import json

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": "testuser",
            "email": "test@example.com",
            "exp": 9999999999,
            "iat": 1000000000,
        }).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesignature"


@pytest.fixture
def sample_jwt_none() -> str:
    """Return a JWT with alg=none for testing."""
    import base64
    import json

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "admin", "role": "admin"}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}."


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """Create a temporary config file for testing."""
    import yaml

    config_data = {
        "target": "https://example.com",
        "modules": ["probe", "jwt"],
        "rate_limit": 5,
    }
    path = tmp_path / "test-config.yml"
    path.write_text(yaml.dump(config_data))
    return path


@pytest.fixture
def mock_http_client():
    """Return a mock-compatible HTTP client for unit tests."""
    import responses

    @responses.activate
    def _make_client(base_url="https://example.com", **kwargs):
        from auth_scan.core.http_client import HTTPClient
        return HTTPClient(base_url=base_url, rate_limit=100, **kwargs)

    return _make_client
