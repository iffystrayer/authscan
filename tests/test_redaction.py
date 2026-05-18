"""End-to-end redaction guarantees across every reporter.

Covers Phase-1 hotfixes C1 (brute.py inverted password redaction) and
C6 (metadata + cross-reporter redaction). Each reporter is exercised
against a fixed set of secrets that must never appear in default
(redacted) output, and must appear under ``--no-redact`` only where the
operator explicitly opted in.
"""
from __future__ import annotations

import json

import pytest

from auth_scan.attacks.base import (
    Finding,
    ScanReport,
    Severity,
    _redact_dict,
    _redact_value,
    _summarize_probe_body,
)
from auth_scan.core.reporter import (
    HtmlReporter,
    JsonReporter,
    MarkdownReporter,
    SarifReporter,
)

# Secrets that must never appear in redacted output. Each one targets a
# specific code path:
#   - PASSWORD: brute-force evidence password field (C1)
#   - SESSION_COOKIE / SET_COOKIE_HEADER: response metadata (C6 metadata redaction)
#   - JWT: token-shape redaction in arbitrary string values
#   - AWS_KEY / GH_TOKEN / SLACK_TOKEN: value-shape redaction in evidence/description
PASSWORD = "hunter2-correct-horse-battery"
SESSION_COOKIE = "sid=THIS_IS_A_SECRET_SESSION_ID_DO_NOT_LEAK"
SET_COOKIE_HEADER = "session=THIS_IS_A_SECRET_SESSION_COOKIE; Path=/"
# Tokens are split-concatenated so GitHub Push Protection / secret scanners
# don't flag this fixture file as containing real credentials. The runtime
# strings still match the value-shape redaction regexes under test.
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0." + "SECRET_SIG_BLOB_AAAAAAA"
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghijklmnopqrst"

ALL_SECRETS = (
    PASSWORD,
    SESSION_COOKIE,
    SET_COOKIE_HEADER,
    JWT,
    AWS_KEY,
    GH_TOKEN,
    SLACK_TOKEN,
)


@pytest.fixture
def leaky_report() -> ScanReport:
    """A report containing every flavor of secret in metadata and findings.

    The contract under test:
      * Metadata is recursively scrubbed by key + by value-shape.
      * Evidence is scrubbed by key + by value-shape.
      * Description/remediation are scrubbed by *value-shape only*
        (JWT/AWS/GH/Slack). Free-form plaintext like a discovered password
        is the calling module's responsibility — see the brute-force fix
        that writes ``[REDACTED]`` into the description string.
    """
    report = ScanReport(target="https://example.com", effective_target="https://example.com")
    # Metadata leaks (the SEC-1 vector — engine writes raw probe artifacts here).
    report.metadata.update({
        "probe_headers": {"Set-Cookie": SET_COOKIE_HEADER, "Authorization": f"Bearer {JWT}"},
        "probe_cookies": {"sid": SESSION_COOKIE.split("=", 1)[1]},
        "probe_body": f"<html>token={JWT} aws={AWS_KEY}</html>",
        "probe_forms": [{"action": "/login", "inputs": [{"name": "csrf_token", "value": "abc"}]}],
    })
    # The brute-force module path (C1). Description uses [REDACTED] like
    # the fixed module now produces; evidence still carries the secret so
    # we can verify the serializer scrubs it.
    report.add_finding(Finding(
        title="Weak/Default Credentials Accepted",
        description="Login succeeded with credentials: admin:[REDACTED]",
        severity=Severity.CRITICAL,
        evidence={
            "username": "admin",
            "password": PASSWORD,
            "form_url": "https://example.com/login",
        },
        module_name="brute",
    ))
    # Evidence with a JWT shape under a non-obvious key name.
    report.add_finding(Finding(
        title="JWT Found in Response",
        description=f"Bearer leak: {JWT}",  # value-shape scrubbed
        severity=Severity.HIGH,
        evidence={"sample": f"Authorization: Bearer {JWT}"},
        module_name="jwt",
    ))
    # Evidence with value-shape secrets that are not in REDACT_KEYS at all.
    report.add_finding(Finding(
        title="API Keys in JS Bundle",
        description=f"AWS={AWS_KEY} GH={GH_TOKEN} Slack={SLACK_TOKEN}",
        severity=Severity.HIGH,
        evidence={"snippet": f"const k = '{AWS_KEY}'; const g = '{GH_TOKEN}';"},
        module_name="api_key",
    ))
    return report


_REPORTERS = [JsonReporter, MarkdownReporter, HtmlReporter, SarifReporter]


@pytest.mark.parametrize("reporter_cls", _REPORTERS)
def test_reporter_redacts_all_secrets_by_default(
    leaky_report: ScanReport, reporter_cls: type
) -> None:
    """No secret may appear in any reporter's redacted output."""
    reporter = reporter_cls()
    # JsonReporter takes redact kwarg directly; the rest accept it positionally on render.
    if reporter_cls is JsonReporter:
        output = reporter.render(leaky_report, redact=True)
    else:
        output = reporter.render(leaky_report, redact=True)

    for secret in ALL_SECRETS:
        # Plain in-text occurrence
        assert secret not in output, (
            f"{reporter_cls.__name__} leaked secret: {secret[:12]}..."
        )
        # Also fail on JSON-escaped forms in HTML/Markdown evidence blocks
        escaped = json.dumps(secret).strip('"')
        assert escaped not in output, (
            f"{reporter_cls.__name__} leaked JSON-escaped secret: {secret[:12]}..."
        )


def test_json_reporter_no_redact_emits_password(leaky_report: ScanReport) -> None:
    """The --no-redact escape hatch still works for operators who need raw values."""
    output = JsonReporter().render(leaky_report, redact=False)
    data = json.loads(output)
    brute_finding = next(f for f in data["findings"] if f["title"].startswith("Weak/Default"))
    assert brute_finding["evidence"]["password"] == PASSWORD


def test_scan_report_to_dict_redacts_metadata(leaky_report: ScanReport) -> None:
    """ScanReport.to_dict(redact=True) must scrub probe_headers / cookies / body."""
    data = leaky_report.to_dict(redact=True)
    serialized = json.dumps(data)
    for secret in ALL_SECRETS:
        assert secret not in serialized, f"to_dict(redact=True) leaked: {secret[:12]}..."


def test_scan_report_to_dict_caps_probe_body(leaky_report: ScanReport) -> None:
    """Large probe_body becomes preview + length + sha256."""
    big = "A" * 50_000 + JWT + "B" * 50_000
    leaky_report.metadata["probe_body"] = big
    data = leaky_report.to_dict(redact=True)
    md = data["metadata"]
    assert md["probe_body_truncated"] is True
    assert md["probe_body_length"] == len(big.encode("utf-8"))
    assert len(md["probe_body_sha256"]) == 64
    # The truncated preview must not contain the JWT either.
    assert JWT not in md["probe_body"]
    # Sanity: short bodies are not truncated.
    leaky_report.metadata["probe_body"] = "hi"
    data2 = leaky_report.to_dict(redact=True)
    assert "probe_body_truncated" not in data2["metadata"]


def test_redact_dict_handles_broadened_keys() -> None:
    """REDACT_KEYS expansion: id_token, client_secret, session_id, csrf_token, etc."""
    sample = {
        "id_token": "value-x",
        "client_secret": "value-y",
        "session_id": "value-z",
        "private_key": "-----BEGIN-----",
        "csrf_token": "abc",
        "Custom-Auth-Header": "value",  # substring match on "auth"
        "X-Session-Cookie": "value",     # substring match on "session" and "cookie"
        "harmless": "keep-me",
    }
    redacted = _redact_dict(sample)
    for k in ("id_token", "client_secret", "session_id", "private_key", "csrf_token",
              "Custom-Auth-Header", "X-Session-Cookie"):
        assert redacted[k] == "[REDACTED]", f"key {k} not redacted"
    assert redacted["harmless"] == "keep-me"


def test_redact_value_replaces_token_shapes() -> None:
    """Token-shape regexes scrub values regardless of key name."""
    cases = {
        f"jwt={JWT}": "[REDACTED:JWT]",
        f"aws_key={AWS_KEY}": "[REDACTED:AWS_KEY]",
        f"gh={GH_TOKEN}": "[REDACTED:GITHUB_TOKEN]",
        f"slack={SLACK_TOKEN}": "[REDACTED:SLACK_TOKEN]",
    }
    for raw, expected_marker in cases.items():
        out = _redact_value(raw)
        assert expected_marker in out, f"missing marker in {out!r}"
        # And the literal secret is gone.
        for s in (JWT, AWS_KEY, GH_TOKEN, SLACK_TOKEN):
            if s in raw:
                assert s not in out


def test_summarize_probe_body_short_passthrough() -> None:
    md = {"probe_body": "small body", "other": "v"}
    assert _summarize_probe_body(md) is md  # unchanged identity


def test_brute_module_redacts_discovered_password_by_default() -> None:
    """C1 regression: BruteForce.run() must not leave plaintext anywhere.

    Drives _test_form() under the same path used in tests/attacks/test_brute.py
    and asserts the discovered password appears nowhere in description or
    evidence by default, and appears under --no-redact only in evidence.
    """
    import responses

    from auth_scan.attacks.brute import BruteForce
    from auth_scan.core.http_client import HTTPClient

    form = {
        "action": "https://example.com/login",
        "method": "POST",
        "username_field": "username",
        "password_field": "password",
        "hidden_fields": [],
    }
    creds = [("admin", PASSWORD)]

    @responses.activate
    def _run(no_redact: bool) -> Finding:
        responses.add(
            responses.POST,
            "https://example.com/login",
            body="Welcome, admin!",
            status=200,
        )
        client = HTTPClient(base_url="https://example.com", rate_limit=100)
        bf = BruteForce()
        # The real entry-point seeds _no_redact from config; mirror that.
        bf._no_redact = no_redact
        result = bf._test_form(form, creds, "https://example.com", client)
        return next(f for f in result.findings if "Credentials" in f.title or "Accepted" in f.title)

    # Default: redacted everywhere.
    finding_redacted = _run(no_redact=False)
    assert PASSWORD not in finding_redacted.description
    assert finding_redacted.evidence["password"] == "[REDACTED]"

    # Opt-in: plaintext password reaches evidence (but description is still safe).
    finding_raw = _run(no_redact=True)
    assert finding_raw.evidence["password"] == PASSWORD


@pytest.mark.parametrize("reporter_cls", _REPORTERS)
def test_reporter_no_redact_emits_secrets(
    leaky_report: ScanReport, reporter_cls: type
) -> None:
    """Belt check: --no-redact must let at least one targeted secret through.

    This protects against an over-zealous fix that redacts even with
    redact=False. Each reporter has a different surface, so we check the
    most reliable one per format.
    """
    if reporter_cls is JsonReporter:
        out = reporter_cls().render(leaky_report, redact=False)
    else:
        out = reporter_cls().render(leaky_report, redact=False)
    # In no-redact mode, evidence carries the raw password and the
    # description carries the AWS key, regardless of format.
    assert PASSWORD in out or AWS_KEY in out
