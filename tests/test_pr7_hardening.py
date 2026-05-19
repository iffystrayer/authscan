"""PR-7 hardening: external default-creds, broader redaction, bounded
HTTP-history body capture, and finding dedup.
"""

from __future__ import annotations

import responses

from auth_scan.attacks.base import (
    Finding,
    ScanReport,
    Severity,
    _redact_dict,
    _redact_value,
)
from auth_scan.attacks.brute import (
    DEFAULT_CREDENTIALS,
    _parse_creds_text,
    load_default_credentials,
)
from auth_scan.core.http_client import BODY_PREVIEW_BYTES, HTTPClient

# ---- M3: externalised DEFAULT_CREDENTIALS ----------------------------------


class TestExternalDefaultCredentials:
    def test_bundled_list_is_loaded(self) -> None:
        # Sanity: the module-level constant is non-empty and looks like
        # what the bundled file shipped.
        assert len(DEFAULT_CREDENTIALS) >= 30
        assert ("admin", "admin") in DEFAULT_CREDENTIALS

    def test_parser_strips_comments_and_blank_lines(self) -> None:
        text = "# header\n\nadmin:admin\n# inline comment\nroot:toor\n\n"
        assert _parse_creds_text(text) == [("admin", "admin"), ("root", "toor")]

    def test_parser_handles_empty_password(self) -> None:
        assert _parse_creds_text("admin:\n") == [("admin", "")]

    def test_parser_skips_malformed_lines(self) -> None:
        assert _parse_creds_text("admin\nroot:toor\n") == [("root", "toor")]

    def test_override_path_is_honored(self, tmp_path) -> None:
        wordlist = tmp_path / "creds.txt"
        wordlist.write_text("alice:wonderland\nbob:builder\n")
        creds = load_default_credentials(str(wordlist))
        assert creds == [("alice", "wonderland"), ("bob", "builder")]

    def test_missing_override_falls_back_to_bundled(self, tmp_path) -> None:
        # Path that doesn't exist on disk
        creds = load_default_credentials(str(tmp_path / "nope.txt"))
        assert creds == DEFAULT_CREDENTIALS


# ---- M6: broadened redaction matching --------------------------------------


class TestRedactionBreadth:
    def test_new_key_substrings(self) -> None:
        d = {
            "PASSPHRASE": "open-sesame",
            "X-Creds-Header": "secret",
            "key_id": "AKIA00000000",
            "client_secret": "v3rys3cret",
            "passwd": "p4ssw0rd",
            "ordinary": "fine",
        }
        out = _redact_dict(d)
        for k in ("PASSPHRASE", "X-Creds-Header", "key_id", "client_secret", "passwd"):
            assert out[k] == "[REDACTED]", k
        assert out["ordinary"] == "fine"

    def test_stripe_keys(self) -> None:
        sk = "sk_" + "test_" + "abcdefghijklmnopqrstuvwxyz0123456789"
        pk = "pk_" + "live_" + "abcdefghijklmnopqrstuvwxyz0123456789"
        for sample in (sk, pk):
            out = _redact_value(f"key={sample}")
            assert sample not in out
            assert "[REDACTED:STRIPE" in out

    def test_anthropic_and_openai_keys(self) -> None:
        ant = "sk-ant-" + "abcdef0123456789ABCDEF"
        oai = "sk-" + "proj-abc123abc123abc123"
        for sample, marker in ((ant, "ANTHROPIC"), (oai, "OPENAI")):
            out = _redact_value(f"x={sample}")
            assert sample not in out
            assert marker in out

    def test_basic_auth_in_url(self) -> None:
        url = "https://alice:hunter2@example.com/path"
        out = _redact_value(url)
        assert "alice:hunter2" not in out
        assert "[REDACTED:BASIC_AUTH]" in out
        assert "example.com/path" in out  # host preserved

    def test_pem_private_key(self) -> None:
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAabc\nZZZZ\n-----END RSA PRIVATE KEY-----"
        out = _redact_value("note=" + pem)
        assert "MIIEow" not in out
        assert "[REDACTED:PRIVATE_KEY]" in out


# ---- M7: bounded body capture in HTTP request history ----------------------


class TestRequestHistoryBounding:
    @responses.activate
    def test_long_body_is_truncated_and_fingerprinted(self) -> None:
        big = "y" * (BODY_PREVIEW_BYTES + 5000)
        responses.add(responses.GET, "https://example.com/big", body=big, status=200)
        client = HTTPClient(base_url="https://example.com", rate_limit=100.0)
        client.get("/big")
        rec = client.request_history[-1]
        assert rec.response_body_length == len(big.encode("utf-8"))
        assert len(rec.response_body_preview.encode("utf-8")) <= BODY_PREVIEW_BYTES
        assert len(rec.response_body_sha256) == 64

    @responses.activate
    def test_response_headers_are_redacted_in_history(self) -> None:
        responses.add(
            responses.GET,
            "https://example.com/x",
            body="ok",
            status=200,
            headers={"Authorization": "Bearer top-secret-token-value-12345", "Set-Cookie": "sid=abc"},
        )
        client = HTTPClient(base_url="https://example.com", rate_limit=100.0)
        client.get("/x")
        rec = client.request_history[-1]
        # Header keys preserved, values redacted.
        assert rec.response_headers.get("Authorization") == "[REDACTED]"
        assert rec.response_headers.get("Set-Cookie") == "[REDACTED]"

    @responses.activate
    def test_body_preview_redacts_token_shapes(self) -> None:
        body = "leaked AWS key: " + "AKIA" + "IOSFODNN7EXAMPLE"
        responses.add(responses.GET, "https://example.com/leak", body=body, status=200)
        client = HTTPClient(base_url="https://example.com", rate_limit=100.0)
        client.get("/leak")
        rec = client.request_history[-1]
        assert "AKIAIOSFODNN7EXAMPLE" not in rec.response_body_preview
        assert "[REDACTED:AWS_KEY]" in rec.response_body_preview


# ---- M8: finding dedup -----------------------------------------------------


class TestFindingDedup:
    def _f(self, title: str = "X", module: str = "m", evidence: dict | None = None) -> Finding:
        return Finding(
            title=title,
            severity=Severity.MEDIUM,
            module_name=module,
            evidence=evidence or {},
        )

    def test_identical_findings_are_merged(self) -> None:
        r = ScanReport(target="https://example.com")
        f1 = self._f(evidence={"endpoint": "/api"})
        f2 = self._f(evidence={"endpoint": "/api"})
        r.add_finding(f1)
        r.add_finding(f2)
        assert len(r.findings) == 1
        assert r.findings[0].occurrence_count == 2

    def test_different_endpoints_are_distinct(self) -> None:
        r = ScanReport(target="https://example.com")
        r.add_finding(self._f(evidence={"endpoint": "/api/a"}))
        r.add_finding(self._f(evidence={"endpoint": "/api/b"}))
        assert len(r.findings) == 2
        assert all(f.occurrence_count == 1 for f in r.findings)

    def test_different_titles_are_distinct(self) -> None:
        r = ScanReport(target="https://example.com")
        r.add_finding(self._f(title="One"))
        r.add_finding(self._f(title="Two"))
        assert len(r.findings) == 2

    def test_dedup_key_uses_url_when_endpoint_absent(self) -> None:
        r = ScanReport(target="https://example.com")
        r.add_finding(self._f(evidence={"url": "https://example.com/x"}))
        r.add_finding(self._f(evidence={"url": "https://example.com/x"}))
        assert len(r.findings) == 1
        assert r.findings[0].occurrence_count == 2

    def test_dedup_includes_cwe(self) -> None:
        """Two findings with the same title but different CWE IDs are
        different defects and must not collapse."""
        r = ScanReport(target="https://example.com")
        r.add_finding(Finding(title="Bad", severity=Severity.HIGH, module_name="m", cwe_id="CWE-79"))
        r.add_finding(Finding(title="Bad", severity=Severity.HIGH, module_name="m", cwe_id="CWE-89"))
        assert len(r.findings) == 2

    def test_occurrence_count_round_trips_to_dict(self) -> None:
        f = self._f()
        f.occurrence_count = 3
        d = f.to_dict()
        assert d["occurrence_count"] == 3
