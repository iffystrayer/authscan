"""Base classes and data models for attack modules."""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

# Multiplier applied to the severity-numeric sum when computing the risk
# score (see ``ScanReport.risk_score``). Set so that ~five CRITICAL
# findings (severity.numeric == 9.5 each) saturate the 100-point cap. L1.
RISK_SCORE_WEIGHT = 2.5


class Severity(str, Enum):
    """Finding severity levels with numeric ranges for CVSS mapping."""

    CRITICAL = "critical"  # 9.0 - 10.0
    HIGH = "high"  # 7.0 - 8.9
    MEDIUM = "medium"  # 4.0 - 6.9
    LOW = "low"  # 0.1 - 3.9
    INFO = "info"  # 0.0

    @property
    def numeric(self) -> float:
        """Return the midpoint of the severity range."""
        mapping = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 2.0,
            Severity.INFO: 0.0,
        }
        return mapping[self]

    @property
    def color(self) -> str:
        """Return Rich color name."""
        mapping = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }
        return mapping[self]

    @property
    def icon(self) -> str:
        """Return emoji icon."""
        mapping = {
            Severity.CRITICAL: "💀",
            Severity.HIGH: "🔴",
            Severity.MEDIUM: "🟠",
            Severity.LOW: "🟡",
            Severity.INFO: "ℹ️",
        }
        return mapping[self]

    @property
    def exit_code(self) -> int:
        """Return the exit code contribution for this severity."""
        mapping = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return mapping[self]


@dataclass
class Finding:
    """A single security finding produced by a module."""

    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cwe_id: str = ""
    cvss_score: float | None = None
    module_name: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0
    chain_parent: str | None = None
    chain_children: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    request_id: str | None = None
    # When an identical finding is added again, ``ScanReport.add_finding``
    # merges it into the existing entry and bumps this counter rather than
    # appending a duplicate. M8.
    occurrence_count: int = 1

    def dedup_key(self) -> tuple[str, str, str, str]:
        """Return a stable tuple identifying "this finding" for dedup.

        Uses module + title + the evidence's endpoint/URL hint if present.
        Different modules / titles / endpoints intentionally do not collide.
        """
        endpoint = ""
        if isinstance(self.evidence, dict):
            for k in ("endpoint", "url", "form_url", "authorization_url", "path"):
                v = self.evidence.get(k)
                if isinstance(v, str) and v:
                    endpoint = v
                    break
        return (self.module_name or "", self.title or "", endpoint, self.cwe_id or "")

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        """Serialize to dict, optionally redacting sensitive values.

        When ``redact`` is True we also scrub token-shaped values out of the
        free-text ``description`` and ``remediation`` fields, since modules
        commonly interpolate found secrets into those strings.
        """
        evidence: Any = self.evidence
        description = self.description
        remediation = self.remediation
        if redact:
            evidence = _redact_dict(evidence.copy())
            description = _redact_value(description)
            remediation = _redact_value(remediation)

        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "module_name": self.module_name,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence,
            "chain_parent": self.chain_parent,
            "chain_children": self.chain_children,
            "tags": self.tags,
            "request_id": self.request_id,
            "occurrence_count": self.occurrence_count,
        }

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.title}"


@dataclass
class ModuleResult:
    """Return value from every attack module's run() method."""

    findings: list[Finding] = field(default_factory=list)
    state_update: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        """True if any finding has CRITICAL severity."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def has_errors(self) -> bool:
        """True if the module encountered errors."""
        return len(self.errors) > 0

    def __bool__(self) -> bool:
        return len(self.findings) > 0 or self.has_errors


@dataclass
class ScanReport:
    """The accumulated state of a scan — passed between phases/modules."""

    scan_id: str = field(default_factory=lambda: str(uuid4()))
    target: str = ""
    effective_target: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    status: str = "initialized"

    # Probe results and discovered artifacts
    metadata: dict[str, Any] = field(default_factory=dict)

    # Findings (the primary output)
    findings: list[Finding] = field(default_factory=list)

    # Session state
    session_state: dict[str, Any] = field(default_factory=dict)

    # Config snapshot
    config_snapshot: dict[str, Any] = field(default_factory=dict)

    # Agentic decision trail
    decision_trail: list[dict[str, Any]] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding, ensuring timestamp is set.

        If an identical finding (same module + title + endpoint + CWE) is
        already present, increment its ``occurrence_count`` rather than
        appending a duplicate. This stops module rerun loops (agentic
        engine, chain synthesis) from inflating the finding count and
        skewing the risk score. M8.
        """
        if finding.timestamp is None:
            finding.timestamp = datetime.now(timezone.utc)
        key = finding.dedup_key()
        for existing in self.findings:
            if existing.dedup_key() == key:
                existing.occurrence_count += 1
                return
        self.findings.append(finding)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a given severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_highest_severity(self) -> Severity:
        """Return the highest severity among all findings."""
        if not self.findings:
            return Severity.INFO
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return Severity.INFO

    @property
    def risk_score(self) -> float:
        """Overall risk score: monotonically-nondecreasing weighted sum,
        clamped to [0, 100].

        Pre-PR-8 the formula divided the severity sum by ``min(n, 20)`` —
        so adding a 21st *below-average* finding could *decrease* the
        score even though the target had more problems than before. The
        replacement is a saturating sum: each finding contributes its
        severity weight (CRITICAL=9.5, HIGH=8.0, MEDIUM=5.5, LOW=2.0,
        INFO=0.0) scaled by ``RISK_SCORE_WEIGHT``, with the total clamped
        to 100. Saturation point is ~five CRITICAL findings, matching the
        intuition that one such defect already warrants attention. L1.
        """
        if not self.findings:
            return 0.0
        total = sum(f.severity.numeric for f in self.findings) * RISK_SCORE_WEIGHT
        return round(min(total, 100.0), 1)

    @property
    def exit_code(self) -> int:
        """Determine appropriate exit code based on highest severity."""
        highest = self.get_highest_severity()
        return highest.exit_code

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        """Serialize the full report to a dict.

        When redact=True, metadata is recursively scrubbed and a large
        ``probe_body`` is replaced with a bounded preview plus length/hash
        so the raw page never reaches downstream artifacts.
        """
        metadata = _summarize_probe_body(self.metadata) if redact else self.metadata
        if redact:
            metadata = _redact_dict(metadata)
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "effective_target": self.effective_target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "risk_score": self.risk_score,
            "findings": [f.to_dict(redact=redact) for f in self.findings],
            "metadata": metadata,
            "decision_trail": self.decision_trail,
        }

    def to_json(self, redact: bool = True, indent: int = 2) -> str:
        """Serialize report to JSON string."""
        import json

        return json.dumps(self.to_dict(redact=redact), indent=indent)


class BaseAttackModule(ABC):
    """Contract for all attack modules (built-in and plugins)."""

    name: str = "base"
    description: str = "Base attack module"
    version: str = "1.0.0"
    priority: int = 50  # Lower runs first

    @abstractmethod
    def run(
        self,
        target: str,
        http_client: Any,  # HTTPClient (avoid circular import)
        report: ScanReport,
        config: Any,  # ScanConfig
    ) -> ModuleResult:
        """Execute the attack module.

        Args:
            target: The target URL.
            http_client: The HTTP adapter for making requests.
            report: The accumulated ScanReport from all prior phases/modules.
            config: The merged scan configuration.

        Returns:
            ModuleResult with findings, state updates, and metadata.
        """
        ...

    def prerequisites(self, report: ScanReport) -> list[str]:
        """Return prerequisite module names. Default: none."""
        return []


# Exact-match keys (lower-cased) that are always redacted regardless of value.
REDACT_KEYS = {
    "authorization",
    "set-cookie",
    "cookie",
    "x-api-key",
    "token",
    "password",
    "secret",
    "api_key",
    "jwt",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "client_id",
    "session_id",
    "sessionid",
    "private_key",
    "csrf_token",
    "xsrf_token",
    "x-csrf-token",
    "x-xsrf-token",
    "api-key",
    "apikey",
    "bearer",
    "auth",
    "auth_token",
}

# Substrings (lower-cased) — any key containing one of these is redacted.
REDACT_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "auth",
    "session",
    "cookie",
    "private",
    "credential",
    "creds",
    "passphrase",
    "key_id",
    "client_secret",
)

# Token-shaped value detectors. Any value matching one is replaced with a
# typed redaction marker so we leak only the shape, never the bytes.
#
# Patterns are split-concatenated where they would otherwise look like real
# credentials to GitHub Push Protection / secret scanners. (e.g. "AKIA",
# "ghp_" etc. — see tests/test_redaction.py for the same trick.)
_TOKEN_SHAPE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("[REDACTED:JWT]", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]*")),
    ("[REDACTED:AWS_KEY]", re.compile(r"\b(?:" + "AKIA" + "|" + "ASIA" + r")[0-9A-Z]{16}\b")),
    ("[REDACTED:GITHUB_TOKEN]", re.compile(r"\b" + "gh" + r"[pousr]_[A-Za-z0-9]{20,}\b")),
    ("[REDACTED:SLACK_TOKEN]", re.compile(r"\b" + "xox" + r"[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("[REDACTED:GOOGLE_API_KEY]", re.compile(r"\b" + "AIza" + r"[0-9A-Za-z_-]{35}\b")),
    ("[REDACTED:BEARER]", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    # New in M6:
    ("[REDACTED:STRIPE_KEY]", re.compile(r"\b" + "sk_" + r"(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("[REDACTED:STRIPE_PUBLIC]", re.compile(r"\b" + "pk_" + r"(?:live|test)_[A-Za-z0-9]{20,}\b")),
    # Anthropic / OpenAI API key prefixes. Anthropic must match first
    # because "sk-ant-..." also satisfies the looser "sk-..." OpenAI shape.
    ("[REDACTED:ANTHROPIC_KEY]", re.compile(r"\b" + "sk-ant-" + r"[A-Za-z0-9_-]{20,}\b")),
    ("[REDACTED:OPENAI_KEY]", re.compile(r"\b" + "sk-" + r"(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    # Azure Storage account keys (44-char base64 ending in =)
    (
        "[REDACTED:AZURE_STORAGE_KEY]",
        re.compile(r"\b[A-Za-z0-9+/]{86}==\b"),
    ),
    # Generic "AccountKey=...;" in connection strings
    (
        "[REDACTED:CONNECTION_KEY]",
        re.compile(r"(?i)(AccountKey|SharedAccessKey|SharedSecret)=[A-Za-z0-9+/=]{16,}"),
    ),
    # PEM-encoded private keys leak when serialised verbatim
    (
        "[REDACTED:PRIVATE_KEY]",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----"
        ),
    ),
    # Basic-auth in URLs (https://user:pass@host)
    (
        r"\g<1>[REDACTED:BASIC_AUTH]@",
        re.compile(r"(https?://)[^/:\s@]+:[^/@\s]+@"),
    ),
)

# Cap probe_body size in serialized reports. Anything larger becomes
# preview + length + sha256.
PROBE_BODY_PREVIEW_BYTES = 4096


def _should_redact_key(key: str) -> bool:
    """Return True if a key name implies sensitive content."""
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    if lowered in REDACT_KEYS:
        return True
    return any(sub in lowered for sub in REDACT_KEY_SUBSTRINGS)


def _redact_value(value: Any) -> Any:
    """Apply token-shape redaction to string values, leave others untouched."""
    if not isinstance(value, str):
        return value
    redacted = value
    for marker, pattern in _TOKEN_SHAPE_PATTERNS:
        redacted = pattern.sub(marker, redacted)
    return redacted


def _redact_dict(d: Any) -> Any:
    """Recursively redact sensitive keys and token-shaped values.

    Accepts arbitrary nested structures (dict / list / scalar). Returns a
    new structure; the input is not mutated.
    """
    if isinstance(d, dict):
        result: dict[str, Any] = {}
        for key, value in d.items():
            if _should_redact_key(str(key)):
                result[key] = "[REDACTED]"
            elif isinstance(value, dict):
                result[key] = _redact_dict(value)
            elif isinstance(value, list):
                result[key] = [_redact_dict(v) for v in value]
            else:
                result[key] = _redact_value(value)
        return result
    if isinstance(d, list):
        return [_redact_dict(v) for v in d]
    return _redact_value(d)


def _summarize_probe_body(metadata: dict[str, Any]) -> dict[str, Any]:
    """Cap probe_body to a bounded preview + sha256 + length.

    Returns a shallow copy of metadata with probe_body replaced when over
    the cap. Leaves all other keys untouched. The cap protects both memory
    and downstream artifacts from full-page captures.
    """
    if not isinstance(metadata, dict):
        return metadata
    body = metadata.get("probe_body")
    if not isinstance(body, str):
        return metadata
    encoded = body.encode("utf-8", errors="ignore")
    if len(encoded) <= PROBE_BODY_PREVIEW_BYTES:
        return metadata
    sha256 = hashlib.sha256(encoded).hexdigest()
    preview = encoded[:PROBE_BODY_PREVIEW_BYTES].decode("utf-8", errors="replace")
    summarized = dict(metadata)
    summarized["probe_body"] = preview
    summarized["probe_body_truncated"] = True
    summarized["probe_body_length"] = len(encoded)
    summarized["probe_body_sha256"] = sha256
    return summarized
