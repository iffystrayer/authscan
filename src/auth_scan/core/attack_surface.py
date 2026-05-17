"""Attack Surface Model — live graph of discovered auth surface."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AuthEndpoint:
    """A discovered endpoint with its auth properties."""

    url: str
    method: str = "GET"
    auth_mechanism: str | None = None  # form, jwt, oauth, apikey, basic, none
    form_fields: list[str] = field(default_factory=list)
    status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    linked_to: list[str] = field(default_factory=list)  # connected endpoint URLs


@dataclass
class ModelToken:
    """A token/credential discovered during scanning."""

    token_type: str  # jwt, bearer, apikey, session_cookie, oauth_token
    location: str  # header:Authorization, cookie:auth_token, body, url_param
    algorithm: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)
    is_cracked: bool = False
    cracked_secret: str | None = None
    weaknesses: list[str] = field(default_factory=list)
    raw_preview: str = ""


@dataclass
class ModelSession:
    """A session discovered and potentially analyzed."""

    cookie_name: str
    flags: dict[str, bool | str] = field(default_factory=dict)
    entropy_score: float = 0.0
    fixation_vulnerable: bool | None = None
    invalidation_works: bool | None = None


@dataclass
class AttackSurfaceModel:
    """Live graph of everything discovered about the target's auth surface.

    Maintains:
    - Discovered endpoints with their auth mechanisms
    - Tokens/credentials found
    - Sessions/cookies analyzed
    - Confidence score for scan completeness
    """

    target: str = ""
    endpoints: dict[str, AuthEndpoint] = field(default_factory=dict)
    tokens: list[ModelToken] = field(default_factory=list)
    sessions: list[ModelSession] = field(default_factory=list)
    auth_mechanisms: set[str] = field(default_factory=set)
    confidence: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    _modules_run: set[str] = field(default_factory=set)
    _modules_failed: set[str] = field(default_factory=set)
    _mechanisms_tested: set[str] = field(default_factory=set)

    def add_endpoint(self, ep: AuthEndpoint) -> None:
        """Add or update an endpoint in the model."""
        existing = self.endpoints.get(ep.url)
        if existing:
            # Merge new info into existing
            if ep.auth_mechanism and not existing.auth_mechanism:
                existing.auth_mechanism = ep.auth_mechanism
            if ep.form_fields:
                existing.form_fields = list(set(existing.form_fields + ep.form_fields))
            if ep.linked_to:
                existing.linked_to = list(set(existing.linked_to + ep.linked_to))
            if ep.status:
                existing.status = ep.status
            if ep.response_headers:
                existing.response_headers.update(ep.response_headers)
            if existing.auth_mechanism:
                self.auth_mechanisms.add(existing.auth_mechanism)
        else:
            self.endpoints[ep.url] = ep
            if ep.auth_mechanism:
                self.auth_mechanisms.add(ep.auth_mechanism)

    def add_token(self, token: ModelToken) -> None:
        """Add a token, deduplicating by type+location."""
        existing = [t for t in self.tokens if t.token_type == token.token_type and t.location == token.location]
        if not existing:
            self.tokens.append(token)
        else:
            # Merge weaknesses
            existing[0].weaknesses = list(set(existing[0].weaknesses + token.weaknesses))
            if token.is_cracked:
                existing[0].is_cracked = True
                existing[0].cracked_secret = token.cracked_secret

    def add_session(self, session: ModelSession) -> None:
        """Add a session, deduplicating by cookie name."""
        existing = [s for s in self.sessions if s.cookie_name == session.cookie_name]
        if not existing:
            self.sessions.append(session)
        else:
            if session.fixation_vulnerable is not None:
                existing[0].fixation_vulnerable = session.fixation_vulnerable
            if session.invalidation_works is not None:
                existing[0].invalidation_works = session.invalidation_works
            existing[0].entropy_score = max(existing[0].entropy_score, session.entropy_score)

    def mark_module_run(self, name: str) -> None:
        self._modules_run.add(name)

    def mark_module_failed(self, name: str) -> None:
        self._modules_failed.add(name)

    def mark_mechanism_tested(self, mech: str) -> None:
        self._mechanisms_tested.add(mech)

    def get_endpoints_by_mechanism(self, mechanism: str) -> list[AuthEndpoint]:
        return [ep for ep in self.endpoints.values() if ep.auth_mechanism == mechanism]

    def get_unprotected_endpoints(self) -> list[AuthEndpoint]:
        return [ep for ep in self.endpoints.values() if ep.auth_mechanism == "none"]

    def get_high_value_targets(self) -> list[str]:
        """Return priority-ranked list of next URLs to investigate."""
        scored: list[tuple[float, str]] = []

        for url, ep in self.endpoints.items():
            score = 0.0
            # Prioritize auth-related endpoints
            if ep.auth_mechanism and ep.auth_mechanism != "none":
                score += 5.0
            # Prefer endpoints with forms
            if ep.form_fields:
                score += 3.0
            # Prefer 200/302 over 403/404
            if ep.status in (200, 302, 307):
                score += 2.0
            elif ep.status == 401:
                score += 1.5
            # Newly discovered (less tested)
            if url not in self._modules_run:
                score += 1.0
            scored.append((score, url))

        scored.sort(key=lambda x: -x[0])
        return [url for _, url in scored]

    def estimate_confidence(self) -> float:
        """Heuristic confidence: how well do we understand this surface?"""
        conf = 0.0

        # Base: probe always runs first
        if "probe" in self._modules_run:
            conf += 0.15

        # Each auth mechanism discovered and tested
        for mech in self._mechanisms_tested:
            conf += 0.10

        # Tokens analyzed
        conf += min(len(self.tokens) * 0.10, 0.20)

        # Sessions analyzed
        conf += min(len(self.sessions) * 0.10, 0.15)

        # No unknown endpoints
        unknown = sum(1 for ep in self.endpoints.values() if ep.auth_mechanism is None)
        if unknown == 0 and len(self.endpoints) > 0:
            conf += 0.15

        # Penalty for failures
        conf -= len(self._modules_failed) * 0.05

        # Bounds
        self.confidence = max(0.0, min(1.0, conf))
        return self.confidence

    def summary(self) -> dict[str, Any]:
        """Serialized overview of the model state."""
        return {
            "target": self.target,
            "endpoints_count": len(self.endpoints),
            "tokens_count": len(self.tokens),
            "sessions_count": len(self.sessions),
            "auth_mechanisms": sorted(self.auth_mechanisms),
            "confidence": self.confidence,
            "modules_run": sorted(self._modules_run),
            "modules_failed": sorted(self._modules_failed),
            "mechanisms_tested": sorted(self._mechanisms_tested),
            "high_value_targets": self.get_high_value_targets()[:10],
        }
