"""OODA (Observe-Orient-Decide-Act) decision engine for agentic scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from auth_scan.attacks.base import Finding, ModuleResult, ScanReport, Severity
from auth_scan.core.attack_surface import (
    AttackSurfaceModel,
    AuthEndpoint,
    ModelSession,
    ModelToken,
)
from auth_scan.core.config import ScanConfig


@dataclass
class DecisionRecord:
    """A single decision in the agentic trail."""

    cycle: int
    phase: str  # observe, orient, decide, act
    action: str
    reasoning: str
    confidence_change: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class OODAEngine:
    """Rule-based OODA loop for adaptive scanning.

    No AI/ML — pure heuristics and state-machine rules.
    """

    def __init__(
        self,
        model: AttackSurfaceModel,
        config: ScanConfig,
        http_client: Any,
    ) -> None:
        self.model = model
        self.config = config
        self.http = http_client
        self.decision_trail: list[DecisionRecord] = []
        self.cycle = 0
        self._modules_run: set[str] = set()
        self._credentials_found: list[dict[str, str]] = []

    # ── Observe ──────────────────────────────────────────────────

    def observe(self, result: ModuleResult, report: ScanReport) -> dict[str, Any]:
        """Extract structured data from module output into the model.

        Scans findings for:
        - Endpoints discovered (path discovery, probe)
        - Tokens found (JWT, API keys, bearer)
        - Session info (cookie flags, fixation, invalidation)
        - Auth mechanisms (form, oauth, jwt, apikey)
        - Valid credentials (brute force success)

        Returns a diff of changes.
        """
        changes: dict[str, Any] = {
            "new_endpoints": 0,
            "new_tokens": 0,
            "new_sessions": 0,
            "new_mechanisms": [],
            "credentials_found": 0,
        }

        prev_endpoints = len(self.model.endpoints)
        prev_tokens = len(self.model.tokens)
        prev_sessions = len(self.model.sessions)

        for finding in result.findings:
            tags = finding.tags or []

            # Endpoint discovery
            if "discovery" in tags or "paths" in tags or "forms" in tags:
                evidence = finding.evidence or {}
                url = evidence.get("path", evidence.get("url", ""))
                if url and url not in self.model.endpoints:
                    self.model.add_endpoint(
                        AuthEndpoint(
                            url=url,
                            method=evidence.get("method", "GET"),
                            status=evidence.get("status", 0),
                            auth_mechanism="none",
                        )
                    )

            # Login form found
            if "forms" in tags or "login" in finding.title.lower():
                evidence = finding.evidence or {}
                url = evidence.get("form_url", evidence.get("path", ""))
                if url and url not in self.model.endpoints:
                    fields = evidence.get("form_fields", evidence.get("input_names", []))
                    self.model.add_endpoint(
                        AuthEndpoint(
                            url=url,
                            method="POST",
                            auth_mechanism="form",
                            form_fields=list(fields) if fields else ["username", "password"],
                            status=200,
                        )
                    )
                    self.model.auth_mechanisms.add("form")

            # JWT tokens
            if "jwt" in tags:
                evidence = finding.evidence or {}
                algorithm = evidence.get("algorithm", "")
                location = evidence.get("location", "unknown")
                token = ModelToken(
                    token_type="jwt",
                    location=location,
                    algorithm=algorithm,
                    is_cracked="cracking" in tags or "cracked" in finding.title.lower(),
                    cracked_secret=evidence.get("secret") if "cracking" in tags else None,
                )
                if "expiry" in tags:
                    token.weaknesses.append("expiry_issue")
                if "sensitive" in tags or "sensitive-data" in tags:
                    token.weaknesses.append("sensitive_data")
                if "alg:none" in finding.title.lower() or "none" in tags:
                    token.weaknesses.append("alg_none_accepted")
                self.model.add_token(token)

            # API keys
            if "api-key" in tags or "api_key" in tags:
                evidence = finding.evidence or {}
                self.model.add_token(
                    ModelToken(
                        token_type="apikey",
                        location=evidence.get("location", "source"),
                        weaknesses=["exposed_in_source"],
                    )
                )

            # Session / cookies
            if "session" in tags or "cookies" in tags or "cookie" in tags:
                evidence = finding.evidence or {}
                cookie_name = evidence.get("cookie_name", evidence.get("name", "unknown"))
                flag = evidence.get("flag", {})
                self.model.add_session(
                    ModelSession(
                        cookie_name=cookie_name,
                        flags=flag if isinstance(flag, dict) else {},
                        fixation_vulnerable=("fixation" in finding.title.lower()),
                        invalidation_works="invalidation" not in finding.title.lower(),
                    )
                )

            # OAuth
            if "oauth" in tags or "oidc" in tags:
                self.model.auth_mechanisms.add("oauth")
                evidence = finding.evidence or {}
                auth_url = evidence.get("authorization_url", "")
                if auth_url and auth_url not in self.model.endpoints:
                    self.model.add_endpoint(
                        AuthEndpoint(
                            url=auth_url,
                            method="GET",
                            auth_mechanism="oauth",
                        )
                    )

            # MFA detected
            if "mfa" in tags:
                self.model.auth_mechanisms.add("mfa")

            # WebSocket endpoints
            if "websocket" in tags:
                evidence = finding.evidence or {}
                ws_url = evidence.get("ws_url", evidence.get("url", ""))
                if ws_url and ws_url not in self.model.endpoints:
                    self.model.add_endpoint(AuthEndpoint(url=ws_url, method="WS", auth_mechanism="ws"))

            # Credentials found (brute force success)
            if "default-credentials" in tags or "brute" in tags:
                if finding.severity == Severity.CRITICAL:
                    evidence = finding.evidence or {}
                    username = evidence.get("username", "")
                    password = evidence.get("password", "")
                    if username:
                        self._credentials_found.append(
                            {
                                "username": username,
                                "password": password if "REDACTED" not in str(password) else "",
                                "source": finding.module_name,
                            }
                        )

        changes["new_endpoints"] = len(self.model.endpoints) - prev_endpoints
        changes["new_tokens"] = len(self.model.tokens) - prev_tokens
        changes["new_sessions"] = len(self.model.sessions) - prev_sessions
        changes["new_mechanisms"] = sorted(self.model.auth_mechanisms - set(self.model._mechanisms_tested))
        changes["credentials_found"] = len(self._credentials_found)

        # Record observation
        self.decision_trail.append(
            DecisionRecord(
                cycle=self.cycle,
                phase="observe",
                action="collect_module_output",
                reasoning=f"Extracted {changes['new_endpoints']} endpoints, "
                f"{changes['new_tokens']} tokens, "
                f"{changes['new_sessions']} sessions",
            )
        )

        return changes

    # ── Orient ───────────────────────────────────────────────────

    def orient(self) -> dict[str, Any]:
        """Update model confidence and identify gaps.

        Returns assessment:
        - confidence: current confidence score
        - gaps: list of untested areas
        - chaining_hints: potential exploit chains detected
        """
        prev_conf = self.model.confidence
        self.model.estimate_confidence()
        delta = self.model.confidence - prev_conf

        gaps: list[str] = []

        # What auth mechanisms exist but haven't been tested?
        for mech in sorted(self.model.auth_mechanisms):
            if mech not in self.model._mechanisms_tested:
                gaps.append(f"untested_mechanism:{mech}")

        # Are there endpoints without auth mechanism classification?
        unknown = [url for url, ep in self.model.endpoints.items() if ep.auth_mechanism is None]
        if unknown:
            gaps.append(f"unclassified_endpoints:{len(unknown)}")

        # Any tokens not yet analyzed?
        for token in self.model.tokens:
            if token.token_type == "jwt" and "alg_none_accepted" not in token.weaknesses:
                if not token.is_cracked:
                    gaps.append("jwt_not_cracked")

        # Chaining hints
        chaining_hints: list[str] = []
        if self._credentials_found and self.model.sessions:
            chaining_hints.append("credentials + sessions → privilege escalation check")
        if any(t.token_type == "jwt" for t in self.model.tokens) and any(
            t.is_cracked for t in self.model.tokens
        ):
            chaining_hints.append("cracked_jwt + other_findings → token_forgery")

        self.decision_trail.append(
            DecisionRecord(
                cycle=self.cycle,
                phase="orient",
                action="update_model",
                reasoning=f"Confidence {self.model.confidence:.2f} ({'+' if delta >= 0 else ''}{delta:.2f}). "
                f"Gaps: {gaps[:3] if gaps else ['none']}",
                confidence_change=delta,
            )
        )

        return {
            "confidence": self.model.confidence,
            "gaps": gaps,
            "chaining_hints": chaining_hints,
        }

    # ── Decide ───────────────────────────────────────────────────

    def decide(self, module_map: dict[str, Any], report: ScanReport) -> dict[str, Any]:
        """Choose the next action based on model state and findings.

        Decision rules (priority-ordered):
        1. Valid creds found → re-run session/jwt with auth
        2. HS256+ JWT found, not cracked → JWT cracker
        3. OAuth endpoints found, not tested → OAuth module
        4. API keys found, not validated → API key module
        5. MFA detected, not tested → MFA module
        6. WebSocket endpoints found, not tested → WS module
        7. Untested auth mechanisms → appropriate module
        8. Conclude

        Returns {"action": ..., "module": ..., "reason": ..., "params": {...}}
        """
        # Rule 1: Valid credentials → re-run session/jwt with auth
        if self._credentials_found:
            cred = self._credentials_found[0]
            if "session" in module_map and "session" not in self._modules_run:
                self._modules_run.add("session")
                return {
                    "action": "run_module",
                    "module": "session",
                    "reason": f"Valid credentials for {cred['username']} found — re-running session tests with auth cookies.",
                    "params": {
                        "cookies": {self.model.sessions[0].cookie_name: "valid"}
                        if self.model.sessions
                        else {}
                    },
                }
            if "jwt" in module_map and "jwt" not in self._modules_run:
                self._modules_run.add("jwt")
                return {
                    "action": "run_module",
                    "module": "jwt",
                    "reason": "Valid credentials found — running JWT analysis with auth context.",
                    "params": {},
                }
            # Mark credentials as "consumed" for session/jwt
            if "session" in self._modules_run and "jwt" in self._modules_run:
                self._credentials_found.pop(0)

        # Rule 2: HS256 JWT found, not cracked
        jwt_tokens = [t for t in self.model.tokens if t.token_type == "jwt"]
        uncracked_hs = [
            t for t in jwt_tokens if t.algorithm and t.algorithm.upper().startswith("HS") and not t.is_cracked
        ]
        if uncracked_hs and "jwt" in module_map:
            self._modules_run.add("jwt")
            return {
                "action": "run_module",
                "module": "jwt",
                "reason": "HS256 JWT found but not yet cracked — running JWT analyzer with cracking priority.",
                "params": {"jwt_crack": True},
            }

        # Rule 3: OAuth endpoints found
        if (
            "oauth" in self.model.auth_mechanisms
            and "oauth" in module_map
            and "oauth" not in self._modules_run
        ):
            self._modules_run.add("oauth")
            return {
                "action": "run_module",
                "module": "oauth",
                "reason": "OAuth endpoints discovered — testing OAuth 2.0 misconfigurations.",
                "params": {},
            }

        # Rule 4: API keys found
        if (
            any(t.token_type == "apikey" for t in self.model.tokens)
            and "api_key" in module_map
            and "api_key" not in self._modules_run
        ):
            self._modules_run.add("api_key")
            return {
                "action": "run_module",
                "module": "api_key",
                "reason": "API keys detected in source — running full API key analysis.",
                "params": {},
            }

        # Rule 5: MFA detected
        if "mfa" in self.model.auth_mechanisms and "mfa" in module_map and "mfa" not in self._modules_run:
            self._modules_run.add("mfa")
            return {
                "action": "run_module",
                "module": "mfa",
                "reason": "MFA indicators detected — testing MFA bypass techniques.",
                "params": {},
            }

        # Rule 6: WebSocket endpoints
        if (
            any(ep.auth_mechanism == "ws" for ep in self.model.endpoints.values())
            and "websocket" in module_map
            and "websocket" not in self._modules_run
        ):
            self._modules_run.add("websocket")
            return {
                "action": "run_module",
                "module": "websocket",
                "reason": "WebSocket endpoints discovered — testing WebSocket authentication.",
                "params": {},
            }

        # Rule 7: Any untested auth mechanisms → appropriate module
        for mech in sorted(self.model.auth_mechanisms):
            if mech not in self.model._mechanisms_tested:
                self.model.mark_mechanism_tested(mech)
                module_name = {
                    "form": "brute",
                    "oauth": "oauth",
                    "jwt": "jwt",
                    "mfa": "mfa",
                    "ws": "websocket",
                }.get(mech)
                if module_name and module_name in module_map and module_name not in self._modules_run:
                    self._modules_run.add(module_name)
                    return {
                        "action": "run_module",
                        "module": module_name,
                        "reason": f"Untested mechanism '{mech}' detected — running {module_name} module.",
                        "params": {},
                    }

        # Rule 8: Also try remaining high-priority modules from config
        config_modules = getattr(self.config, "modules", [])
        for mod_name in config_modules:
            if mod_name != "probe" and mod_name in module_map and mod_name not in self._modules_run:
                self._modules_run.add(mod_name)
                return {
                    "action": "run_module",
                    "module": mod_name,
                    "reason": f"Running remaining module '{mod_name}' from configured set.",
                    "params": {},
                }

        # Conclude
        return {
            "action": "conclude",
            "reason": "All productive actions completed.",
        }

    # ── Act ──────────────────────────────────────────────────────

    def act(
        self,
        decision: dict[str, Any],
        module_map: dict[str, Any],
        report: ScanReport,
    ) -> ModuleResult | None:
        """Execute the decided action."""
        action = decision.get("action", "")
        module_name = decision.get("module", "")
        reason = decision.get("reason", "")

        self.decision_trail.append(
            DecisionRecord(
                cycle=self.cycle,
                phase="act",
                action=f"{action}:{module_name}" if module_name else action,
                reasoning=reason,
            )
        )

        if action == "conclude":
            return None

        if action in ("run_module", "re_run_module"):
            cls = module_map.get(module_name)
            if cls is None:
                return None

            module = cls()
            self.model.mark_module_run(module_name)
            self.model.last_updated = datetime.now(timezone.utc)

            try:
                result = module.run(
                    target=self.config.target,
                    http_client=self.http,
                    report=report,
                    config=self.config,
                )
                return result
            except Exception:
                self.model.mark_module_failed(module_name)
                return ModuleResult(errors=[f"Module {module_name} failed"])

        return None

    # ── Main Loop ────────────────────────────────────────────────

    def run_loop(
        self,
        module_map: dict[str, Any],
        report: ScanReport,
        max_cycles: int = 10,
    ) -> ScanReport:
        """Run the OODA loop until conclusion or max_cycles reached."""
        self.cycle = 0
        threshold = self.config.confidence_threshold

        # Mark probe as done (it always runs first)
        self.model.mark_module_run("probe")
        self.model._mechanisms_tested.add("none")

        # Initial observation from probe findings
        probe_result = ModuleResult(findings=list(report.findings))
        self.observe(probe_result, report)

        while self.cycle < max_cycles:
            self.cycle += 1

            # Orient
            assessment = self.orient()

            # Check termination conditions
            if self.model.confidence >= threshold:
                self.decision_trail.append(
                    DecisionRecord(
                        cycle=self.cycle,
                        phase="decide",
                        action="conclude",
                        reasoning=f"Confidence {self.model.confidence:.2f} >= threshold {threshold}.",
                    )
                )
                break

            # M4: derive the termination set from the live module_map
            # instead of a hardcoded list. This ensures plugin-registered
            # modules also get exercised before the agent concludes.
            all_modules = set(module_map.keys())
            if all_modules and not assessment["gaps"] and self._modules_run >= all_modules:
                self.decision_trail.append(
                    DecisionRecord(
                        cycle=self.cycle,
                        phase="decide",
                        action="conclude",
                        reasoning="No gaps remaining and all registered modules exhausted.",
                    )
                )
                break

            # Decide
            decision = self.decide(module_map, report)
            self.decision_trail.append(
                DecisionRecord(
                    cycle=self.cycle,
                    phase="decide",
                    action=f"{decision.get('action', '')}:{decision.get('module', '')}",
                    reasoning=decision.get("reason", ""),
                )
            )

            if decision["action"] == "conclude":
                # Check if chain synthesis might find more
                if self.cycle < max_cycles:
                    self.decision_trail.append(
                        DecisionRecord(
                            cycle=self.cycle,
                            phase="decide",
                            action="synthesize_chains",
                            reasoning="Concluded — running chain synthesis.",
                        )
                    )
                break

            # Act
            result = self.act(decision, module_map, report)
            if result is None:
                self.decision_trail.append(
                    DecisionRecord(
                        cycle=self.cycle,
                        phase="act",
                        action="no_op",
                        reasoning="Act returned None.",
                    )
                )
                continue

            # Merge findings into report
            for finding in result.findings:
                report.add_finding(finding)

            # Merge state
            report.session_state.update(result.state_update)

            # Observe the results of this action
            self.observe(result, report)

        # Mark conclusion
        report.status = "completed_agentic" if self.cycle <= max_cycles else "max_cycles_exhausted"

        # Attach decision trail
        report.decision_trail = [
            {
                "cycle": d.cycle,
                "phase": d.phase,
                "action": d.action,
                "reasoning": d.reasoning,
                "confidence_change": d.confidence_change,
                "timestamp": d.timestamp.isoformat(),
            }
            for d in self.decision_trail
        ]

        # Run chain synthesis
        chain_findings = self.synthesize_chains(report)
        for cf in chain_findings:
            report.add_finding(cf)

        return report

    # ── Chain Synthesis ──────────────────────────────────────────

    def synthesize_chains(self, report: ScanReport) -> list[Finding]:
        """Analyze all findings for exploit chains and synthesize new combined findings.

        Predefined chain patterns:
        - user_enum + weak_password → account_takeover
        - jwt_hs256 + cracked_secret → token_forgery
        - missing_state + open_redirect → oauth_csrf
        - missing_httponly + xss_related → session_hijacking
        - apikey_in_source + unscoped_key → privilege_escalation

        Confidence model (PR-15, 2026-05-19)
        ------------------------------------
        Per-finding ``confidence`` ∈ [0, 1] reflects *detector reliability* —
        how likely is this finding to be a true positive given the evidence
        we observed. It is set per-Finding by the originating module. The
        target floors are:

        - ≥ 0.9  : strong direct observation with low false-positive risk
                  (cracked secret, accepted weak creds, missing security
                  header, exposed /.env on 200).
        - 0.80-0.89 : reliable binary detection where the evidence is
                  explicit but inference is needed (PKCE absence,
                  MFA body manipulation accepted, session not invalidated
                  on logout, user-enum via ≥2 unique error keywords).
        - 0.60-0.79 : heuristic with non-trivial false-positive risk
                  (scope acceptance ≠ proven escalation, MFA bypass via
                  param injection).
        - ≤ 0.5 : soft signal — timing-based, library-unavailable, manual
                  verification required.

        Chain confidence = ``min(children.confidence) * penalty`` where
        ``penalty`` ∈ [0.85, 0.9] captures the inferential risk that the
        chain itself doesn't fire (the constituents existing doesn't strictly
        prove the combined exploit works). Math implication: even with two
        strong detectors at 1.0, the chain caps at 0.9 — chains are *always*
        rated less certain than their best constituent, by design.

        With the PR-15 floor adjustments, the canonical account-takeover
        chain (user-enum 0.9, weak-creds 0.95, penalty 0.9) now lands at
        0.81 — defensible "high-confidence exploit chain" territory rather
        than the pre-PR-15 0.63 that looked like a hedge.
        """
        chains: list[Finding] = []

        def _tagged(tag: str) -> list[Finding]:
            return [f for f in report.findings if tag in (f.tags or [])]

        def _severity_upgrade(s1: Severity, s2: Severity) -> Severity:
            levels = [
                Severity.INFO,
                Severity.LOW,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            ]
            idx = max(levels.index(s1), levels.index(s2))
            return levels[min(idx + 1, len(levels) - 1)]  # upgrade by 1, max CRITICAL

        # Chain 1: user_enum + weak_password → account_takeover
        user_enum = _tagged("user-enumeration")
        weak_pass = _tagged("default-credentials")
        if user_enum and weak_pass:
            children = [user_enum[0].id, weak_pass[0].id]
            chains.append(
                Finding(
                    title="Exploit Chain: Account Takeover via Enumeration + Weak Password",
                    description=(
                        "Low-severity user enumeration combined with weak/default credentials "
                        "creates a viable account takeover path. An attacker can enumerate valid "
                        "usernames, then authenticate using known weak passwords."
                    ),
                    severity=_severity_upgrade(user_enum[0].severity, weak_pass[0].severity),
                    evidence={
                        "chained_findings": children,
                        "attack_path": "user_enumeration → credential_spraying → account_takeover",
                    },
                    remediation="Fix both user enumeration (use generic error messages) and enforce strong password policy.",
                    cwe_id="CWE-287",
                    module_name="agentic_engine",
                    confidence=min(user_enum[0].confidence, weak_pass[0].confidence) * 0.9,
                    chain_parent=None,
                    chain_children=children,
                    tags=["chain", "account-takeover", "exploit-chain"],
                )
            )

        # Chain 2: jwt_hs256 + cracked_secret → token_forgery
        jwt_cracked = [
            f for f in report.findings if "cracking" in (f.tags or []) and f.severity == Severity.CRITICAL
        ]
        jwt_sensitive = [
            f for f in report.findings if "sensitive-data" in (f.tags or []) and "jwt" in (f.tags or [])
        ]
        if jwt_cracked and jwt_sensitive:
            children = [jwt_cracked[0].id, jwt_sensitive[0].id]
            chains.append(
                Finding(
                    title="Exploit Chain: JWT Token Forgery via Cracked Secret + Sensitive Payload",
                    description=(
                        "JWT HMAC secret was cracked, and the token contains sensitive data. "
                        "An attacker can forge arbitrary tokens with escalated privileges or "
                        "impersonate any user."
                    ),
                    severity=Severity.CRITICAL,
                    evidence={
                        "chained_findings": children,
                        "attack_path": "crack_hmac_secret → forge_jwt_with_admin_role → full_access",
                    },
                    remediation="Rotate JWT secret immediately and use RS256/ES256. Remove sensitive data from JWT payloads.",
                    cwe_id="CWE-347",
                    module_name="agentic_engine",
                    confidence=min(jwt_cracked[0].confidence, jwt_sensitive[0].confidence) * 0.9,
                    chain_parent=None,
                    chain_children=children,
                    tags=["chain", "token-forgery", "exploit-chain", "critical"],
                )
            )

        # Chain 3: missing_state + open_redirect → oauth_csrf
        oauth_redirect = [
            f for f in report.findings if "open-redirect" in (f.tags or []) and "oauth" in (f.tags or [])
        ]
        oauth_csrf_find = [
            f for f in report.findings if "csrf" in (f.tags or []) and "oauth" in (f.tags or [])
        ]
        if oauth_redirect and oauth_csrf_find:
            children = [oauth_redirect[0].id, oauth_csrf_find[0].id]
            chains.append(
                Finding(
                    title="Exploit Chain: OAuth CSRF via Missing State + Open Redirect",
                    description=(
                        "Missing state parameter combined with open redirect in the OAuth flow "
                        "enables full CSRF attacks during authorization. Attackers can steal "
                        "authorization codes and access victim accounts."
                    ),
                    severity=Severity.CRITICAL,
                    evidence={
                        "chained_findings": children,
                        "attack_path": "csrf_attack → victim_authorizes → code_redirected_to_attacker → account_takeover",
                    },
                    remediation="Add state parameter to all OAuth requests and strictly validate redirect_uri against a whitelist.",
                    cwe_id="CWE-352",
                    module_name="agentic_engine",
                    confidence=min(oauth_redirect[0].confidence, oauth_csrf_find[0].confidence) * 0.9,
                    chain_parent=None,
                    chain_children=children,
                    tags=["chain", "oauth-csrf", "exploit-chain", "critical"],
                )
            )

        # Chain 4: missing_httponly + any auth finding → session_hijacking
        missing_httponly = [
            f
            for f in report.findings
            if "HttpOnly" in (f.evidence or {}).get("cookie_name", "") or "HttpOnly" in f.title
        ]
        auth_findings = [
            f
            for f in report.findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL) and f.module_name not in ("agentic_engine",)
        ]
        if missing_httponly and auth_findings:
            children = [missing_httponly[0].id, auth_findings[0].id]
            chains.append(
                Finding(
                    title="Exploit Chain: Session Hijacking via Missing HttpOnly + Auth Vulnerability",
                    description=(
                        "Missing HttpOnly flag on cookies combined with other authentication "
                        "weaknesses enables session hijacking via XSS or other injection vectors. "
                        "An attacker can steal session cookies and impersonate users."
                    ),
                    severity=_severity_upgrade(missing_httponly[0].severity, auth_findings[0].severity),
                    evidence={
                        "chained_findings": children,
                        "attack_path": "xss_or_injection → steal_session_cookie → session_hijacking",
                    },
                    remediation="Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                    cwe_id="CWE-1004",
                    module_name="agentic_engine",
                    confidence=min(missing_httponly[0].confidence, auth_findings[0].confidence) * 0.85,
                    chain_parent=None,
                    chain_children=children,
                    tags=["chain", "session-hijacking", "exploit-chain"],
                )
            )

        # Chain 5: apikey_exposure + auth_weakness → privilege_escalation
        api_keys = _tagged("api-key")
        api_secrets = _tagged("secret-exposure")
        high_findings = [f for f in report.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        if (api_keys or api_secrets) and high_findings:
            children = [(api_keys + api_secrets)[0].id, high_findings[0].id]
            chains.append(
                Finding(
                    title="Exploit Chain: Privilege Escalation via Exposed Keys + Auth Weakness",
                    description=(
                        "API keys/secrets found in client-side code combined with other "
                        "authentication weaknesses create a path to privilege escalation. "
                        "Exposed keys can be used to access backend services directly."
                    ),
                    severity=Severity.CRITICAL,
                    evidence={
                        "chained_findings": children,
                        "attack_path": "extract_api_key → access_admin_apis → privilege_escalation",
                    },
                    remediation="Remove all secrets from client-side code. Use server-side API proxies.",
                    cwe_id="CWE-798",
                    module_name="agentic_engine",
                    confidence=min((api_keys + api_secrets)[0].confidence, high_findings[0].confidence)
                    * 0.85,
                    chain_parent=None,
                    chain_children=children,
                    tags=["chain", "privilege-escalation", "exploit-chain", "critical"],
                )
            )

        return chains
