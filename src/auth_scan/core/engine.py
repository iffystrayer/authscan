"""Core assessment engine — orchestrates HTTP client and attack modules."""

from __future__ import annotations

import logging
import re
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auth_scan.attacks.base import BaseAttackModule, Finding, ScanReport, Severity
from auth_scan.core.config import ScanConfig
from auth_scan.core.exceptions import ConfigError, HttpError, ModuleError
from auth_scan.core.http_client import HTTPClient
from auth_scan.core.session import check_security_headers

# Module discovery via entry_points (Phase 2 plugin system)

_log = logging.getLogger(__name__)


def discover_modules() -> dict[str, type[BaseAttackModule]]:
    """Discover all available attack modules via entry_points + built-in fallback.

    Returns a name → class map, e.g. ``{"jwt": JWTAnalyzer, ...}``. Plugins
    that register the same name as a built-in override the built-in.
    This is the single canonical registry; CLI and engine both consult it.
    """
    modules: dict[str, type[BaseAttackModule]] = {}

    # Try entry_points first (supports external plugins)
    try:
        from importlib.metadata import entry_points

        discovered = entry_points(group="auth_scan.modules")
        for ep in discovered:
            try:
                cls = ep.load()
                if isinstance(cls, type) and issubclass(cls, BaseAttackModule) and hasattr(cls, "name"):
                    modules[cls.name] = cls
            except Exception as exc:
                _log.debug("swallowed: %s", exc)
    except Exception as exc:
        _log.debug("swallowed: %s", exc)

    # Fall back to built-in hardcoded registry if entry_points fails or returns nothing
    if not modules:
        from auth_scan.attacks.api_key import ApiKeyAnalyzer
        from auth_scan.attacks.brute import BruteForce
        from auth_scan.attacks.jwt_analyzer import JWTAnalyzer
        from auth_scan.attacks.mfa import MfaBypass
        from auth_scan.attacks.oauth import OAuthTester
        from auth_scan.attacks.session_tests import SessionTester
        from auth_scan.attacks.websocket_auth import WebSocketAuth

        builtins: list[type[BaseAttackModule]] = [
            JWTAnalyzer,
            BruteForce,
            SessionTester,
            OAuthTester,
            MfaBypass,
            WebSocketAuth,
            ApiKeyAnalyzer,
        ]
        for cls in builtins:
            if hasattr(cls, "name"):
                modules[cls.name] = cls

    return modules


def all_module_names() -> list[str]:
    """Return the canonical module name list for ``--modules all``.

    Includes ``probe`` (always-on lifecycle phase) plus every name
    returned by :func:`discover_modules`, deduped, ordered with ``probe``
    first.
    """
    names = ["probe"]
    for name in discover_modules().keys():
        if name not in names:
            names.append(name)
    return names


# Backwards-compatible alias for code that imported the private name.
_discover_modules = discover_modules


class ScanEngine:
    """Main scanner that coordinates HTTP client, probe phase, and attack modules."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.report = ScanReport(
            target=config.target,
            effective_target=config.target,
            status="initialized",
        )
        self.http: HTTPClient | None = None
        self._shutdown_requested = False
        self._start_time: float = 0.0
        self._endpoints_tested: int = 0

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum: int, frame: Any) -> None:
        """Handle SIGINT/SIGTERM gracefully."""
        if self._shutdown_requested:
            # Force exit on second signal
            sys.exit(255)

        self._shutdown_requested = True
        self.report.status = "failed"
        self.report.completed_at = datetime.now(timezone.utc)

        from rich.console import Console

        Console(stderr=True).print("\n[yellow]Shutdown requested. Saving partial results...[/yellow]")

        # Save partial results
        try:
            self._save_checkpoint()
        except Exception as exc:
            _log.debug("swallowed: %s", exc)

        sys.exit(255)

    def _save_checkpoint(self) -> str:
        """Save current scan state to a checkpoint file."""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_path = output_dir / f"checkpoint-{self.report.scan_id}.json"
        checkpoint_path.write_text(self.report.to_json(redact=not self.config.no_redact))
        return str(checkpoint_path)

    def _init_http_client(self) -> HTTPClient:
        """Initialize the HTTP client from config."""
        self.http = HTTPClient(
            base_url=self.config.target,
            proxy=self.config.proxy or None,
            verify_ssl=not self.config.no_verify,
            ca_bundle=self.config.ca_bundle or None,
            rate_limit=self.config.rate_limit,
            timeout=self.config.timeout,
            scope_allow=self.config.scope_allow or None,
            scope_deny=self.config.scope_deny or None,
            user_agent=self.config.user_agent,
            cookies=self.config.cookies,
            headers=self.config.headers,
            allow_http_fallback=getattr(self.config, "allow_http_fallback", False),
        )
        return self.http

    def run(self) -> ScanReport:
        """Execute the full scan lifecycle: probe → modules → report."""
        self._start_time = time.monotonic()
        self.report.started_at = datetime.now(timezone.utc)

        try:
            # Validate config
            self.config.validate()

            # Initialize HTTP client
            self._init_http_client()
            assert self.http is not None

            # Phase 1: Probe
            self.report.status = "probing"
            self._run_probe()

            if self._shutdown_requested:
                return self.report

            # Phase 2: Attack modules
            agentic_enabled = getattr(self.config, "agentic", False)
            if agentic_enabled:
                self._run_agentic()
            else:
                self._run_modules()

            if self._shutdown_requested:
                return self.report

            # Snapshot config
            self.report.config_snapshot = {
                "rate_limit": self.config.rate_limit,
                "timeout": self.config.timeout,
                "modules": self.config.modules,
                "agentic": self.config.agentic,
            }

            # Surface the endpoint count so reporters / external tooling
            # don't have to dig into the engine. L10.
            self.report.metadata["endpoints_tested"] = self._endpoints_tested

            # Mark complete
            self.report.status = "completed"
            self.report.completed_at = datetime.now(timezone.utc)

        except ConfigError as e:
            self.report.status = "failed"
            self.report.add_finding(
                Finding(
                    title="Configuration Error",
                    description=str(e),
                    severity=Severity.INFO,
                    module_name="engine",
                )
            )
            raise

        except HttpError as e:
            self.report.status = "failed"
            self.report.add_finding(
                Finding(
                    title="HTTP Error",
                    description=str(e),
                    severity=Severity.INFO,
                    module_name="engine",
                )
            )

        except Exception as e:
            self.report.status = "failed"
            self.report.add_finding(
                Finding(
                    title="Scan Error",
                    description=f"Unexpected error: {e}",
                    severity=Severity.INFO,
                    module_name="engine",
                )
            )
            raise

        finally:
            self.report.completed_at = self.report.completed_at or datetime.now(timezone.utc)
            if self.http:
                self.http.close()

        return self.report

    def _run_probe(self) -> None:
        """FR-SL-002 through FR-SL-004: Execute the probe phase."""
        assert self.http is not None

        try:
            probe = self.http.probe()
            self._endpoints_tested += 1

            # Store probe results in metadata
            self.report.metadata["probe_status"] = probe.status_code
            self.report.metadata["probe_headers"] = probe.headers
            self.report.metadata["probe_cookies"] = probe.cookies
            self.report.metadata["probe_body"] = probe.body
            self.report.metadata["probe_body_length"] = probe.body_length
            self.report.metadata["probe_forms"] = probe.forms
            self.report.metadata["probe_tls_version"] = probe.tls_version
            self.report.metadata["probe_redirect_chain"] = probe.redirect_chain
            self.report.metadata["probe_final_url"] = probe.final_url
            self.report.effective_target = probe.final_url

            # Store in session state for modules
            self.report.session_state["probe_cookies"] = probe.cookies
            self.report.session_state["probe_headers"] = probe.headers

            # FR-SL-003: TLS check
            target_scheme = self.config.target.split("://")[0] if "://" in self.config.target else "https"
            is_https = probe.final_url.startswith("https://")

            if not is_https and target_scheme == "https":
                # HTTPS redirected to HTTP — potential downgrade attack
                self.report.add_finding(
                    Finding(
                        title="HTTPS to HTTP Downgrade",
                        description=(
                            f"Target redirected from HTTPS to HTTP: {probe.redirect_chain}. "
                            "This may indicate a misconfigured redirect or potential SSL stripping."
                        ),
                        severity=Severity.HIGH,
                        evidence={"redirect_chain": probe.redirect_chain},
                        remediation="Ensure all traffic uses HTTPS. Configure HSTS with includeSubDomains.",
                        module_name="probe",
                        tags=["ssl", "downgrade"],
                    )
                )

            elif target_scheme == "http" and is_https:
                # HTTP upgraded to HTTPS — good but worth noting original
                self.report.add_finding(
                    Finding(
                        title="HTTP to HTTPS Redirect",
                        description="Target redirected HTTP to HTTPS. This is good but the original HTTP endpoint still exists.",
                        severity=Severity.LOW,
                        evidence={"redirect_chain": probe.redirect_chain},
                        remediation="Consider disabling HTTP entirely or using HSTS to enforce HTTPS.",
                        module_name="probe",
                        tags=["ssl", "redirect"],
                    )
                )

            elif not is_https:
                self.report.add_finding(
                    Finding(
                        title="No TLS/HTTPS",
                        description="Target is served over unencrypted HTTP. All traffic, including credentials, is transmitted in cleartext.",
                        severity=Severity.HIGH,
                        evidence={"scheme": "http"},
                        remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
                        cwe_id="CWE-319",
                        module_name="probe",
                        tags=["ssl", "no-tls"],
                    )
                )

            # H4: surface scanner-side HTTPS->HTTP fallback as a finding so it
            # isn't silent. This is distinct from the server-driven redirect
            # case above — the *scanner* fell back because HTTPS failed.
            if getattr(probe, "http_fallback_attempted", False):
                self.report.add_finding(
                    Finding(
                        title="Scanner HTTPS-to-HTTP Fallback",
                        description=(
                            "HTTPS probe failed; the scanner fell back to plain HTTP "
                            "(allow_http_fallback was enabled). All authentication "
                            "material captured by this scan travelled in plaintext."
                        ),
                        severity=Severity.MEDIUM,
                        evidence={"redirect_chain": probe.redirect_chain},
                        remediation=(
                            "Investigate the HTTPS failure (TLS cert, SNI, proxy). "
                            "Avoid using --allow-http-fallback in production engagements."
                        ),
                        cwe_id="CWE-319",
                        module_name="probe",
                        tags=["ssl", "downgrade", "scanner-fallback"],
                    )
                )

            # FR-SL-004: Security headers check
            header_checks = check_security_headers(probe.headers, is_https)
            for header_name, check in header_checks.items():
                if not check["present"] and check["required"]:
                    severity = Severity.MEDIUM if check["severity"] == "medium" else Severity.LOW
                    self.report.add_finding(
                        Finding(
                            title=f"Missing Security Header: {header_name}",
                            description=check["message"],
                            severity=severity,
                            evidence={"header": header_name, "present": False},
                            remediation=(
                                f"Add the {header_name} header with appropriate directives. "
                                "Refer to OWASP Secure Headers Project for guidance."
                            ),
                            module_name="probe",
                            tags=["headers", header_name.lower()],
                        )
                    )

            # Discovered forms info
            if probe.forms:
                login_forms = [
                    f for f in probe.forms if any(i.get("type") == "password" for i in f.get("inputs", []))
                ]
                self.report.metadata["login_forms_discovered"] = len(login_forms)
                if login_forms:
                    self.report.add_finding(
                        Finding(
                            title="Login Form Discovered",
                            description=f"Found {len(login_forms)} form(s) with password fields.",
                            severity=Severity.INFO,
                            evidence={
                                "form_count": len(login_forms),
                                "actions": [f.get("action") for f in login_forms],
                            },
                            module_name="probe",
                            tags=["discovery", "forms"],
                        )
                    )

            # Check for JWTs in cookies
            from auth_scan.core.session import TokenInfo

            jwt_found = False
            for name, value in probe.cookies.items():
                parts = value.split(".")
                if len(parts) == 3 and all(re.match(r"^[a-zA-Z0-9_-]+$", p) for p in parts):
                    try:
                        token = TokenInfo.from_string(value, "cookie", name)
                        if token.is_jwt:
                            jwt_found = True
                            self.report.metadata.setdefault("jwt_tokens", []).append(
                                {
                                    "location": "cookie",
                                    "name": name,
                                    "algorithm": token.algorithm,
                                    "expires": str(token.expires) if token.expires else None,
                                    "issues": token.issues,
                                }
                            )
                    except Exception as exc:
                        _log.debug("swallowed: %s", exc)
            if jwt_found:
                self.report.add_finding(
                    Finding(
                        title="JWT Token in Cookies",
                        description="JWT tokens found in browser cookies. Verify proper token handling.",
                        severity=Severity.INFO,
                        module_name="probe",
                        tags=["jwt", "discovery"],
                    )
                )

            import re

            # Check for sensitive info in response
            sensitive_patterns = [
                (r"password\s*[=:]\s*[\"'][^\"']+[\"']", "password in response", Severity.HIGH),
                (r"secret\s*[=:]\s*[\"'][^\"']+[\"']", "secret in response", Severity.HIGH),
                (r"api[_-]?key\s*[=:]\s*[\"'][^\"']+[\"']", "API key in response", Severity.HIGH),
                (r"<!--.*TODO.*-->", "TODO comment in HTML", Severity.INFO),
            ]
            for pattern, desc, sev in sensitive_patterns:
                if re.search(pattern, probe.body, re.IGNORECASE):
                    self.report.add_finding(
                        Finding(
                            title=f"Sensitive Information in Response: {desc}",
                            description=f"Response body may contain {desc}.",
                            severity=sev,
                            module_name="probe",
                            tags=["information-disclosure"],
                        )
                    )

            # Path Discovery (Phase 2)
            no_discovery = getattr(self.config, "no_discovery", False)
            if not no_discovery and not self._shutdown_requested:
                from auth_scan.core.path_discovery import (
                    discover_paths,
                    report_discoveries,
                )

                path_results = discover_paths(self.http, timeout_per=3)
                self.report.metadata["path_results"] = path_results
                report_discoveries(self.report.findings, path_results, module_name="path_discovery")
                self._endpoints_tested += len(path_results)

        except HttpError as e:
            self.report.add_finding(
                Finding(
                    title="Probe Failed",
                    description=f"Could not probe target: {e}",
                    severity=Severity.HIGH,
                    evidence={"error": str(e)},
                    module_name="probe",
                )
            )
            raise

    def _run_modules(self) -> None:
        """FR-SL-005, FR-SL-006: Run attack modules in order."""
        assert self.http is not None

        # Get desired module names from config
        desired_modules = self.config.modules

        # Load modules via discovery (entry_points or built-in fallback)
        module_map = _discover_modules()

        # Filter to requested modules, excluding "probe" (already run)
        to_run: list[str] = []
        for mod_name in desired_modules:
            if mod_name == "probe":
                continue
            if mod_name == "all":
                to_run = [m for m in module_map if m != "probe"]
                break
            if mod_name in module_map:
                to_run.append(mod_name)
            else:
                self.report.add_finding(
                    Finding(
                        title=f"Unknown Module: {mod_name}",
                        description=f"Module '{mod_name}' was requested but is not available. Skipping.",
                        severity=Severity.INFO,
                        module_name="engine",
                    )
                )

        # Sort by priority
        to_run.sort(key=lambda m: module_map[m].priority)

        # FR-SL-011: Quick mode — only run probe + header checks
        if self.config.quick:
            return

        # Run each module sequentially
        for mod_name in to_run:
            if self._shutdown_requested:
                break

            module_cls = module_map[mod_name]
            module = module_cls()

            try:
                result = module.run(
                    target=self.config.target,
                    http_client=self.http,
                    report=self.report,
                    config=self.config,
                )

                # Merge findings
                for finding in result.findings:
                    self.report.add_finding(finding)

                # Merge state updates
                self.report.session_state.update(result.state_update)

                # Track warnings
                for _warning in result.warnings:
                    # Log warning but don't add as finding
                    pass

                # Track endpoints tested
                self._endpoints_tested += 1

            except ModuleError as e:
                self.report.add_finding(
                    Finding(
                        title=f"Module Error: {mod_name}",
                        description=str(e),
                        severity=Severity.INFO,
                        evidence={"module": mod_name, "error": str(e)},
                        module_name="engine",
                    )
                )
            except Exception as e:
                self.report.add_finding(
                    Finding(
                        title=f"Module Failed: {mod_name}",
                        description=f"Module '{mod_name}' failed with error: {e}",
                        severity=Severity.INFO,
                        evidence={"module": mod_name, "error": str(e)},
                        module_name="engine",
                    )
                )

    def _run_agentic(self) -> None:
        """Run scan with the OODA agentic engine instead of sequential modules."""
        assert self.http is not None

        from auth_scan.core.agentic import OODAEngine
        from auth_scan.core.attack_surface import AttackSurfaceModel

        # Build initial attack surface model from probe results
        model = AttackSurfaceModel(target=self.config.target)

        # Populate model from probe metadata
        self.report.metadata.get("probe_body", "")
        probe_url = self.report.metadata.get("probe_final_url", self.config.target)

        # Add probed endpoint
        from auth_scan.core.attack_surface import AuthEndpoint

        model.add_endpoint(
            AuthEndpoint(
                url=probe_url,
                method="GET",
                status=self.report.metadata.get("probe_status", 0),
                response_headers=self.report.metadata.get("probe_headers", {}),
            )
        )

        # Add forms
        probe_forms = self.report.metadata.get("probe_forms", [])
        for form in probe_forms:
            action = form.get("action", "")
            if action:
                inputs = form.get("inputs", [])
                has_pass = any(i.get("type") == "password" for i in inputs)
                model.add_endpoint(
                    AuthEndpoint(
                        url=action,
                        method=form.get("method", "POST"),
                        auth_mechanism="form" if has_pass else None,
                        form_fields=[i.get("name", "") for i in inputs if i.get("name")],
                    )
                )

        # Add JWTs from cookies
        probe_cookies = self.report.metadata.get("probe_cookies", {})
        import re

        from auth_scan.core.attack_surface import ModelToken

        for name, value in probe_cookies.items():
            parts = value.split(".")
            if len(parts) == 3 and all(re.match(r"^[a-zA-Z0-9_-]+$", p) for p in parts):
                from auth_scan.core.session import TokenInfo

                try:
                    ti = TokenInfo.from_string(value, "cookie", name)
                    if ti.is_jwt:
                        model.add_token(
                            ModelToken(
                                token_type="jwt",
                                location=f"cookie:{name}",
                                algorithm=ti.algorithm,
                                claims=ti.payload or {},
                                weaknesses=ti.issues.copy(),
                                raw_preview=value[:40] + "...",
                            )
                        )
                except Exception as exc:
                    _log.debug("swallowed: %s", exc)

        # Add cookies as sessions
        from auth_scan.core.attack_surface import ModelSession

        for name, _value in probe_cookies.items():
            if any(h in name.lower() for h in ["session", "sid", "sess", "auth"]):
                model.add_session(ModelSession(cookie_name=name))

        # Get module map
        module_map = _discover_modules()

        # Create OODA engine
        ooda = OODAEngine(
            model=model,
            config=self.config,
            http_client=self.http,
        )

        # Run the loop
        max_cycles = getattr(self.config, "max_depth", 10)
        self.report = ooda.run_loop(module_map, self.report, max_cycles=max_cycles)

        # Record decision trail metadata
        self.report.metadata["agentic_mode"] = True
        self.report.metadata["agentic_model_summary"] = model.summary()

    def get_summary(self) -> dict[str, Any]:
        """Return a summary dict for the CLI to use."""
        return {
            "scan_id": self.report.scan_id,
            "target": self.report.target,
            "status": self.report.status,
            "duration": time.monotonic() - self._start_time,
            "endpoints_tested": self._endpoints_tested,
            "findings_count": len(self.report.findings),
            "highest_severity": self.report.get_highest_severity().value,
            "risk_score": self.report.risk_score,
            "exit_code": self.report.exit_code,
        }


def run_assessment(config: ScanConfig) -> ScanReport:
    """Top-level entry point: run a full assessment and return the report."""
    engine = ScanEngine(config)
    return engine.run()
