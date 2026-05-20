"""Path discovery — probes common auth-related endpoints."""

from __future__ import annotations

import concurrent.futures
from typing import Any

# ~80 common auth-related paths
AUTH_PATHS: list[str] = [
    # OIDC / OAuth discovery
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth2/authorize",
    "/oauth2/token",
    "/oidc/.well-known/openid-configuration",
    "/openid-configuration",
    # API docs / discovery
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger",
    "/swagger.json",
    "/swagger-ui.html",
    "/docs",
    "/api-docs",
    "/redoc",
    # Auth endpoints
    "/login",
    "/signin",
    "/sign-in",
    "/signup",
    "/sign-up",
    "/register",
    "/registration",
    "/auth/login",
    "/auth/signin",
    "/auth/register",
    "/reset-password",
    "/forgot-password",
    "/forgot",
    "/logout",
    "/signout",
    "/sign-out",
    "/auth/logout",
    "/profile",
    "/account",
    "/settings",
    "/dashboard",
    "/admin",
    "/administrator",
    "/panel",
    "/cpanel",
    # Sensitive files
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.example",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/backup",
    "/backup/",
    "/backups",
    "/dump",
    "/db.sql",
    "/wp-config.php",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    # VCS
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/hgrc",
    # Common apps
    "/phpmyadmin",
    "/phpMyAdmin",
    "/pma",
    "/wp-admin",
    "/wp-login.php",
    "/drupal",
    "/joomla",
    # Other
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]


def _probe_one(http_client: Any, path: str, timeout_per: int) -> dict[str, Any]:
    """Issue a single probe and return its serialized result entry.

    Network and HTTP errors are normalised to a zero-status placeholder so
    the parallel runner doesn't have to special-case them. The HTTP
    client's own rate limiter still serialises wire access.
    """
    try:
        resp = http_client.get(path, timeout=timeout_per)
        status = resp.status_code
        entry: dict[str, Any] = {
            "status": status,
            "length": len(resp.content),
            "headers": dict(resp.headers),
            "interesting": status not in (404, 410, 405, 501),
        }
        if status in (200, 301, 302, 307, 308, 401, 403):
            entry["interesting"] = True
        return entry
    except Exception:
        return {"status": 0, "length": 0, "headers": {}, "interesting": False}


def discover_paths(
    http_client: Any,
    paths: list[str] | None = None,
    max_paths: int = 80,
    timeout_per: int = 3,
    max_workers: int = 10,
) -> dict[str, dict[str, Any]]:
    """Probe common paths and record responses.

    Probes run on a bounded ``ThreadPoolExecutor`` (default 10 workers) so
    discovery on slow or geographically-distant targets is no longer
    serialised — previously 80 paths × 3s timeout could take 240s before
    any attack module started. Rate limiting is still enforced at the
    HTTP-client level (``RateLimiter.acquire()`` inside each request), so
    the global request budget is unchanged; only the latency hides behind
    parallel I/O.

    Returns dict mapping path -> {status, length, headers, interesting}.
    "interesting" is True for non-404 responses or auth-related endpoints.
    """
    to_check = (paths or AUTH_PATHS)[:max_paths]
    if not to_check:
        return {}

    results: dict[str, dict[str, Any]] = {}
    # max_workers=1 falls back to serial — useful for tests that record
    # request order, and for environments that can't spawn threads.
    workers = max(1, min(max_workers, len(to_check)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_path = {pool.submit(_probe_one, http_client, path, timeout_per): path for path in to_check}
        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            try:
                results[path] = future.result()
            except Exception:
                results[path] = {
                    "status": 0,
                    "length": 0,
                    "headers": {},
                    "interesting": False,
                }
    return results


# Paths whose presence is *expected* on most auth-protected apps — a 200 here
# is not a finding, just normal app structure. Bookkeeping only; the raw
# probe results are still available via report.metadata['path_results'].
EXPECTED_AUTH_ENDPOINTS: frozenset[str] = frozenset(
    {
        "/login",
        "/signin",
        "/sign-in",
        "/signup",
        "/sign-up",
        "/register",
        "/registration",
        "/auth/login",
        "/auth/signin",
        "/auth/register",
        "/auth/logout",
        "/logout",
        "/signout",
        "/sign-out",
        "/reset-password",
        "/forgot-password",
        "/forgot",
        "/profile",
        "/account",
        "/settings",
        "/dashboard",
        "/api",
        "/api/",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth2/authorize",
        "/oauth2/token",
        "/robots.txt",
        "/sitemap.xml",
    }
)

# Paths whose accessibility on 200 is a security finding by itself (secrets,
# VCS metadata, backups, admin consoles, info disclosure pages).
SENSITIVE_PATH_PREFIXES: tuple[str, ...] = (
    "/.env",
    "/.git/",
    "/.svn/",
    "/.hg/",
    "/backup",
    "/backups",
    "/dump",
    "/db.sql",
    "/wp-config.php",
    "/wp-admin",
    "/wp-login.php",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/pma",
    "/drupal",
    "/joomla",
    "/admin",
    "/administrator",
    "/panel",
    "/cpanel",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
)

# /.well-known endpoints: exposing OIDC/OAuth metadata is expected (it's
# designed to be public), but worth recording as a discovery so downstream
# modules can pick them up. Treated as INFO discoveries, not findings.
DISCOVERY_PATH_PREFIXES: tuple[str, ...] = (
    "/.well-known/",
    "/openid-configuration",
    "/oidc/",
    "/swagger",
    "/docs",
    "/api-docs",
    "/redoc",
)


def _is_sensitive_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in SENSITIVE_PATH_PREFIXES)


def _is_expected_auth_endpoint(path: str) -> bool:
    return path in EXPECTED_AUTH_ENDPOINTS


def _is_discovery_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in DISCOVERY_PATH_PREFIXES)


def report_discoveries(
    findings: list[Any],
    results: dict[str, dict[str, Any]],
    module_name: str = "path_discovery",
    target_url: str | None = None,
) -> None:
    """Add Finding entries for *genuinely* interesting path discoveries.

    Filtering rules (changed in PR-13):
    - 200 on an expected auth endpoint (e.g. `/login`, `/register`) is NOT a
      finding — it's normal app structure. Suppressed to keep reports actionable.
    - 200 on a sensitive path (`/.env`, `/.git/*`, `/backup`, admin consoles,
      VCS metadata, info-disclosure pages) IS a finding (MEDIUM/HIGH).
    - 401/403 are always emitted — they prove a protected resource exists.
    - 3xx redirects are emitted only when the destination is off-origin
      (a cross-origin redirect is interesting; staying on the same host is
      routine auth-flow plumbing).
    - OIDC/OAuth `.well-known` and API doc endpoints are recorded as INFO
      discoveries so downstream modules can ingest them.

    Raw probe data remains available via ``report.metadata['path_results']``
    for operators who want the full picture.
    """
    from auth_scan.attacks.base import Finding, Severity

    interesting = {p: r for p, r in results.items() if r["interesting"]}

    if not interesting:
        return

    for path, result in sorted(interesting.items()):
        status = result["status"]

        if status == 200:
            if _is_sensitive_path(path):
                # Pick severity: admin consoles & VCS metadata are HIGH; other
                # sensitive exposures (info pages, backups) are MEDIUM.
                high_signals = ("/.env", "/.git/", "/.svn/", "/.hg/", "/wp-config.php", "/db.sql")
                severity = Severity.HIGH if any(path.startswith(p) for p in high_signals) else Severity.MEDIUM
                findings.append(
                    Finding(
                        title=f"Sensitive Path Exposed: {path}",
                        description=(
                            f"Sensitive path {path} is publicly accessible "
                            f"(HTTP 200, {result['length']} bytes). This typically "
                            "exposes secrets, source control metadata, backups, or admin tooling."
                        ),
                        severity=severity,
                        evidence={"path": path, "status": status, "length": result["length"]},
                        remediation=(
                            "Restrict access to this path at the web server or framework level; "
                            "for VCS or config files, remove them from the web root entirely."
                        ),
                        cwe_id="CWE-538",
                        module_name=module_name,
                        confidence=0.85,
                        tags=["discovery", "paths", "exposure"],
                    )
                )
            elif _is_discovery_path(path):
                findings.append(
                    Finding(
                        title=f"Discovery Endpoint: {path}",
                        description=(
                            f"Discovery/metadata endpoint {path} is accessible. "
                            "Use this to enumerate supported auth flows, scopes, and keys."
                        ),
                        severity=Severity.INFO,
                        evidence={"path": path, "status": status},
                        module_name=module_name,
                        tags=["discovery", "paths", "metadata"],
                    )
                )
            elif not _is_expected_auth_endpoint(path):
                # Unknown 200 — not in the expected list, not sensitive. Keep
                # as INFO so it isn't lost, but don't flood the report.
                findings.append(
                    Finding(
                        title=f"Path Discovered (200): {path}",
                        description=f"Accessible path found: {path} (HTTP 200, {result['length']} bytes).",
                        severity=Severity.INFO,
                        evidence={"path": path, "status": status},
                        module_name=module_name,
                        tags=["discovery", "paths"],
                    )
                )
            # else: expected auth endpoint on 200 — suppressed.

        elif status in (301, 302, 307, 308):
            location = result["headers"].get("Location", result["headers"].get("location", ""))
            if _is_offsite_redirect(location, target_url):
                findings.append(
                    Finding(
                        title=f"Off-Origin Redirect at: {path}",
                        description=f"Path {path} redirects (HTTP {status}) to off-origin {location}.",
                        severity=Severity.INFO,
                        evidence={"path": path, "status": status, "redirect_to": location},
                        module_name=module_name,
                        tags=["discovery", "paths", "redirect"],
                    )
                )
            # else: same-origin redirect — routine auth flow plumbing, suppressed.

        elif status == 401:
            findings.append(
                Finding(
                    title=f"Protected Endpoint (401): {path}",
                    description=f"Path {path} requires authentication (HTTP 401).",
                    severity=Severity.INFO,
                    evidence={"path": path, "status": status},
                    module_name=module_name,
                    tags=["discovery", "paths", "auth"],
                )
            )

        elif status == 403:
            findings.append(
                Finding(
                    title=f"Forbidden Endpoint (403): {path}",
                    description=f"Path {path} is forbidden (HTTP 403). May contain sensitive resources.",
                    severity=Severity.LOW,
                    evidence={"path": path, "status": status},
                    module_name=module_name,
                    tags=["discovery", "paths"],
                )
            )


def _is_offsite_redirect(location: str, target_url: str | None) -> bool:
    """True if the redirect target's host differs from the scan target's host.

    Relative paths, empty Location values, and absolute URLs whose host
    matches ``target_url`` are treated as same-origin.
    """
    if not location:
        return False
    if location.startswith("/"):
        return False
    if "://" not in location:
        return False

    from urllib.parse import urlparse

    try:
        loc_host = urlparse(location).netloc.lower()
    except ValueError:
        return False
    if not loc_host:
        return False

    if not target_url:
        return True
    try:
        target_host = urlparse(target_url).netloc.lower()
    except ValueError:
        return True
    return loc_host != target_host
