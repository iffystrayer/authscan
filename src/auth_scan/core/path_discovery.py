"""Path discovery — probes common auth-related endpoints."""
from __future__ import annotations

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


def discover_paths(
    http_client: Any,
    paths: list[str] | None = None,
    max_paths: int = 80,
    timeout_per: int = 3,
) -> dict[str, dict[str, Any]]:
    """Probe common paths and record responses.

    Returns dict mapping path -> {status, length, headers, interesting}.
    "interesting" is True for non-404 responses or auth-related endpoints.
    """
    results: dict[str, dict[str, Any]] = {}
    to_check = (paths or AUTH_PATHS)[:max_paths]

    for path in to_check:
        try:
            resp = http_client.get(path, timeout=timeout_per)
            status = resp.status_code

            # Normalize path
            clean_path = path.rstrip("/") or "/"

            results[path] = {
                "status": status,
                "length": len(resp.content),
                "headers": dict(resp.headers),
                "interesting": status not in (404, 410, 405, 501),
            }

            # Flag auth-related responses
            if status in (200, 301, 302, 307, 308, 401, 403):
                results[path]["interesting"] = True

        except Exception:
            # Silently skip unreachable paths
            results[path] = {
                "status": 0,
                "length": 0,
                "headers": {},
                "interesting": False,
            }

    return results


def report_discoveries(
    findings: list[Any],
    results: dict[str, dict[str, Any]],
    module_name: str = "path_discovery",
) -> None:
    """Add Finding entries for interesting path discoveries."""
    from auth_scan.attacks.base import Finding, Severity

    interesting = {p: r for p, r in results.items() if r["interesting"]}

    if not interesting:
        findings.append(Finding(
            title="Path Discovery: No Interesting Endpoints",
            description="No interesting auth-related paths discovered beyond the root.",
            severity=Severity.INFO,
            module_name=module_name,
            tags=["discovery", "paths"],
        ))
        return

    # Group by status
    for path, result in sorted(interesting.items()):
        status = result["status"]
        if status == 200:
            findings.append(Finding(
                title=f"Path Discovered (200): {path}",
                description=f"Accessible path found: {path} (HTTP 200, {result['length']} bytes).",
                severity=Severity.INFO,
                evidence={"path": path, "status": status},
                module_name=module_name,
                tags=["discovery", "paths"],
            ))
        elif status in (301, 302, 307, 308):
            location = result["headers"].get("Location", result["headers"].get("location", ""))
            findings.append(Finding(
                title=f"Redirect at: {path}",
                description=f"Path {path} redirects (HTTP {status}) to {location}.",
                severity=Severity.INFO,
                evidence={"path": path, "status": status, "redirect_to": location},
                module_name=module_name,
                tags=["discovery", "paths"],
            ))
        elif status == 401:
            findings.append(Finding(
                title=f"Protected Endpoint (401): {path}",
                description=f"Path {path} requires authentication (HTTP 401).",
                severity=Severity.INFO,
                evidence={"path": path, "status": status},
                module_name=module_name,
                tags=["discovery", "paths", "auth"],
            ))
        elif status == 403:
            findings.append(Finding(
                title=f"Forbidden Endpoint (403): {path}",
                description=f"Path {path} is forbidden (HTTP 403). May contain sensitive resources.",
                severity=Severity.LOW,
                evidence={"path": path, "status": status},
                module_name=module_name,
                tags=["discovery", "paths"],
            ))
