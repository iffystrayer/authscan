"""Command-line interface for auth-scan."""

from __future__ import annotations

import sys

import click

from auth_scan import __version__
from auth_scan.core.config import generate_default_config, load_config
from auth_scan.core.engine import all_module_names, run_assessment
from auth_scan.core.exceptions import AuthScanError, ConfigError
from auth_scan.core.reporter import Reporter


class AuthScanCommand(click.Command):
    """Custom Click command with improved error handling."""

    def main(self, *args, **kwargs):
        try:
            return super().main(*args, **kwargs)
        except ConfigError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(e.exit_code)
        except AuthScanError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(e.exit_code)
        except click.Abort:
            sys.exit(255)


@click.command(
    cls=AuthScanCommand,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.argument("target", required=False, default="")
@click.option(
    "--modules",
    "-m",
    multiple=True,
    type=click.Choice(["probe", "jwt", "session", "brute", "oauth", "mfa", "websocket", "api_key", "all"]),
    help="Attack modules to run. Use 'all' for every module. Repeatable.",
)
@click.option(
    "--output",
    "-o",
    "output_formats",
    multiple=True,
    type=click.Choice(["terminal", "json", "markdown", "html", "pdf", "sarif"]),
    default=["terminal"],
    help="Output formats. Repeatable for multiple formats.",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to YAML config file.",
)
@click.option(
    "--profile",
    "-P",
    help="Named profile from config file.",
)
@click.option(
    "--quick",
    is_flag=True,
    help="Quick scan: probe + header checks only.",
)
@click.option(
    "--agentic",
    is_flag=True,
    help="Enable adaptive scanning (OODA loop).",
)
@click.option(
    "--max-depth",
    type=int,
    default=5,
    help="Agentic recursion depth (default: 5).",
)
@click.option(
    "--confidence-threshold",
    type=float,
    default=0.9,
    help="Agentic confidence threshold (default: 0.9, range: 0.0-1.0).",
)
@click.option(
    "--rate-limit",
    type=int,
    help="Requests per second (default: 10, range: 1-100).",
)
@click.option(
    "--timeout",
    type=int,
    help="Request timeout in seconds (default: 30).",
)
@click.option(
    "--proxy",
    help="Proxy URL (http://host:port or socks5://host:port).",
)
@click.option(
    "--cookie",
    "cookies_raw",
    multiple=True,
    help="Initial cookie in KEY=VALUE format (repeatable).",
)
@click.option(
    "--header",
    "headers_raw",
    multiple=True,
    help="Custom header in KEY=VALUE format (repeatable).",
)
@click.option(
    "--auth-type",
    type=click.Choice(["bearer", "basic", "form", "cookie"]),
    help="Authentication type for authenticated scanning.",
)
@click.option(
    "--username",
    help="Authentication username.",
)
@click.option(
    "--password",
    help="Authentication password.",
)
@click.option(
    "--token",
    help="Bearer token or API key for authenticated scanning.",
)
@click.option(
    "--wordlist",
    "-w",
    type=click.Path(exists=True, dir_okay=False),
    help="Password wordlist path.",
)
@click.option(
    "--user-wordlist",
    type=click.Path(exists=True, dir_okay=False),
    help="Username wordlist path.",
)
@click.option(
    "--scope",
    multiple=True,
    help="Allowed domain (repeatable). Default: target domain only.",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase verbosity (-v, -vv, -vvv).",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress all output except errors and summary.",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored terminal output.",
)
@click.option(
    "--no-redact",
    is_flag=True,
    help="Show secrets in output (DANGEROUS — for debugging only).",
)
@click.option(
    "--resume",
    "resume_scan_id",
    help="Resume a previous scan from checkpoint ID.",
)
@click.option(
    "--no-verify",
    is_flag=True,
    help="Disable TLS certificate verification.",
)
@click.option(
    "--ca-bundle",
    type=click.Path(exists=True, dir_okay=False),
    help="Custom CA bundle for TLS verification.",
)
@click.option(
    "--allow-http-fallback",
    is_flag=True,
    help=(
        "If HTTPS probe fails, retry over plain HTTP. DANGEROUS — auth "
        "headers, cookies, and credentials travel in plaintext. Disabled "
        "by default."
    ),
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False),
    default="./scan-results",
    help="Directory for file-based output (default: ./scan-results).",
)
@click.option(
    "--output-file",
    type=click.Path(dir_okay=False, writable=True, allow_dash=True),
    default=None,
    help=(
        "Write a single report to this exact path (or '-' for stdout). "
        "Requires exactly one --output format other than 'terminal'. "
        "Overrides --output-dir for that format."
    ),
)
@click.option(
    "--init",
    "init_config",
    is_flag=True,
    help="Generate a default config file and exit.",
)
@click.option(
    "--jwt-wordlist",
    type=click.Path(exists=True, dir_okay=False),
    help="Wordlist for JWT HMAC secret cracking (requires --jwt-crack).",
)
@click.option(
    "--jwt-crack",
    is_flag=True,
    help=(
        "Enable offline HMAC secret cracking against discovered JWTs. "
        "CPU-expensive; off by default. Tune --jwt-crack-max-attempts to "
        "cap effort per token."
    ),
)
@click.option(
    "--jwt-crack-max-attempts",
    type=int,
    default=5000,
    show_default=True,
    help="Maximum HMAC cracking attempts per token (requires --jwt-crack).",
)
@click.option(
    "--default-creds",
    "default_creds_path",
    type=click.Path(exists=True, dir_okay=False),
    help=(
        "Override the bundled default-credentials wordlist. File format is "
        "one 'user:password' pair per line; '#' comments and blank lines "
        "are ignored."
    ),
)
@click.option(
    "--no-discovery",
    is_flag=True,
    help="Skip path discovery phase.",
)
@click.option(
    "--no-mfa",
    is_flag=True,
    help="Skip MFA bypass tests.",
)
@click.option(
    "--oauth-scope",
    help="Test scope escalation with this scope value.",
)
@click.version_option(
    version=__version__,
    prog_name="auth-scan",
    message="%(prog)s v%(version)s",
)
@click.pass_context
def main(
    ctx: click.Context,
    target: str,
    modules: tuple[str, ...],
    output_formats: tuple[str, ...],
    config_path: str | None,
    profile: str | None,
    quick: bool,
    agentic: bool,
    max_depth: int,
    confidence_threshold: float,
    rate_limit: int | None,
    timeout: int | None,
    proxy: str | None,
    cookies_raw: tuple[str, ...],
    headers_raw: tuple[str, ...],
    auth_type: str | None,
    username: str | None,
    password: str | None,
    token: str | None,
    wordlist: str | None,
    user_wordlist: str | None,
    scope: tuple[str, ...],
    verbose: int,
    quiet: bool,
    no_color: bool,
    no_redact: bool,
    resume_scan_id: str | None,
    no_verify: bool,
    ca_bundle: str | None,
    allow_http_fallback: bool,
    output_dir: str,
    output_file: str | None,
    init_config: bool,
    jwt_wordlist: str | None,
    jwt_crack: bool,
    jwt_crack_max_attempts: int,
    default_creds_path: str | None,
    no_discovery: bool,
    no_mfa: bool,
    oauth_scope: str | None,
) -> None:
    """Web authentication security assessment tool.

    TARGET is the URL to scan (e.g., https://example.com).

    \b
    Examples:
      auth-scan https://example.com
      auth-scan example.com --quick
      auth-scan https://app.example.com --modules jwt session --output json
      auth-scan https://app.example.com --config auth-scan-config.yml --profile ci-pipeline
      auth-scan --init
    """
    # --init: generate config and exit
    if init_config:
        path = generate_default_config()
        click.echo(f"Default config written to: {path}")
        return

    # TARGET is required for scanning
    if not target:
        click.echo("Error: Missing argument 'TARGET'.", err=True)
        click.echo("Usage: auth-scan [OPTIONS] TARGET", err=True)
        sys.exit(2)

    # Build ScanConfig from multiple sources
    try:
        # Parse cookies and headers from CLI
        cookies_dict: dict[str, str] = {}
        for c in cookies_raw:
            if "=" in c:
                k, v = c.split("=", 1)
                cookies_dict[k.strip()] = v.strip()

        headers_dict: dict[str, str] = {}
        for h in headers_raw:
            if "=" in h:
                k, v = h.split("=", 1)
                headers_dict[k.strip()] = v.strip()

        # Load config (file + profile + env vars)
        config = load_config(
            config_path=config_path,
            profile=profile,
        )

        # Override with CLI flags
        config.target = target
        config.quick = quick or config.quick
        config.output_dir = output_dir
        if output_file is not None:
            config.output_file = output_file

        if modules:
            config.modules = list(modules)
        if "all" in config.modules:
            config.modules = all_module_names()

        if output_formats and output_formats != ("terminal",):
            config.output_formats = list(output_formats)

        if rate_limit is not None:
            config.rate_limit = rate_limit
        if timeout is not None:
            config.timeout = timeout
        if proxy is not None:
            config.proxy = proxy
        if no_verify:
            config.no_verify = True
        if ca_bundle is not None:
            config.ca_bundle = ca_bundle
        if allow_http_fallback:
            config.allow_http_fallback = True
        if cookies_dict:
            config.cookies.update(cookies_dict)
        if headers_dict:
            config.headers.update(headers_dict)
        if auth_type is not None:
            config.auth_type = auth_type
        if username is not None:
            config.auth_credentials["username"] = username
        if password is not None:
            config.auth_credentials["password"] = password
        if token is not None:
            config.auth_credentials["token"] = token
        if scope:
            config.scope_allow = list(scope)
        if wordlist:
            config.wordlist = wordlist
        if user_wordlist:
            config.user_wordlist = user_wordlist
        if agentic:
            config.agentic = True
        if max_depth != 5:
            config.max_depth = max_depth
        if confidence_threshold != 0.9:
            config.confidence_threshold = confidence_threshold
        if resume_scan_id:
            config.resume_scan_id = resume_scan_id

        config.no_redact = no_redact
        config.no_color = no_color
        config.verbose = verbose
        config.quiet = quiet

        # Phase 2 flags
        if jwt_wordlist:
            config.jwt_wordlist = jwt_wordlist
        if jwt_crack:
            config.jwt_crack = True
        if jwt_crack_max_attempts != 5000:
            config.jwt_crack_max_attempts = jwt_crack_max_attempts
        if default_creds_path:
            config.default_creds_path = default_creds_path
        if no_discovery:
            config.no_discovery = True
        if no_mfa:
            config.no_mfa = True
        if oauth_scope:
            config.oauth_scope = oauth_scope

        # Validate
        config.validate()

    except ConfigError as e:
        click.echo(f"Configuration error: {e}", err=True)
        sys.exit(e.exit_code)

    # Print header
    if not config.quiet:
        from rich.console import Console

        console = Console(no_color=config.no_color)
        console.print()
        console.print(
            f"[bold blue]auth-scan[/bold blue] v{__version__} — Web Authentication Security Scanner"
        )
        console.print(f"Target: {config.target}")
        mods = config.modules.copy()
        if "probe" in mods:
            mods.remove("probe")
        console.print(f"Modules: {', '.join(mods) if mods else 'probe only'}")
        if config.quick:
            console.print("[yellow]Quick mode: probe + header checks only[/yellow]")
        if config.agentic:
            console.print("[cyan]Agentic mode enabled[/cyan]")
        console.print()

    # Run the scan
    try:
        report = run_assessment(config)
    except AuthScanError as e:
        click.echo(f"Scan failed: {e}", err=True)
        sys.exit(e.exit_code)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(255)

    # Validate --output-file usage. It only makes sense with exactly one
    # non-terminal format (you can't write JSON + HTML to one file).
    non_terminal = [f for f in config.output_formats if f != "terminal"]
    if config.output_file and len(non_terminal) != 1:
        click.echo(
            "Error: --output-file requires exactly one --output format "
            f"other than 'terminal' (got: {non_terminal or ['(none)']}).",
            err=True,
        )
        sys.exit(2)

    # Generate reports
    reporter = Reporter(
        output_formats=config.output_formats,
        no_redact=config.no_redact,
    )

    saved_paths = reporter.render(
        report=report,
        endpoints_tested=0,  # TODO: track from engine
        output_dir=config.output_dir,
        target=config.target,
        output_file=config.output_file or None,
    )

    # Print file output paths
    if not config.quiet:
        from rich.console import Console

        console = Console(no_color=config.no_color)
        for fmt, path in saved_paths.items():
            if fmt != "terminal" and not path.startswith("error"):
                console.print(f"[dim]Report saved: {path}[/dim]")

    # Exit with appropriate code
    sys.exit(report.exit_code)


if __name__ == "__main__":
    main()
