"""HTTP client with session management, retry, proxy, rate limiting, and scope enforcement."""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from auth_scan.core.exceptions import HttpError, ScopeError

# Maximum number of redirects we will follow manually. Mirrors the requests
# default but lets us re-check scope between hops.
MAX_REDIRECTS = 10

# Cloud metadata endpoints — IMDS (AWS / GCP / Azure / DigitalOcean / Alibaba).
# Any redirect to these hosts is a strong SSRF signal and is always blocked.
CLOUD_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",  # AWS / GCP / Azure / DO / OCI / Alibaba
        "metadata.google.internal",
        "metadata.azure.com",
        "instance-data",
        "fd00:ec2::254",  # AWS IMDSv2 IPv6
    }
)

_log = logging.getLogger(__name__)


def _is_private_or_metadata_host(host: str) -> bool:
    """Return True if `host` resolves to a private, loopback, link-local,
    or cloud-metadata address. Used to block SSRF via redirect.

    Pure-name matches (CLOUD_METADATA_HOSTS) short-circuit DNS. Otherwise
    we rely on `ipaddress` for literal IPs and `socket.getaddrinfo` for
    names. DNS failures are treated as *not* private — the subsequent
    request will fail loudly on its own.
    """
    if not host:
        return False
    if host.lower() in CLOUD_METADATA_HOSTS:
        return True
    # Strip brackets from IPv6 literals.
    candidate = host.strip("[]")
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        # Hostname — resolve and check all returned addresses.
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError:
            return False
        for info in infos:
            sockaddr = info[4]
            addr = sockaddr[0]
            try:
                resolved = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if _ip_is_blocked(resolved):
                return True
        return False
    return _ip_is_blocked(ip)


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True for loopback / link-local / private / reserved / multicast."""
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


@dataclass
class RateLimiter:
    """Token bucket rate limiter."""

    rate: float  # requests per second
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)

    def __post_init__(self) -> None:
        self._tokens = self.rate
        self._last_refill = time.monotonic()

    def acquire(self) -> float:
        """Wait until a token is available. Returns the delay."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
        self._last_refill = now

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return 0.0

        wait_time = (1.0 - self._tokens) / self.rate
        time.sleep(wait_time)
        self._tokens = 0.0
        self._last_refill = time.monotonic()
        return wait_time


@dataclass
class ScopeEnforcer:
    """Enforces domain/IP allowlist and denylist for outbound requests."""

    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    strict: bool = True  # When True, reject unlisted hosts

    def is_allowed(self, url: str) -> bool:
        """Check if a URL is within the allowed scope."""
        if not self.allowlist and not self.denylist:
            return True

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Denylist takes precedence
        for denied in self.denylist:
            if self._host_matches(hostname, denied):
                return False

        # If allowlist is defined, must match
        if self.allowlist:
            for allowed in self.allowlist:
                if self._host_matches(hostname, allowed):
                    return True
            return False

        return True

    @staticmethod
    def _host_matches(hostname: str, pattern: str) -> bool:
        """Check if hostname matches a pattern (exact, subdomain, or dot-prefix match)."""
        if hostname == pattern:
            return True
        # ".example.com" matches "example.com" and all subdomains
        if pattern.startswith("."):
            if hostname == pattern[1:] or hostname.endswith(pattern):
                return True
        if hostname.endswith("." + pattern):
            return True
        return False


@dataclass
class RequestRecord:
    """Metadata for a single HTTP request.

    Response headers and body preview are scrubbed at capture time (M7).
    The preview is capped at ``BODY_PREVIEW_BYTES``; the full body's
    ``response_body_length`` and SHA-256 fingerprint are kept so analyses
    that need to correlate without seeing the bytes still can.
    """

    request_id: str
    method: str
    url: str
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""
    response_body_length: int = 0
    response_body_sha256: str = ""
    duration_ms: float = 0.0
    error: str | None = None


# Maximum captured body preview in request history. Mirrors the cap in
# ``base.PROBE_BODY_PREVIEW_BYTES`` so memory pressure is bounded
# regardless of which path serializes a record. M7.
BODY_PREVIEW_BYTES = 4096


@dataclass
class ProbeResult:
    """Results from the initial probe request."""

    url: str
    final_url: str
    status_code: int | None
    headers: dict[str, str]
    cookies: dict[str, str]
    body: str
    body_length: int
    forms: list[dict[str, Any]]
    tls_version: str | None
    request_id: str
    redirect_chain: list[str]
    duration_ms: float
    # True if the probe fell back from HTTPS to plain HTTP. Engine emits a
    # MEDIUM finding when this is set; opt-in via HTTPClient(
    # allow_http_fallback=True).
    http_fallback_attempted: bool = False


class HTTPClient:
    """Session-aware HTTP client wrapping requests.Session.

    Features:
    - Retry logic with exponential backoff
    - Proxy support (HTTP, HTTPS, SOCKS5)
    - TLS verification toggle and custom CA bundle
    - Token-bucket rate limiting
    - Scope enforcement (domain/IP allow/denylist)
    - Request ID generation (UUID4 per request)
    - Configurable timeouts
    """

    def __init__(
        self,
        base_url: str,
        proxy: str | None = None,
        verify_ssl: bool = True,
        ca_bundle: str | None = None,
        max_retries: int = 3,
        rate_limit: float = 10.0,
        timeout: int = 30,
        scope_allow: list[str] | None = None,
        scope_deny: list[str] | None = None,
        user_agent: str = "auth-scan/0.1.0",
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        allow_private_redirects: bool = False,
        allow_http_fallback: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.allow_private_redirects = allow_private_redirects
        self.allow_http_fallback = allow_http_fallback

        self.session = requests.Session()
        self.rate_limiter = RateLimiter(rate=rate_limit)
        self.scope_enforcer = ScopeEnforcer(
            allowlist=scope_allow or [],
            denylist=scope_deny or [],
        )

        # Proxy
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # TLS
        self.session.verify = verify_ssl
        if ca_bundle:
            self.session.verify = ca_bundle

        # Retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # Default headers
        self.session.headers["User-Agent"] = user_agent
        if headers:
            self.session.headers.update(headers)

        # Initial cookies
        if cookies:
            for name, value in cookies.items():
                self.session.cookies.set(name, value)

        # Request tracking
        self.request_history: list[RequestRecord] = []

    def _build_url(self, path: str) -> str:
        """Resolve a path or full URL against the base URL."""
        if path.startswith(("http://", "https://")):
            return path
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def _generate_request_id(self) -> str:
        """Generate a unique request ID."""
        return str(uuid.uuid4())

    def _check_scope(self, url: str) -> None:
        """Enforce scope rules, raising ScopeError if blocked."""
        if not self.scope_enforcer.is_allowed(url):
            raise ScopeError(f"Request blocked by scope enforcement: {url}")

    def _check_redirect_target(self, url: str) -> None:
        """Validate a redirect target before following it.

        Raises ScopeError if the destination is out of the configured scope
        or, by default, resolves to a private / loopback / link-local /
        cloud-metadata address. Set ``allow_private_redirects=True`` on the
        client to disable the private-address check (useful when scanning
        an internal target on purpose).
        """
        self._check_scope(url)
        if self.allow_private_redirects:
            return
        host = urlparse(url).hostname or ""
        if _is_private_or_metadata_host(host):
            raise ScopeError(f"Refusing to follow redirect to private/metadata host: {url}")

    def _follow_redirects(
        self,
        response: requests.Response,
        method: str,
        request_kwargs: dict[str, Any],
    ) -> tuple[requests.Response, list[str]]:
        """Follow redirects manually, checking scope at every hop.

        Returns (final_response, redirect_chain). The chain is a list of
        ``"from -> to"`` strings for the report. Each hop is rate-limited
        and goes through _check_redirect_target. RFC 7231/7538 semantics
        for status codes apply: 301/302/303 demote POST→GET, 307/308
        preserve the method.
        """
        chain: list[str] = []
        hops = 0
        while response.is_redirect or response.is_permanent_redirect:
            if hops >= MAX_REDIRECTS:
                raise HttpError(f"Exceeded max redirects ({MAX_REDIRECTS}); last URL: {response.url}")
            location = response.headers.get("Location")
            if not location:
                break
            next_url = urljoin(response.url, location)
            self._check_redirect_target(next_url)
            chain.append(f"{response.url} -> {next_url}")

            # RFC 7231 §6.4.{2,3,4}: 301/302/303 should switch to GET and
            # drop the body. 307/308 preserve method and body.
            next_method = method
            next_kwargs = dict(request_kwargs)
            if response.status_code in (301, 302, 303):
                next_method = "GET"
                next_kwargs.pop("data", None)
                next_kwargs.pop("json", None)

            self.rate_limiter.acquire()
            response = self.session.request(
                method=next_method,
                url=next_url,
                allow_redirects=False,
                **next_kwargs,
            )
            hops += 1
        return response, chain

    def _record_request(
        self,
        request_id: str,
        method: str,
        url: str,
        response: requests.Response | None = None,
        error: str | None = None,
        duration_ms: float = 0.0,
    ) -> RequestRecord:
        """Record request metadata for audit trail.

        Response headers are scrubbed via the shared ``_redact_dict``
        helper at capture time so the in-memory history can never leak
        Authorization / Set-Cookie / similar tokens, even if the operator
        later dumps it. The body preview is capped at
        ``BODY_PREVIEW_BYTES`` and also value-shape redacted; full-body
        bytes are not retained, but length + sha256 are.
        """
        # Import locally to avoid a circular module dependency at top of file.
        import hashlib as _hashlib

        from auth_scan.attacks.base import _redact_dict, _redact_value

        record = RequestRecord(
            request_id=request_id,
            method=method,
            url=url,
            duration_ms=duration_ms,
            error=error,
        )
        if response is not None:
            record.status_code = response.status_code
            record.response_headers = _redact_dict(dict(response.headers))
            body = response.text or ""
            encoded = body.encode("utf-8", errors="ignore")
            record.response_body_length = len(encoded)
            if encoded:
                record.response_body_sha256 = _hashlib.sha256(encoded).hexdigest()
            preview = body[:BODY_PREVIEW_BYTES]
            record.response_body_preview = _redact_value(preview) if preview else ""
        self.request_history.append(record)
        return record

    def request(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
        timeout: int | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Make an HTTP request with rate limiting and scope enforcement.

        Redirects are followed manually so we can re-check scope and block
        private/loopback/cloud-metadata targets between hops. Pass
        ``allow_redirects=False`` to disable redirect-following entirely.
        """
        url = self._build_url(path)
        request_id = self._generate_request_id()

        # Scope check
        self._check_scope(url)

        # Rate limit
        self.rate_limiter.acquire()

        # Merge headers
        req_headers: dict[str, str] = {"X-Request-ID": request_id}
        if headers:
            req_headers.update(headers)

        request_kwargs: dict[str, Any] = {
            "data": data,
            "json": json,
            "headers": req_headers,
            "timeout": timeout or self.timeout,
            **kwargs,
        }

        start_time = time.monotonic()
        try:
            response = self.session.request(
                method=method,
                url=url,
                allow_redirects=False,
                **request_kwargs,
            )
            if allow_redirects:
                response, _chain = self._follow_redirects(response, method, request_kwargs)
            duration_ms = (time.monotonic() - start_time) * 1000
            self._record_request(request_id, method, url, response=response, duration_ms=duration_ms)
            return response
        except requests.exceptions.Timeout as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            self._record_request(request_id, method, url, error=f"Timeout: {e}", duration_ms=duration_ms)
            raise HttpError(f"Request timed out after {self.timeout}s: {url}") from e
        except requests.exceptions.ConnectionError as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            self._record_request(
                request_id, method, url, error=f"Connection error: {e}", duration_ms=duration_ms
            )
            raise HttpError(f"Connection failed: {url} - {e}") from e
        except requests.exceptions.SSLError as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            self._record_request(request_id, method, url, error=f"TLS error: {e}", duration_ms=duration_ms)
            raise HttpError(f"TLS verification failed: {url} - {e}") from e

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        """Convenience GET request."""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> requests.Response:
        """Convenience POST request."""
        return self.request("POST", path, **kwargs)

    def head(self, path: str, **kwargs: Any) -> requests.Response:
        """Convenience HEAD request."""
        return self.request("HEAD", path, **kwargs)

    def options(self, path: str, **kwargs: Any) -> requests.Response:
        """Convenience OPTIONS request."""
        return self.request("OPTIONS", path, **kwargs)

    def probe(self) -> ProbeResult:
        """Perform the initial probe request and extract metadata.

        Catches both `HttpError` and `requests.exceptions.RequestException`
        on the HTTPS path; the previous code caught only HttpError, which
        the session.get() call never raises directly (H3).

        HTTPS-to-HTTP fallback is gated on `allow_http_fallback` (default
        False — H4). When fallback succeeds, ``http_fallback_attempted``
        is set on the returned ProbeResult and a console warning is
        emitted; the engine converts that into a MEDIUM finding.
        """
        import logging

        from bs4 import BeautifulSoup

        log = logging.getLogger(__name__)
        request_id = self._generate_request_id()
        url = self.base_url  # probe the exact target URL, not always /

        redirect_chain: list[str] = []
        final_url = url
        http_fallback_attempted = False

        start_time = time.monotonic()
        try:
            # Direct request to base_url to avoid urljoin quirks. We disable
            # automatic redirect-following on the underlying session and
            # follow manually so each hop goes through scope/private-host
            # checks (C5).
            self._check_scope(url)
            self.rate_limiter.acquire()
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            response, manual_chain = self._follow_redirects(response, "GET", {"timeout": self.timeout})
            redirect_chain.extend(manual_chain)
        except (HttpError, requests.exceptions.RequestException) as primary_err:
            # H4: fallback is OFF by default. The previous behaviour silently
            # downgraded auth headers, cookies, and credentials onto plain
            # HTTP. Operators must now opt in.
            if not url.startswith("https://"):
                # Not an HTTPS probe — nothing to fall back to.
                if isinstance(primary_err, HttpError):
                    raise
                raise HttpError(f"Failed to probe target: {url} - {primary_err}") from primary_err
            if not self.allow_http_fallback:
                raise HttpError(
                    f"HTTPS probe failed for {url}: {primary_err}. "
                    "Plain-HTTP fallback is disabled by default; re-run with "
                    "allow_http_fallback=True (CLI: --allow-http-fallback) "
                    "to override at your own risk."
                ) from primary_err

            fallback = url.replace("https://", "http://", 1)
            log.warning(
                "HTTPS probe failed; falling back to HTTP — auth material "
                "will travel in plaintext. original=%s fallback=%s err=%s",
                url,
                fallback,
                primary_err,
            )
            self._check_scope(fallback)
            self.rate_limiter.acquire()
            try:
                response = self.session.get(fallback, timeout=self.timeout, allow_redirects=False)
                response, manual_chain = self._follow_redirects(response, "GET", {"timeout": self.timeout})
                redirect_chain.append(f"{url} -> {fallback}")
                redirect_chain.extend(manual_chain)
                final_url = fallback
                http_fallback_attempted = True
            except (HttpError, requests.exceptions.RequestException) as e:
                raise HttpError(f"Failed to probe target: {url} - {e}") from e

        final_url = response.url

        # Extract forms
        forms: list[dict[str, Any]] = []
        try:
            soup = BeautifulSoup(response.text, "lxml")
            for form in soup.find_all("form"):
                form_data: dict[str, Any] = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "inputs": [],
                }
                for inp in form.find_all(["input", "select", "textarea"]):
                    form_data["inputs"].append(
                        {
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        }
                    )
                forms.append(form_data)
        except Exception as exc:
            _log.debug("swallowed: %s", exc)

        # Determine TLS version from the final URL
        tls_version = None
        if final_url.startswith("https://"):
            raw_sock = getattr(response.raw, "_connection", None)
            if raw_sock and hasattr(raw_sock, "sock"):
                sock = raw_sock.sock
                if hasattr(sock, "version"):
                    tls_version = sock.version()

        return ProbeResult(
            url=url,
            final_url=final_url,
            status_code=response.status_code,
            headers=dict(response.headers),
            cookies=dict(response.cookies),
            body=response.text,
            body_length=len(response.content),
            forms=forms,
            tls_version=tls_version,
            request_id=request_id,
            redirect_chain=redirect_chain,
            duration_ms=(time.monotonic() - start_time) * 1000,
            http_fallback_attempted=http_fallback_attempted,
        )

    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()
