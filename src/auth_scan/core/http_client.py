"""HTTP client with session management, retry, proxy, rate limiting, and scope enforcement."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from auth_scan.core.exceptions import HttpError, ScopeError


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
    """Metadata for a single HTTP request."""

    request_id: str
    method: str
    url: str
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""
    duration_ms: float = 0.0
    error: str | None = None


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
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

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

    def _record_request(
        self,
        request_id: str,
        method: str,
        url: str,
        response: requests.Response | None = None,
        error: str | None = None,
        duration_ms: float = 0.0,
    ) -> RequestRecord:
        """Record request metadata for audit trail."""
        record = RequestRecord(
            request_id=request_id,
            method=method,
            url=url,
            duration_ms=duration_ms,
            error=error,
        )
        if response is not None:
            record.status_code = response.status_code
            record.response_headers = dict(response.headers)
            record.response_body_preview = response.text[:500] if response.text else ""
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
        """Make an HTTP request with rate limiting and scope enforcement."""
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

        start_time = time.monotonic()
        try:
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                json=json,
                headers=req_headers,
                allow_redirects=allow_redirects,
                timeout=timeout or self.timeout,
                **kwargs,
            )
            duration_ms = (time.monotonic() - start_time) * 1000
            self._record_request(request_id, method, url, response=response, duration_ms=duration_ms)
            return response
        except requests.exceptions.Timeout as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            self._record_request(request_id, method, url, error=f"Timeout: {e}", duration_ms=duration_ms)
            raise HttpError(f"Request timed out after {self.timeout}s: {url}") from e
        except requests.exceptions.ConnectionError as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            self._record_request(request_id, method, url, error=f"Connection error: {e}", duration_ms=duration_ms)
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
        """Perform the initial probe request and extract metadata."""
        from bs4 import BeautifulSoup

        request_id = self._generate_request_id()
        url = self.base_url  # probe the exact target URL, not always /

        redirect_chain: list[str] = []
        final_url = url

        start_time = time.monotonic()
        try:
            # Direct request to base_url to avoid urljoin quirks
            self.rate_limiter.acquire()
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except HttpError:
            # Try HTTP fallback
            if url.startswith("https://"):
                fallback = url.replace("https://", "http://", 1)
                self.rate_limiter.acquire()
                try:
                    response = self.session.get(fallback, timeout=self.timeout)
                    redirect_chain.append(f"{url} -> {fallback}")
                    final_url = fallback
                except Exception as e:
                    raise HttpError(f"Failed to probe target: {url} - {e}") from e
            else:
                raise

        final_url = response.url
        if response.history:
            for r in response.history:
                redirect_chain.append(f"{r.url} -> {r.headers.get('Location', 'unknown')}")

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
                    form_data["inputs"].append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                forms.append(form_data)
        except Exception:
            pass

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
        )

    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()
