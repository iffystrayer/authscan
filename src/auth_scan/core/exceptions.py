"""auth-scan custom exceptions."""


class AuthScanError(Exception):
    """Base exception for all auth-scan errors."""

    exit_code: int = 255
    message: str = "An unknown error occurred"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.message
        super().__init__(self.message)


class HttpError(AuthScanError):
    """HTTP-level errors (connectivity, TLS, timeouts)."""

    exit_code = 255


class ModuleError(AuthScanError):
    """Error within an attack module (non-fatal — scan continues)."""

    exit_code = 1


class ConfigError(AuthScanError):
    """Configuration-related errors (invalid YAML, bad values)."""

    exit_code = 255


class ScopeError(AuthScanError):
    """Request blocked by scope enforcement."""

    exit_code = 1


class RateLimitError(AuthScanError):
    """Rate limiter saturated beyond recovery."""

    exit_code = 1


class TargetError(AuthScanError):
    """Invalid or unreachable target."""

    exit_code = 255


class ReporterError(AuthScanError):
    """Report generation failure."""

    exit_code = 255
