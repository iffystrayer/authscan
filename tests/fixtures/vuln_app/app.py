"""
Deliberately vulnerable Flask application for testing auth-scan.

DO NOT DEPLOY PUBLICLY — this app contains intentional security flaws.

Vulnerabilities:
- Default credentials (admin:admin, user:password)
- JWT signed with weak HS256 secret ("weak-secret-12345")
- JWT endpoint accepts alg=none (no signature verification)
- Session cookies missing HttpOnly, Secure, SameSite flags
- No CSRF protection on forms
- Session fixation (pre-auth session ID accepted after login)
- Session not invalidated on logout
- User enumeration via distinct error messages
- No rate limiting on /login
- Sensitive data in JWT payload (email, role)
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- OAuth open redirect in /oauth/authorize
- OAuth implicit flow supported
- OAuth no PKCE enforcement
- MFA bypass via parameter pollution
- WebSocket token in URL
- Exposed API keys in page source (/config)
- Accessible paths: /api, /admin, /backup, .well-known endpoints
"""

import datetime
import hashlib
import hmac
import json
import os
import uuid
from functools import wraps

from flask import Flask, jsonify, make_response, redirect, render_template_string, request, session

app = Flask(__name__)

# WEAK: Hardcoded, weak secret key
app.secret_key = "super-secret-key-that-is-not-random-123"
app.config["SESSION_COOKIE_HTTPONLY"] = False  # VULN: No HttpOnly
app.config["SESSION_COOKIE_SECURE"] = False  # VULN: No Secure
app.config["SESSION_COOKIE_SAMESITE"] = None  # VULN: No SameSite

# WEAK: Hardcoded JWT secret
JWT_SECRET = "weak-secret-12345"

# WEAK: Hardcoded credentials
USERS = {
    "admin": "admin",
    "user": "password",
    "test": "test",
    "guest": "guest",
}

# "Database" of valid sessions (WEAK: stored in memory, no invalidation)
ACTIVE_SESSIONS: dict[str, str] = {}

# ── Templates ──────────────────────────────────────────────────

LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Login - TestApp</title></head>
<body>
    <h1>Login</h1>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <button type="submit">Login</button>
    </form>
    <p><a href="/register">Register</a></p>
</body>
</html>"""

DASHBOARD_PAGE = """<!DOCTYPE html>
<html>
<head><title>Dashboard - TestApp</title></head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p>Your email: {{ email }}</p>
    <p>Your role: {{ role }}</p>
    <p>Your session ID: <code>{{ session_id }}</code></p>
    <p><a href="/profile">View Profile</a></p>
    <p><a href="/logout?sessionid={{ session_id }}">Logout</a></p>
</body>
</html>"""

PROFILE_PAGE = """<!DOCTYPE html>
<html>
<head><title>Profile - TestApp</title></head>
<body>
    <h1>Update Profile</h1>
    <form method="POST" action="/profile">
        <input type="text" name="email" placeholder="Email"><br>
        <input type="text" name="display_name" placeholder="Display Name"><br>
        <button type="submit">Update</button>
    </form>
    <p><a href="/dashboard">Back to Dashboard</a></p>
</body>
</html>"""

REGISTER_PAGE = """<!DOCTYPE html>
<html>
<head><title>Register - TestApp</title></head>
<body>
    <h1>Register</h1>
    <form method="POST" action="/register">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <button type="submit">Register</button>
    </form>
</body>
</html>"""


# ── JWT Helper Functions ───────────────────────────────────────


def base64url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def base64url_decode(data: str) -> bytes:
    import base64

    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# ── JWT Handling — DELIBERATELY VULNERABLE ─────────────────────


def create_jwt(payload: dict) -> str:
    """Create a JWT with HS256 signing."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_jwt(token: str) -> dict | None:
    """Verify a JWT — VULNERABLE: accepts alg=none and weak secrets."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        alg = header.get("alg", "HS256")

        # VULN: Accept alg=none without signature verification
        if alg == "none":
            return payload

        # Normal verification (weak HS256)
        if alg == "HS256":
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            expected_sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
            actual_sig = base64url_decode(parts[2])
            if hmac.compare_digest(expected_sig, actual_sig):
                return payload

        # VULN: Key confusion — also accept HS256 with public key equivalent
        # In a real attack, this is where the public key could be used as HMAC secret

        # Check expiry
        exp = payload.get("exp")
        if exp:
            exp_time = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
            if exp_time < datetime.datetime.now(datetime.timezone.utc):
                # VULN: Doesn't reject expired tokens by default
                pass

        return None
    except Exception:
        return None


# ── Decorators ─────────────────────────────────────────────────


def login_required(f):
    """Decorator that checks for a valid session or JWT."""

    @wraps(f)
    def decorated(*args, **kwargs):
        # Check session cookie
        if "user" in session:
            return f(*args, **kwargs)

        # Check Authorization header for JWT
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            payload = verify_jwt(token)
            if payload and "sub" in payload:
                return f(*args, **kwargs)

        return jsonify({"error": "Unauthorized"}), 401

    return decorated


def jwt_optional(f):
    """Allow access but parse JWT if present."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if token:
            payload = verify_jwt(token)
            request.jwt_payload = payload  # type: ignore[attr-defined]
        else:
            request.jwt_payload = None  # type: ignore[attr-defined]
        return f(*args, **kwargs)

    return decorated


# ── Routes ─────────────────────────────────────────────────────


@app.route("/")
def index():
    """Home page — redirects based on auth state."""
    if "user" in session:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login endpoint — VULNERABLE: user enumeration, no rate limiting, weak error handling."""
    if request.method == "GET":
        return LOGIN_PAGE

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        # VULN: Distinct error messages for missing vs invalid
        return "Error: Username is required", 400

    if username not in USERS:
        # VULN: User enumeration — tells attacker the user doesn't exist
        return "Error: Username not found", 401

    if USERS[username] != password:
        # VULN: User enumeration — different message for wrong password
        return "Error: Incorrect password", 401

    # VULN: Session fixation — does not regenerate session ID on login
    session["user"] = username
    session["role"] = "admin" if username == "admin" else "user"

    # Create JWT with sensitive data (VULN)
    jwt_token = create_jwt(
        {
            "sub": username,
            "email": f"{username}@example.com",  # VULN: PII in JWT
            "role": session["role"],
            "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "exp": int(
                (
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
                ).timestamp()
            ),  # VULN: Long expiry (30 days)
        }
    )

    resp = make_response(redirect("/dashboard"))
    resp.set_cookie(
        "auth_token",
        jwt_token,
        httponly=False,  # VULN: No HttpOnly
        secure=False,  # VULN: No Secure
        samesite=None,  # VULN: No SameSite
        max_age=30 * 24 * 3600,  # VULN: 30 day session
    )
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    """Registration endpoint — VULNERABLE: no password policy, user enumeration."""
    if request.method == "GET":
        return REGISTER_PAGE

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        return "Error: All fields required", 400

    if username in USERS:
        # VULN: User enumeration at registration
        return "Error: Username already exists", 409

    USERS[username] = password
    return redirect("/login")


@app.route("/dashboard")
@login_required
def dashboard():
    """Dashboard — VULNERABLE: displays session ID in page."""
    username = session.get("user", "unknown")
    email = f"{username}@example.com"
    role = session.get("role", "user")
    session_id = request.cookies.get("session", "unknown")
    # VULN: Session ID displayed on page (leaked to DOM)
    return render_template_string(
        DASHBOARD_PAGE,
        username=username,
        email=email,
        role=role,
        session_id=session_id,
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():
    """Profile page — VULNERABLE: no CSRF protection on POST, session ID in URL."""
    if request.method == "GET":
        # VULN: Session ID in URL redirect
        if "user" not in session:
            session_id = request.cookies.get("session", str(uuid.uuid4()))
            return redirect(f"/login?sessionid={session_id}")
        return PROFILE_PAGE

    # POST — VULN: No CSRF token check
    email = request.form.get("email", "")
    display_name = request.form.get("display_name", "")
    return f"Profile updated: {email}, {display_name}"


@app.route("/logout")
def logout():
    """Logout — VULN: does not invalidate session server-side."""
    # VULN: Session ID in URL parameter
    request.args.get("sessionid", "")
    # VULN: Only clears client-side cookie, not server-side session
    session.pop("user", None)
    resp = make_response(redirect("/login"))
    # VULN: Does not clear or invalidate auth_token cookie
    return resp


@app.route("/api/profile")
@jwt_optional
@login_required
def api_profile():
    """API endpoint — VULNERABLE: JWT with sensitive data."""
    username = session.get("user", "unknown")
    getattr(request, "jwt_payload", None)

    response_data = {
        "username": username,
        "email": f"{username}@example.com",  # VULN: PII in API response
        "role": session.get("role", "user"),
        "internal_id": hash(username) % 10000,  # VULN: Internal IDs exposed
    }

    return jsonify(response_data)


@app.route("/api/user")
@login_required
def api_user():
    """User info endpoint — VULN: returns sensitive data."""
    username = session.get("user", "unknown")
    return jsonify(
        {
            "username": username,
            "email": f"{username}@example.com",
            "role": session.get("role", "user"),
            "password_hash": "not-a-real-hash-but-exposed",  # VULN: password field in response
        }
    )


# ── OAuth 2.0 Stubs (Phase 2) ─────────────────────────────────


@app.route("/oauth/authorize")
def oauth_authorize():
    """OAuth authorization endpoint — VULNERABLE: no state validation, open redirect."""
    redirect_uri = request.args.get("redirect_uri", "/dashboard")
    response_type = request.args.get("response_type", "code")
    client_id = request.args.get("client_id", "unknown")
    state = request.args.get("state", "")

    # VULN: No state validation — accepts requests without state
    # VULN: No redirect_uri validation — redirects anywhere
    if response_type == "token":
        # VULN: Implicit flow supported
        return redirect(f"{redirect_uri}#access_token=fake-implicit-token&token_type=bearer")

    # VULN: Open redirect — accepts any redirect_uri
    code = f"auth-code-{client_id}-{hash(redirect_uri) % 10000}"
    sep = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{sep}code={code}&state={state}")


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    """OAuth token endpoint — VULN: accepts any code, no PKCE check."""
    request.form.get("grant_type", "")
    # VULN: No client authentication
    # VULN: No code_verifier/PKCE check
    return jsonify(
        {
            "access_token": "fake-access-token-for-testing",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "fake-refresh-token",
            "scope": "openid profile email admin",
        }
    )


@app.route("/.well-known/openid-configuration")
def oidc_configuration():
    """OIDC discovery endpoint — exposes OAuth endpoints."""
    base = request.host_url.rstrip("/")
    return jsonify(
        {
            "issuer": f"{base}",
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "userinfo_endpoint": f"{base}/api/user",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": ["authorization_code", "implicit"],
            "code_challenge_methods_supported": ["S256"],
        }
    )


@app.route("/.well-known/jwks.json")
def jwks_endpoint():
    """JWKS endpoint stub."""
    return jsonify({"keys": []})


# ── MFA Stubs (Phase 2) ───────────────────────────────────────

MFA_PAGE = """<!DOCTYPE html>
<html>
<head><title>MFA Verification - TestApp</title></head>
<body>
    <h1>Two-Factor Authentication</h1>
    <p>Enter your 6-digit TOTP code:</p>
    <form method="POST" action="/mfa/verify">
        <input type="text" name="code" placeholder="000000" maxlength="6"><br>
        <input type="hidden" name="mfa_required" value="true">
        <button type="submit">Verify</button>
    </form>
    <p><a href="/mfa/verify?bypass=1">Use backup code</a></p>
</body>
</html>"""


@app.route("/mfa")
def mfa_page():
    """MFA page — VULNERABLE: bypassable, no rate limiting."""
    return MFA_PAGE


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    """MFA verification — VULNERABLE: accepts bypass params, no rate limiting."""
    # VULN: Parameter pollution bypass
    if request.args.get("bypass") == "1" or request.form.get("skip_mfa") == "1":
        session["mfa_verified"] = True
        return redirect("/dashboard")

    if request.method == "GET":
        return MFA_PAGE

    code = request.form.get("code", "")

    # VULN: Accepts any 6-digit code (should validate against TOTP)
    if len(code) == 6 and code.isdigit():
        session["mfa_verified"] = True
        return redirect("/dashboard")

    return "Invalid MFA code. Try again.", 401


# ── WebSocket Stub (Phase 2) ──────────────────────────────────
# Note: Requires flask-sock for real WebSocket support.
# This route shows the WS detection page.

WS_PAGE = """<!DOCTYPE html>
<html>
<head><title>WebSocket Test - TestApp</title></head>
<body>
    <h1>WebSocket Echo Test</h1>
    <div id="output"></div>
    <script>
        // VULN: Token in URL
        var ws = new WebSocket("ws://localhost:5555/ws/echo?token=fake-ws-token");
        ws.onmessage = function(e) {
            document.getElementById("output").innerText += e.data + "\\n";
        };
        ws.onopen = function() {
            ws.send("Hello WebSocket!");
        };
    </script>
</body>
</html>"""


@app.route("/ws")
def websocket_page():
    """WebSocket test page — VULNERABLE: token in URL, no origin check."""
    return WS_PAGE


# ── API Key Exposure (Phase 2) ────────────────────────────────

EXPOSED_KEYS_PAGE = """<!DOCTYPE html>
<html>
<head><title>Config - TestApp</title></head>
<body>
    <h1>Application Configuration</h1>
    <pre>
// Internal config — DO NOT COMMIT
const config = {
    apiKey: "sk_test_NOTREALNOTREALNOTREALNOTREAL",
    secret: "not-a-real-secret-key-for-testing",
    awsAccessKey: "AKIA0000000000000000EXMPL",
    githubToken: "ghp_000000000000000000000000000000000000",
};
    </pre>
    <!-- Backup API key: AIza0000000000000000000000000000000000 -->
    <p>Status: OK</p>
</body>
</html>"""


@app.route("/config")
def config_page():
    """Config page — VULNERABLE: exposes fake API keys in source."""
    return EXPOSED_KEYS_PAGE


# ── Additional Paths (Phase 2) ────────────────────────────────


@app.route("/admin")
def admin_panel():
    """Admin panel stub."""
    return "Admin Panel — Access Denied", 403


@app.route("/api")
def api_index():
    """API index stub."""
    return jsonify({"version": "1.0", "endpoints": ["/api/user", "/api/profile"]})


@app.route("/backup")
def backup_page():
    """Backup page stub."""
    return "Backup directory", 403


# ── Health Check ───────────────────────────────────────────────


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "users": len(USERS)})


# ── Main ───────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5555))
    print(f"Starting vulnerable test app on http://0.0.0.0:{port}")
    print("Vulnerabilities:")
    print("  - Default credentials: admin:admin, user:password, test:test, guest:guest")
    print("  - JWT alg=none accepted at /api/profile")
    print("  - Session cookies: no HttpOnly, Secure, or SameSite")
    print("  - No CSRF protection on /profile POST")
    print("  - Session fixation: session ID unchanged after login")
    print("  - Session not invalidated on /logout")
    print("  - User enumeration via distinct error messages")
    print("  - No rate limiting on /login")
    print("  - Sensitive data in JWT payload (email, role)")
    print("  - Missing security headers")
    print()
    app.run(host="0.0.0.0", port=port, debug=False)
