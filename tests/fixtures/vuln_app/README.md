# Vulnerable Test Application

Deliberately vulnerable Flask application for testing auth-scan.

**DO NOT DEPLOY PUBLICLY.**

## Running

```bash
pip install flask
python app.py
# Starts on http://0.0.0.0:5555
```

## Credentials

| Username | Password |
|----------|----------|
| admin    | admin    |
| user     | password |
| test     | test     |
| guest    | guest    |

## Vulnerabilities

1. Default/weak credentials
2. JWT alg=none accepted at /api/profile
3. JWT weak HS256 secret ("weak-secret-12345")
4. Session cookies missing HttpOnly, Secure, SameSite
5. No CSRF protection on /profile POST
6. Session fixation (session ID unchanged after login)
7. Session not invalidated on /logout
8. User enumeration via distinct error messages
9. No rate limiting on /login
10. Sensitive data in JWT payload (email, role)
11. Missing security headers (HSTS, CSP, etc.)
12. Session ID in URL query parameter
