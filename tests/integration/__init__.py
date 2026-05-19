"""End-to-end integration tests against tests/fixtures/vuln_app.

Each test spawns a real Flask process and runs ScanEngine against it,
proving that the shipped modules detect their target vulnerabilities
against a real HTTP socket — not a `responses`-mocked stub.

The whole suite is gated behind ``pytest.mark.slow`` so the default
``make test`` workflow stays fast; run ``make integration`` (or
``pytest -m slow``) to execute it.
"""
