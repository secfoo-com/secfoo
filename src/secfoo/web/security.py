"""Browser-facing protections for the local dashboard (#118).

`secfoo serve` binds 127.0.0.1 and has no login, so the threat is the user's
own browser: any page they visit can send requests to http://127.0.0.1:8787.

- Cross-site writes: a page can POST a form (or `fetch(..., {mode: "no-cors"})`)
  to start a paid agent run, delete a case file or flip a finding review.
  Unsafe methods must come from the dashboard's own origin. Browsers always
  send `Origin` (and modern ones `Sec-Fetch-Site`) on such requests, so a
  request carrying neither is a non-browser client (curl, the CLI, tests).
- DNS rebinding: an attacker's hostname that resolves to 127.0.0.1 makes the
  dashboard same-origin with the attacker's page, which could then read every
  report. Requests must name the dashboard by a loopback host or the --host
  it was started with.
- Framing and content sniffing: security headers on every response.

The runtime ingest API (/api/runtime/) authenticates with an API key in the
Authorization header, which a cross-site page cannot set without a CORS
preflight the app never grants, so it is exempt from the origin check (sensors
are not browsers) but not from the Host check.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from starlette.responses import PlainTextResponse

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
WILDCARD_BINDS = {"", "0.0.0.0", "::"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MACHINE_API_PREFIX = "/api/runtime/"

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    # Mermaid writes <style> into the SVGs it renders; no script is inline.
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def _hostname(netloc: str) -> str:
    """'127.0.0.1:8787' -> '127.0.0.1', '[::1]:8787' -> '::1', 'LocalHost.' -> 'localhost'."""
    netloc = netloc.strip().lower()
    if netloc.startswith("["):
        return netloc[1:netloc.find("]")] if "]" in netloc else ""
    if netloc.count(":") == 1:
        netloc = netloc.rsplit(":", 1)[0]
    return netloc.rstrip(".")


def is_loopback(host: str) -> bool:
    return _hostname(host) in LOOPBACK_HOSTS


def allowed_hosts(bind_host: str, extra=()) -> set[str] | None:
    """Host names the dashboard answers to; None means any (a wildcard bind,
    where the operator already chose to expose it to the network)."""
    bind = _hostname(bind_host)
    if bind in WILDCARD_BINDS:
        return None
    return set(LOOPBACK_HOSTS) | {bind} | {_hostname(name) for name in extra}


def _same_origin(url: str, host_header: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme in {"http", "https"} and parts.netloc.lower() == host_header.strip().lower()


def check_request(method: str, path: str, headers, hosts: set[str] | None) -> PlainTextResponse | None:
    """Return a rejection response, or None to let the request through."""
    host_header = headers.get("host", "")
    if hosts is not None and _hostname(host_header) not in hosts:
        return PlainTextResponse(
            "Invalid Host header. secfoo serve only answers to loopback names and its --host; "
            "add another name with --allow-host NAME.", status_code=400)
    if method.upper() in SAFE_METHODS or path.startswith(MACHINE_API_PREFIX):
        return None
    fetch_site = headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site not in {"same-origin", "none"}:
        return PlainTextResponse("Cross-site request refused", status_code=403)
    origin = headers.get("origin")
    if origin is not None:
        if not _same_origin(origin, host_header):  # includes Origin: null
            return PlainTextResponse("Cross-origin request refused", status_code=403)
    elif fetch_site is None:
        referer = headers.get("referer")
        if referer and not _same_origin(referer, host_header):
            return PlainTextResponse("Cross-origin request refused", status_code=403)
    return None


def install(app, *, bind_host: str, allow_hosts=()) -> None:
    hosts = allowed_hosts(bind_host, allow_hosts)

    @app.middleware("http")
    async def dashboard_security(request, call_next):
        # Read at request time so tests can add TestClient's "testserver".
        current = None if hosts is None else hosts | EXTRA_ALLOWED_HOSTS
        refused = check_request(request.method, request.url.path, request.headers, current)
        response = refused or await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response


# Empty in production; tests/conftest.py adds Starlette TestClient's default host.
EXTRA_ALLOWED_HOSTS: set[str] = set()
