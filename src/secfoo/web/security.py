"""Security middleware for the local web dashboard (#118).

Defends secfoo serve against:
1. Cross-Site Request Forgery (CSRF) via Origin / Sec-Fetch-Site validation.
2. DNS rebinding via Starlette's TrustedHostMiddleware.
3. Clickjacking and injection via strict security headers (CSP, X-Frame-Options,
   X-Content-Type-Options, Referrer-Policy).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]", "testserver"})

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def _extract_hostname(val: str | None) -> str | None:
    if not val:
        return None
    val = val.strip()
    if val == "null":
        return None
    try:
        parts = urlsplit(val if "://" in val else f"http://{val}")
        return parts.hostname.lower() if parts.hostname else None
    except (ValueError, AttributeError):
        return None


class CrossSiteProtectionMiddleware(BaseHTTPMiddleware):
    """Rejects cross-site state-changing requests to the web dashboard.

    Modern browsers send `Origin` on all cross-origin requests and all
    state-changing fetch/form requests. They also send `Sec-Fetch-Site`.
    If Origin or Sec-Fetch-Site indicates a cross-origin source, the request
    is forbidden (403). Non-browser clients (such as the secfoo CLI and
    runtime sensors) that omit these browser headers entirely are permitted.
    """

    def __init__(
        self, app, allowed_hostnames: set[str] | frozenset[str] | None = None
    ) -> None:
        super().__init__(app)
        self.allowed_hostnames = {
            h.lower() for h in (allowed_hostnames or LOOPBACK_HOSTS)
        }

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in STATE_CHANGING_METHODS:
            origin = request.headers.get("origin")
            sec_fetch_site = request.headers.get("sec-fetch-site", "").lower()
            referer = request.headers.get("referer")

            # 1. Explicit Origin header: must match an allowed local host
            if origin:
                origin_host = _extract_hostname(origin)
                if not origin_host or origin_host not in self.allowed_hostnames:
                    return PlainTextResponse(
                        "Cross-origin state-changing request forbidden", status_code=403
                    )

            # 2. Sec-Fetch-Site header: reject cross-site navigation/fetch
            if sec_fetch_site == "cross-site":
                return PlainTextResponse(
                    "Cross-site request forbidden", status_code=403
                )

            # 3. Referer fallback when Origin is missing: if present, must match
            if not origin and referer:
                referer_host = _extract_hostname(referer)
                if not referer_host or referer_host not in self.allowed_hostnames:
                    return PlainTextResponse(
                        "Cross-origin request forbidden", status_code=403
                    )

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attaches defensive security headers to all responses."""

    def __init__(self, app, csp: str = DEFAULT_CSP) -> None:
        super().__init__(app)
        self.csp = csp

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers["Content-Security-Policy"] = self.csp
        headers["X-Frame-Options"] = "DENY"
        headers["X-Content-Type-Options"] = "nosniff"
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
