"""Allowlist for HTTP calls this package makes with user data.

Report upload goes only to https://app.secfoo.com. The optional memory
client accepts the https URL the user configured (the default is
https://memory.secfoo.com, or a self-hosted service) and rejects
cleartext and credentials in the URL.
"""

from __future__ import annotations

from urllib.parse import urlsplit

PORTAL_HOST = "app.secfoo.com"


class EgressError(ValueError):
    pass


def require_https_origin(url: str) -> str:
    """Return the https origin of `url`.

    Used for a service the user explicitly configures (secfoo-memory,
    including a self-hosted URL). Rejects cleartext, missing hosts, and
    credentials embedded in the URL. The path is discarded.
    """
    cleaned = (url or "").strip()
    if not cleaned or any(char in cleaned for char in "\r\n\t \\"):
        raise EgressError(f"refusing URL {url!r}: an https URL is required")
    parts = urlsplit(cleaned)
    hostname = (parts.hostname or "").rstrip(".").lower()
    if parts.scheme != "https" or not hostname or parts.username or parts.password:
        raise EgressError(f"refusing URL {url!r}: an https URL with no credentials is required")
    port = f":{parts.port}" if parts.port else ""
    return f"https://{hostname}{port}"


def require_origin(url: str, *, host: str) -> str:
    """Return `https://host`, or raise if `url` is any other origin.

    Rejects http, other hosts, userinfo, non-443 ports, and whitespace.
    The path is discarded: callers append their own API paths, so a
    config value cannot smuggle a different host into the request.
    """
    cleaned = (url or "").strip()
    if not cleaned or any(char in cleaned for char in "\r\n\t \\"):
        raise EgressError(f"refusing URL {url!r}: only https://{host} is allowed")
    parts = urlsplit(cleaned)
    hostname = (parts.hostname or "").rstrip(".").lower()
    if (
        parts.scheme != "https"
        or hostname != host
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
    ):
        raise EgressError(f"refusing URL {url!r}: only https://{host} is allowed")
    return f"https://{host}"
