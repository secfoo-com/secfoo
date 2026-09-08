"""Guards against inline JS reappearing in any template.

The portal (portal/security.py's SecurityHeadersMiddleware) sends
`Content-Security-Policy: default-src 'self'` with no 'unsafe-inline',
which silently blocks both inline `onclick="..."` attributes and inline
`<script>...</script>` blocks in a real browser. Local `secfoo serve`
sends no CSP at all, so inline JS "works" there and nowhere else --
exactly the trap that made click-through navigation and Mermaid
rendering look broken only in production for so long. Nothing in the
test suite (TestClient doesn't enforce CSP) would have caught that, so
this scans the actual template source instead.
"""

from __future__ import annotations

import re
from pathlib import Path

TEMPLATE_DIRS = [
    Path(__file__).parents[2] / "src" / "secfoo" / "web" / "templates",
    Path(__file__).parents[2] / "portal" / "templates",
]

_ONCLICK_RE = re.compile(r"\bonclick\s*=")
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>")


def _all_templates() -> list[Path]:
    return [f for d in TEMPLATE_DIRS for f in d.rglob("*.html")]


def test_no_template_uses_an_inline_onclick_attribute():
    offenders = {
        str(f): m.group(0)
        for f in _all_templates()
        for m in [_ONCLICK_RE.search(f.read_text())]
        if m
    }
    assert not offenders, (
        f"Found onclick=... attributes, CSP-blocked on the portal: {offenders}. "
        "Use data-href (row navigation) or data-confirm/data-delete-url "
        "(confirm dialogs, delete buttons) with static/js/interactive.js instead."
    )


def test_no_template_has_an_inline_script_block():
    offenders = {
        str(f): m.group(0)
        for f in _all_templates()
        for m in [_INLINE_SCRIPT_RE.search(f.read_text())]
        if m
    }
    assert not offenders, (
        f"Found inline <script> blocks (no src=), CSP-blocked on the portal: {offenders}. "
        "Move the code into a file under src/secfoo/web/static/js/ and reference it "
        "with <script src=\"/static/js/...\"> instead."
    )
