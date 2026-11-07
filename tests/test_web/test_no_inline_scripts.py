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

# Any inline event-handler attribute inside a tag (onclick, onchange,
# onsubmit, oninput, ...) -- the CSP blocks all of them, not just onclick.
_INLINE_HANDLER_RE = re.compile(r"<[^>]*\son[a-z]+\s*=", re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>")


def _all_templates() -> list[Path]:
    return [f for d in TEMPLATE_DIRS for f in d.rglob("*.html")]


def test_no_template_uses_an_inline_event_handler_attribute():
    offenders = {
        str(f): m.group(0)
        for f in _all_templates()
        for m in [_INLINE_HANDLER_RE.search(f.read_text())]
        if m
    }
    assert not offenders, (
        f"Found inline on...= event handlers, CSP-blocked on the portal: {offenders}. "
        "Use data-href (row navigation), data-confirm/data-delete-url "
        "(confirm dialogs, delete buttons) or data-autosubmit (filter dropdowns) "
        "with static/js/interactive.js instead."
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


# The same CSP (no 'unsafe-inline') also blocks inline CSS: style="..."
# attributes and <style> blocks are silently dropped on the portal, so a
# page can look right under `secfoo serve` and wrong on app.secfoo.com.
_INLINE_STYLE_ATTR_RE = re.compile(r"<[^>]*\sstyle\s*=", re.IGNORECASE)
_STYLE_BLOCK_RE = re.compile(r"<style\b", re.IGNORECASE)


def test_no_template_uses_an_inline_style_attribute():
    offenders = {
        str(f): m.group(0)[-80:]
        for f in _all_templates()
        for m in [_INLINE_STYLE_ATTR_RE.search(f.read_text())]
        if m
    }
    assert not offenders, (
        f"Found inline style=... attributes, CSP-blocked on the portal: {offenders}. "
        "Use a class from static/css/dashboard.css (u-* utilities) instead; for "
        "data-driven values use data-bar-width / data-donut-gradient, which "
        "static/js/interactive.js applies."
    )


def test_no_template_has_an_inline_style_block():
    offenders = [str(f) for f in _all_templates() if _STYLE_BLOCK_RE.search(f.read_text())]
    assert not offenders, (
        f"Found <style> blocks, CSP-blocked on the portal: {offenders}. "
        "Move the rules into static/css/dashboard.css instead."
    )
