"""Clickable table rows must be usable without a mouse.

`<tr class="run-row" data-href=...>` rows are opened by static/js/
interactive.js. A <tr> isn't focusable by default, so the script gives
each such row tabindex=0 and opens it on Enter. These checks guard both
halves: every clickable row carries data-href (what the script looks
for), and the script still sets up focus and Enter handling.
"""

from __future__ import annotations

import re
from pathlib import Path

WEB = Path(__file__).parents[2] / "src" / "secfoo" / "web"
_RUN_ROW_RE = re.compile(r"<tr\b[^>]*\bclass=\"[^\"]*\brun-row\b[^>]*>")


def test_every_clickable_row_has_a_data_href():
    rows = [
        (str(f), m.group(0))
        for f in (WEB / "templates").rglob("*.html")
        for m in _RUN_ROW_RE.finditer(f.read_text())
    ]
    assert rows, "expected at least one clickable run-row in the templates"
    missing = [(f, tag) for f, tag in rows if "data-href=" not in tag]
    assert not missing, f"run-row without data-href (not keyboard/clickable): {missing}"


def test_interactive_js_makes_rows_focusable_and_opens_them_on_enter():
    js = (WEB / "static" / "js" / "interactive.js").read_text()
    assert '.run-row[data-href]' in js
    assert "tabIndex = 0" in js
    assert '"keydown"' in js and '"Enter"' in js
