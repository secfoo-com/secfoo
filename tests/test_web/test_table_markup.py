"""Table-cell markup that silently breaks column alignment.

A <td> styled display:flex (e.g. class="findings-cell") stops being a
table cell; the browser wraps it -- and any adjacent one -- into a single
anonymous cell, so two such cells side by side collapse into one column
and every later column shifts left. The flex container has to be a <div>
inside the <td>.
"""

from __future__ import annotations

import re
from pathlib import Path

TEMPLATE_DIRS = [
    Path(__file__).parents[2] / "src" / "secfoo" / "web" / "templates",
    Path(__file__).parents[2] / "portal" / "templates",
]

_FLEX_CELL_RE = re.compile(r'<td\b[^>]*\bclass="[^"]*\bfindings-cell\b')


def test_no_table_cell_is_itself_a_flex_container():
    offenders = [
        str(f)
        for d in TEMPLATE_DIRS
        for f in d.rglob("*.html")
        if _FLEX_CELL_RE.search(f.read_text())
    ]
    assert not offenders, (
        f"<td class=\"findings-cell\"> breaks table column alignment: {offenders}. "
        "Use <td><div class=\"findings-cell\">...</div></td> instead."
    )
