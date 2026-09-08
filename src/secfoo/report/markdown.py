"""Renders a stored assessment report (Markdown, following the fixed
`### [SEVERITY] Title` finding shape from skills/renderer.py) to HTML, wired
to the design system: severity/verdict/status badges, styled tables, and
lightweight diff-block highlighting. A report that doesn't match the
expected shape still renders fine as plain markdown -- all of this is
best-effort annotation, never a requirement.
"""

from __future__ import annotations

import re

from markdown_it import MarkdownIt

_SEVERITY_BADGE_CLASS = {
    "critical": "badge--error",
    "high": "badge--error",
    "medium": "badge--warning",
    "low": "badge--teal",
    "informational": "badge--neutral",
}

# Exact-match words for table cells (Findings Register's Severity/Verdict
# columns, Security Controls Matrix's Status column). Deliberately only
# fires when a cell's entire trimmed content is one of these words, so
# prose mentioning "high" or "low" in a Description cell is never touched.
_CELL_BADGE_CLASS = {
    **_SEVERITY_BADGE_CLASS,
    "confirmed": "badge--error",
    "conditional": "badge--warning",
    "latent": "badge--neutral",
    "implemented": "badge--success",
    "partial": "badge--warning",
    "not implemented": "badge--error",
}

_FINDING_HEADING_RE = re.compile(
    r"<h3>\[(?P<severity>[A-Za-z]+)\]\s*(?P<title>.*?)</h3>", re.IGNORECASE
)
_TD_EXACT_RE = re.compile(r"<td>\s*([A-Za-z ]+?)\s*</td>")
_DIFF_BLOCK_RE = re.compile(
    r'(<pre><code class="language-diff">)(.*?)(</code></pre>)', re.DOTALL
)
_MERMAID_BLOCK_RE = re.compile(
    r'<pre><code class="language-mermaid">(.*?)</code></pre>', re.DOTALL
)
_TOP_LEVEL_HEADING_RE = re.compile(r"^#\s+.+$", re.MULTILINE)

# "commonmark" alone is the strict base spec and does NOT parse GFM pipe
# tables -- every `| a | b |` block silently fell through as a plain
# paragraph of literal text. `enable(["table"])` turns on just the table
# rule without pulling in the full "gfm-like" preset (which additionally
# wants the optional linkify-it-py package for autolinking we don't need).
#
# The commonmark preset also defaults html=True (raw HTML passthrough),
# which is unsafe here: report content is produced by an LLM agent reading
# a target codebase that may be untrusted (this tool has an explicit
# "third-party" assessment type for exactly that case), and gets rendered
# with Jinja's `|safe` in run_detail.html. Disabling html_block/html_inline
# makes any literal HTML in agent output render as escaped text instead of
# executing -- confirmed via `MarkdownIt("commonmark").render("<script>...")`
# emitting the tag verbatim, unescaped, before this fix.
_md = (
    MarkdownIt("commonmark")
    .enable(["table", "strikethrough"])
    .disable(["html_block", "html_inline"])
)


def strip_preamble(text: str) -> str:
    """Drops any assistant chatter before the report's required top-level
    heading (`# <Skill> Report`). The prompt explicitly forbids a preamble,
    but that instruction isn't 100% reliable in practice -- this is the
    defensive backstop. Leaves text unchanged if no top-level heading is
    found at all, rather than risk hiding a malformed report.
    """
    match = _TOP_LEVEL_HEADING_RE.search(text)
    if match is None:
        return text
    return text[match.start():]


def _annotate_severity_badges(html: str) -> str:
    def replace(match: re.Match[str]) -> str:
        severity = match.group("severity")
        title = match.group("title")
        badge_class = _SEVERITY_BADGE_CLASS.get(severity.lower(), "badge--neutral")
        return f'<h3><span class="badge {badge_class}">{severity.upper()}</span> {title}</h3>'

    return _FINDING_HEADING_RE.sub(replace, html)


def _annotate_table_cell_badges(html: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(1)
        badge_class = _CELL_BADGE_CLASS.get(text.lower())
        if badge_class is None:
            return match.group(0)
        return f'<td><span class="badge {badge_class}">{text}</span></td>'

    return _TD_EXACT_RE.sub(replace, html)


def _style_tables(html: str) -> str:
    """markdown-it emits bare <table> with no class -- the design system's
    table styling (components/tables.css) only applies to `.table` inside a
    `.table-wrap`, matching how every other table in this app is marked up.
    """
    html = html.replace("<table>", '<div class="table-wrap"><table class="table">')
    return html.replace("</table>", "</table></div>")


def _colorize_diff_line(line: str) -> str:
    if line.startswith(("+++", "---")):
        return line
    if line.startswith("+"):
        return f'<span class="diff-add">{line}</span>'
    if line.startswith("-"):
        return f'<span class="diff-del">{line}</span>'
    return line


def _prepare_mermaid_blocks(html: str) -> str:
    """Rewrites ```mermaid fences into the `<pre class="mermaid">` shape
    mermaid.js looks for, wrapped in a figure that keeps the raw source
    available.

    The diagram text stays HTML-escaped: mermaid reads `textContent`, which
    the browser unescapes for us, so `A --&gt; B` still parses as `A --> B`
    without ever putting unescaped agent output into the DOM. If mermaid.js
    isn't present (it's an optional vendored asset -- see
    web/templates/run_detail.html) the block degrades to a readable code
    listing rather than disappearing, since mermaid source is legible on
    its own.
    """

    def replace(match: re.Match[str]) -> str:
        source = match.group(1)
        return (
            '<figure class="mermaid-figure">'
            f'<pre class="mermaid">{source}</pre>'
            '<figcaption class="mermaid-figure__fallback">'
            "Diagram source (Mermaid)</figcaption>"
            "</figure>"
        )

    return _MERMAID_BLOCK_RE.sub(replace, html)


def _annotate_diff_blocks(html: str) -> str:
    def replace(match: re.Match[str]) -> str:
        opening, body, closing = match.groups()
        colored = "\n".join(_colorize_diff_line(line) for line in body.split("\n"))
        return opening + colored + closing

    return _DIFF_BLOCK_RE.sub(replace, html)


def render_report_html(markdown_text: str) -> str:
    html = _md.render(markdown_text)
    html = _annotate_severity_badges(html)
    html = _annotate_table_cell_badges(html)
    html = _annotate_diff_blocks(html)
    # Before _style_tables so the mermaid <pre> is never mistaken for one.
    html = _prepare_mermaid_blocks(html)
    return _style_tables(html)
