"""Renders a stored assessment report (Markdown, following the fixed
`### [SEVERITY] Title` finding shape from skills/renderer.py) to HTML, wired
to the design system: severity/verdict/status badges, styled tables, and
lightweight diff-block highlighting. A report that doesn't match the
expected shape still renders fine as plain markdown -- all of this is
best-effort annotation, never a requirement.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from html import unescape
from pathlib import Path
from urllib.parse import urlsplit

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

# Fallback anchor for an agent that skips the literal "# <Skill> Report"
# title outright (observed with the copilot adapter: it unpromptedly runs
# its own native security-scan tool first, emitting an unrelated "##"/"###"
# preamble, then goes straight into the skill's required numbered sections
# without ever writing a single top-level "#" heading anywhere). Every
# skill's contract requires "## 1. Executive Summary" verbatim as its
# first numbered section (see skills/renderer.py's shared "Required
# output format" block -- identical across every skill, not just SAST),
# so anchoring on that literal phrase, not just "## 1." with any text,
# matters: a preamble that itself numbers an unrelated "## 1. <something>"
# section (a plan, a to-do list) would otherwise be matched instead of the
# real report -- cutting to the wrong, earlier point instead of past the
# preamble entirely. Tried only when the primary title search above finds
# nothing, so a compliant agent's report (which always has both) is
# unaffected either way.
_NUMBERED_SECTION_ONE_RE = re.compile(r"^##\s+1\.\s+Executive Summary\s*$", re.MULTILINE | re.IGNORECASE)

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
    defensive backstop. Falls back to anchoring on "## 1. Executive
    Summary" (see _NUMBERED_SECTION_ONE_RE above) when no top-level heading
    exists at all, for an agent that skips the title outright but still
    gets to the required sections eventually. Leaves text unchanged if
    neither anchor is found, rather than risk hiding a malformed report.
    """
    match = _TOP_LEVEL_HEADING_RE.search(text)
    if match is None:
        match = _NUMBERED_SECTION_ONE_RE.search(text)
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


_IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_A_HREF_RE = re.compile(r'(<a\b[^>]*\bhref=")([^"]*)(")', re.IGNORECASE)


def _is_safe_navigation_url(url: str) -> bool:
    """Links the dashboard may leave in a report. Images are removed
    separately: the browser would fetch them as soon as the page loads,
    which is an exfiltration channel for a prompt-injected report."""
    parts = urlsplit(unescape(url).strip())
    return parts.scheme in {"http", "https"} and bool(parts.hostname) and not parts.username and not parts.password


def _strip_outbound_markup(html: str) -> str:
    html = _IMG_RE.sub("", html)

    def replace(match: re.Match[str]) -> str:
        if _is_safe_navigation_url(match.group(2)):
            return match.group(0)
        return match.group(1) + "#" + match.group(3)

    return _A_HREF_RE.sub(replace, html)


def render_report_html(markdown_text: str) -> str:
    html = _md.render(markdown_text)
    html = _annotate_severity_badges(html)
    html = _annotate_table_cell_badges(html)
    html = _annotate_diff_blocks(html)
    # Before _style_tables so the mermaid <pre> is never mistaken for one.
    html = _prepare_mermaid_blocks(html)
    html = _style_tables(html)
    return _strip_outbound_markup(html)


MD = MarkdownIt('commonmark').disable(['html_block', 'html_inline'])
FINDING = re.compile(r'^ {0,3}###\s*\[(?P<severity>[A-Za-z]+)\]\s*(?P<id>[A-Za-z]\d+)?:?')


class MalformedReportError(ValueError):
    """Report structure cannot be safely counted or persisted."""


@dataclass(frozen=True)
class Heading:
    level: int
    text: str
    start: int
    end: int


@dataclass(frozen=True)
class ParsedReport:
    source: str
    headings: tuple[Heading, ...]
    excluded: tuple[tuple[int, int], ...]


class ReportText(str):
    """A source view carrying the already parsed report through extractors."""

    def __new__(cls, source: str, parsed: ParsedReport, start: int = 0):
        value = super().__new__(cls, source)
        value.parsed = parsed
        value.start = start
        return value

    def view(self, start: int, end: int) -> ReportText:
        return ReportText(self[start:end], self.parsed, self.start + start)


@lru_cache(maxsize=8)
def _parse_report(source: str) -> ReportText:
    # Match markdown-it's newline normalization exactly. Unicode separators
    # and C0 controls are source characters, never additional token-map lines.
    source = source.replace('\r\n', '\n').replace('\r', '\n')
    pieces = source.split('\n')
    lines = [line + '\n' for line in pieces[:-1]] + [pieces[-1]]
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    result = []
    excluded = []
    ignored = set()
    for token in MD.parse(source):
        if token.type in {'fence', 'code_block', 'blockquote_open'} and token.map:
            a, b = token.map
            ignored.update(range(a, b))
            excluded.append((offsets[a], offsets[b]))
        if token.type == 'fence' and token.map:
            a, b = token.map
            last = lines[b - 1].rstrip('\r\n')
            if token.level > 0:
                last = re.sub(r'^(?: {0,3}> ?)+', '', last).lstrip(' \t')
            closing = re.fullmatch(r' {0,3}' + re.escape(token.markup[0]) +
                                  '{' + str(len(token.markup)) + r',}[ \t]*', last)
            if not closing or b - a < 2:
                raise MalformedReportError('Unclosed Markdown code fence')
        if token.type == 'heading_open' and token.level == 0 and token.map:
            a, b = token.map
            result.append(Heading(int(token.tag[1]), lines[a].rstrip('\r\n').lstrip(' '), offsets[a], offsets[b]))
    real = {h.start for h in result if h.level == 3}
    for i, line in enumerate(lines):
        if i not in ignored and FINDING.match(line) and offsets[i] not in real:
            raise MalformedReportError('Finding-like text is not a valid top-level Markdown heading')
    parsed = ParsedReport(source, tuple(result), tuple(excluded))
    return ReportText(source, parsed)


def parse_report(report: str) -> ReportText:
    """Parse once; the bounded cache also shares work between dashboard readers."""
    return report if isinstance(report, ReportText) else _parse_report(report)


def headings(report: str) -> list[Heading]:
    report = parse_report(report)
    return [Heading(h.level, h.text, h.start - report.start, h.end - report.start)
            for h in report.parsed.headings
            if report.start <= h.start and h.end <= report.start + len(report)]


def section(report: str, title: str) -> str:
    report = parse_report(report)
    items = headings(report)
    for i, item in enumerate(items):
        if item.level == 2 and re.match(r'^##\s+(?:\d+\.\s*)?' + re.escape(title) + r'(?:\s|$)', item.text):
            end = next((x.start for x in items[i + 1:] if x.level <= 2), len(report))
            return report.view(item.end, end)
    return report.view(0, 0)


def detail_blocks(report: str, pattern: re.Pattern | None = None) -> list[tuple[str, str]]:
    report = parse_report(report)
    items = headings(report)
    blocks = []
    for i, item in enumerate(items):
        if item.level != 3:
            continue
        match = pattern.match(item.text) if pattern else None
        if pattern and match is None:
            continue
        # An explanatory h3 (e.g. "Fix") belongs to this finding. Only the
        # next finding or a higher-level section terminates its narrative.
        end = next((x.start for x in items[i + 1:]
                    if x.level < 3 or (x.level == 3 and
                        (pattern.match(x.text) if pattern else FINDING.match(x.text)))), len(report))
        blocks.append((match.group('id') if match else item.text, report.view(item.end, end)))
    return blocks


def prose_source(report: str) -> str:
    """Blank examples without changing source offsets or re-parsing sections."""
    report = parse_report(report)
    chars = list(report)
    for start, end in report.parsed.excluded:
        for i in range(max(start - report.start, 0), min(end - report.start, len(report))):
            if chars[i] != '\n':
                chars[i] = ' '
    return ''.join(chars)


def visible_text(report: str) -> str:
    """Unquoted prose including list items, excluding code examples."""
    return prose_source(report)


def example_finding_ids(report: str) -> set[str]:
    report = parse_report(report)
    identifiers = set()
    for start, end in report.parsed.excluded:
        a, b = max(start - report.start, 0), min(end - report.start, len(report))
        for line in report[a:b].split('\n'):
            match = FINDING.match(line.lstrip(' >\t'))
            if match and match.group('id'):
                identifiers.add(match.group('id'))
    return identifiers


def has_json_draft(report: str) -> bool:
    """Recognize a JSON draft envelope even after a model's prose preamble."""
    text = prose_source(report)
    decoder = json.JSONDecoder()
    for match in re.finditer(r'\{', text):
        try:
            value, _ = decoder.raw_decode(text, match.start())
        except ValueError:
            continue
        if isinstance(value, dict) and isinstance(value.get('draft_report'), str):
            return True
    return False


def read_stored_report(path: str | Path | None, *, errors: list[str] | None = None) -> str:
    """Older malformed reports are unavailable data, never a dashboard crash."""
    if not path:
        return ''
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
        parsed = parse_report(text)
        if has_json_draft(parsed):
            raise MalformedReportError('JSON draft wrapper is not a report')
        return parsed
    except MalformedReportError as error:
        logging.getLogger(__name__).warning('Unparsable stored report %s: %s', path, error)
        if errors is not None:
            errors.append(str(path))
        return ''
    except OSError:
        return ''
