"""Extracts severity counts and the overall risk rating from a stored
report's raw Markdown, so they can be persisted as queryable columns
instead of only living inside report text. Operates on the same
`### [SEVERITY] Title` finding-heading shape and `**Overall risk rating:**`
line that skills/renderer.py's output contracts require every skill to
produce -- malformed Markdown raises rather than silently passing a severity gate.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from secfoo.report.markdown import (
    MalformedReportError,
    has_json_draft,
    headings,
    section,
    text_outside_code,
    text_without_json_drafts,
    visible_text,
)

_FINDING_HEADING_RE = re.compile(r"^###\s*\[(?P<severity>[A-Za-z]+)\]", re.MULTILINE)
_RISK_RATING_RE = re.compile(r"\*\*Overall risk rating:\*\*\s*([A-Za-z]+)", re.IGNORECASE)

# Small models follow the contract's content but not always its formatting:
# they drop the bold, or fold the rating into the summary paragraph as its
# last sentence. These looser shapes are tried only after the contract's
# bold line, only in unquoted prose, and only with a known tier word, so an
# example in a fence, a blockquote or a JSON echo still cannot supply it.
_RATING = r"(?:\*\*)?Overall risk rating:(?:\*\*)?[ \t]*(?:\*\*)?(?P<rating>[A-Za-z]+)(?:\*\*)?[ \t]*\.?"
_RATING_LINE_RE = re.compile(r"^[ \t]*(?:[-*+][ \t]+)?" + _RATING + r"[ \t]*$", re.IGNORECASE | re.MULTILINE)
_TRAILING_RATING_RE = re.compile(r"(?:^|(?<=[.!?:])[ \t]+)" + _RATING + r"\s*$", re.IGNORECASE)
_SUMMARY_SECTIONS = ("Executive Summary", "Summary")

# secfoo's own skills only ever emit high/medium/low (a deliberate 3-tier
# simplification), but the dashboard's severity scale is the full 5-tier
# Critical/High/Medium/Low/Informational -- recognizing all five here means
# a future skill (or a manually-authored report) that does use them is
# counted correctly without any further code change.
_TIER_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


@dataclass(frozen=True)
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


def count_severities(report_markdown: str) -> SeverityCounts:
    if has_json_draft(report_markdown):
        raise MalformedReportError("JSON draft wrapper is not a report")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for heading in headings(report_markdown):
        if heading.level != 3:
            continue
        match = _FINDING_HEADING_RE.match(heading.text)
        if match is None:
            continue
        tier = _TIER_ALIASES.get(match.group("severity").lower())
        if tier is not None:
            counts[tier] += 1
    return SeverityCounts(**counts)


def _is_json_document(text: str) -> bool:
    stripped = text.strip()
    if not stripped or stripped[0] not in '{["':
        return False
    try:
        json.loads(stripped)
    except ValueError:
        return False
    return True


def _known_tier(match: re.Match | None) -> str | None:
    if match is None or match.group("rating").lower() not in _TIER_ALIASES:
        return None
    return match.group("rating").lower()


def _first_paragraph_lines(text: str) -> list[str]:
    """The first paragraph, split at Markdown hard line breaks (two trailing
    spaces or a backslash): a model that ends the summary sentence with a
    hard break and runs a table straight after it still ends a line there."""
    paragraph = re.split(r"\n[ \t]*\n", text.strip("\n"), maxsplit=1)[0]
    return re.split(r"(?: {2,}|\\)\n", paragraph)


def extract_overall_risk_rating(report_markdown: str) -> str | None:
    """The report's own `**Overall risk rating:**` line. Prose first, then
    blockquotes (a rating written as a callout); never code blocks, never a
    JSON echo of a report.

    Failing that, the shapes small models actually write: the same marker
    without bold on its own line, or as the last sentence of the Summary /
    Executive Summary section's first paragraph. Those are read from
    unquoted prose only and must name a known severity tier."""
    if has_json_draft(report_markdown) or _is_json_document(report_markdown):
        return None
    for text in (visible_text(report_markdown), text_outside_code(report_markdown)):
        match = _RISK_RATING_RE.search(text_without_json_drafts(text))
        if match is not None:
            return match.group(1).strip().lower()
    prose = text_without_json_drafts(visible_text(report_markdown))
    for match in _RATING_LINE_RE.finditer(prose):
        rating = _known_tier(match)
        if rating is not None:
            return rating
    for title in _SUMMARY_SECTIONS:
        summary = section(report_markdown, title)
        if not summary:
            continue
        for line in _first_paragraph_lines(text_without_json_drafts(visible_text(summary))):
            rating = _known_tier(_TRAILING_RATING_RE.search(line))
            if rating is not None:
                return rating
    return None
