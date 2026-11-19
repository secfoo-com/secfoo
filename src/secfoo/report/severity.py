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
    text_outside_code,
    text_without_json_drafts,
    visible_text,
)

_FINDING_HEADING_RE = re.compile(r"^###\s*\[(?P<severity>[A-Za-z]+)\]", re.MULTILINE)
_RISK_RATING_RE = re.compile(r"\*\*Overall risk rating:\*\*\s*([A-Za-z]+)", re.IGNORECASE)

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


def extract_overall_risk_rating(report_markdown: str) -> str | None:
    """The report's own `**Overall risk rating:**` line. Prose first, then
    blockquotes (a rating written as a callout); never code blocks, never a
    JSON echo of a report."""
    if has_json_draft(report_markdown) or _is_json_document(report_markdown):
        return None
    for text in (visible_text(report_markdown), text_outside_code(report_markdown)):
        match = _RISK_RATING_RE.search(text_without_json_drafts(text))
        if match is not None:
            return match.group(1).strip().lower()
    return None
