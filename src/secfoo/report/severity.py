"""Extracts severity counts and the overall risk rating from a stored
report's raw Markdown, so they can be persisted as queryable columns
instead of only living inside report text. Operates on the same
`### [SEVERITY] Title` finding-heading shape and `**Overall risk rating:**`
line that skills/renderer.py's output contracts require every skill to
produce -- best-effort only, a report that doesn't match still stores as
all-zero counts / no rating rather than raising.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

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
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for match in _FINDING_HEADING_RE.finditer(report_markdown):
        tier = _TIER_ALIASES.get(match.group("severity").lower())
        if tier is not None:
            counts[tier] += 1
    return SeverityCounts(**counts)


def extract_overall_risk_rating(report_markdown: str) -> str | None:
    match = _RISK_RATING_RE.search(report_markdown)
    if match is None:
        return None
    return match.group(1).strip().lower()
