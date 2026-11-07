"""Shared filters for the findings-list pages (SAST findings, SCA
vulnerabilities, secret findings): severity, and -- for SAST, the only
register that records when a finding first appeared -- a first-found
date range.

Filtering happens in Python over the already-built rows, the same way the
SCA and secret lists already filter by project: the registers are small
(one row per distinct finding), and it keeps all three pages behaving the
same regardless of how each one builds its rows.
"""

from __future__ import annotations

from datetime import date
from urllib.parse import urlencode

# (value used in the URL, label shown in the dropdown)
SEVERITY_OPTIONS = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Informational"),
]
_VALID_SEVERITIES = {value for value, _ in SEVERITY_OPTIONS}


def normalize_severity(value: str | None) -> str:
    """'High' / 'high' -> 'high'; 'Informational' -> 'info'; anything
    unrecognised (including an empty or hand-edited query param) -> ''
    meaning "no severity filter"."""
    v = (value or "").strip().lower()
    if v == "informational":
        v = "info"
    return v if v in _VALID_SEVERITIES else ""


def parse_day(value: str | None) -> date | None:
    """A YYYY-MM-DD query param (what <input type="date"> submits) -> date.
    Malformed values are ignored rather than erroring, like a filter that
    wasn't set."""
    try:
        return date.fromisoformat((value or "").strip())
    except ValueError:
        return None


def matches_severity(finding_severity: str | None, selected: str) -> bool:
    return not selected or normalize_severity(finding_severity) == selected


def in_day_range(timestamp: str | None, start: date | None, end: date | None) -> bool:
    """Inclusive on both ends, compared by calendar day (the stored value is
    an ISO timestamp such as 2026-10-09T22:24:40+00:00)."""
    if start is None and end is None:
        return True
    day = parse_day((timestamp or "")[:10])
    if day is None:
        return False
    return (start is None or day >= start) and (end is None or day <= end)


def query_string(**params: object) -> str:
    """Builds a properly encoded query string from the non-empty params --
    for links that carry the current filters (e.g. the Open/Closed tabs)."""
    return urlencode({k: v for k, v in params.items() if v not in (None, "")})


def parse_project_id(value: str | None) -> int | None:
    """The "All projects" option submits project_id= (empty). Declaring the
    route param as `int | None` made FastAPI reject that with a 422, so
    choosing "All projects" -- or pressing Search with it selected, the
    default -- errored. Accept the raw string; empty/invalid means "all"."""
    try:
        return int((value or "").strip())
    except ValueError:
        return None
