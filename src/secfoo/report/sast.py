"""Extracts SAST-report-specific structured data from a report's raw
Markdown: the Findings Register (the actual findings table), and the
Detailed Findings block per finding (Description/Recommendation). Mirrors
`report/sca.py`'s extraction idiom exactly. Best-effort only -- a report
that doesn't carry these just yields an empty list/dict rather than
raising, so the dashboard degrades gracefully instead of erroring.

Also owns the per-run finding fingerprint (`fingerprint_for_row`), the one
piece of this whole feature genuinely new to this app: every other
dashboard in secfoo is recomputed fresh from report text on every request,
with zero persistent per-finding identity. Real open/closed tracking needs
a stable identity for "the same bug" across two separate runs, which this
report's own `Fn` IDs cannot provide -- they restart at F1 every run.

The fingerprint is CWE + normalized file path, deliberately NOT the
finding's title or its line number:

- Line number is unstable -- any unrelated edit elsewhere in the file can
  shift it even when the vulnerable line itself never moved.
- Title is prose the model regenerates from scratch each run; keying on it
  would turn harmless rephrasing ("SQL Injection via raw query" one run,
  "SQLi in user search endpoint" the next) into a false "this finding was
  fixed, and a new one was found" -- silently dropping a still-open bug off
  the Open list. That failure mode (false "closed") is strictly worse than
  the alternative (a genuinely-fixed finding lingers one extra scan as
  "open" before nothing re-matches it and it correctly closes), so the
  fingerprint deliberately biases toward over-matching.

Known failure modes of this approximation, worth remembering when reading
the resulting Open/Closed lists: a CWE reclassification between runs (a
partial fix that changes which CWE best describes what remains) looks like
close+reopen, not "the same finding, narrowed"; a file rename looks like
close+reopen, not "the same finding, moved"; two distinct findings sharing
both CWE and file collide onto one fingerprint unless the per-run
collision guard below (a coarse line-bucket, added only when a run's own
findings actually collide) keeps them apart.
"""

from __future__ import annotations

import hashlib
import re

from secfoo.report.architecture import _extract_section

SKILL_ID = "sast"

# Findings Register: | ID | Finding | Severity | CWE | OWASP | CVSS Vector |
# Location | Verdict |. Anchored on an "Fn" ID so header/separator rows
# never match.
_FINDINGS_REGISTER_ROW_RE = re.compile(
    r"^\|\s*(?P<id>F\d+)\s*\|(?P<title>[^|]*)\|(?P<severity>[^|]*)\|(?P<cwe>[^|]*)\|"
    r"(?P<owasp>[^|]*)\|(?P<cvss_vector>[^|]*)\|(?P<location>[^|]*)\|(?P<verdict>[^|]*)\|\s*$",
    re.MULTILINE,
)

# Detailed Findings heading: "### [SEVERITY] F1: Finding title"
_DETAIL_HEADING_RE = re.compile(r"^###\s*\[[A-Za-z]+\]\s*(?P<id>F\d+):", re.MULTILINE)

_DESCRIPTION_FIELD_RE = re.compile(r"\*\*Description:\*\*\s*([^\n]+)")
_RECOMMENDATION_FIELD_RE = re.compile(r"\*\*Recommendation:\*\*\s*([^\n]+)")

# "`app/db.py:42`" -> ("app/db.py", "42"); the line group is optional since
# a location without one ("`app/db.py`") should still parse.
_LOCATION_RE = re.compile(r"`?(?P<file>[^:`]+?)(?::(?P<line>\d+))?`?\s*$")


def extract_findings_register_rows(report_markdown: str) -> list[dict[str, str]]:
    """One dict per row of the SAST contract's Findings Register table --
    id/title/severity/cwe/owasp/cvss_vector/location/verdict, all stripped
    strings. Reports from other skills, or predating this contract
    version (no CVSS Vector column), simply yield an empty list -- this
    module never falls back to guessing a vector for an older report.
    """
    section = _extract_section(report_markdown, "Findings Register")
    rows = []
    for match in _FINDINGS_REGISTER_ROW_RE.finditer(section):
        rows.append({key: value.strip() for key, value in match.groupdict().items()})
    return rows


def _iter_detail_blocks(report_markdown: str) -> list[tuple[str, str]]:
    """(Fn, block_text) for each Detailed Findings entry -- the text
    between one `### [SEVERITY] Fn:` heading and the next.
    """
    section = _extract_section(report_markdown, "Detailed Findings")
    headings = list(_DETAIL_HEADING_RE.finditer(section))
    blocks = []
    for i, heading in enumerate(headings):
        start = heading.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(section)
        blocks.append((heading.group("id"), section[start:end]))
    return blocks


def extract_description_by_id(report_markdown: str) -> dict[str, str]:
    """Fn -> the report's own `**Description:**` text."""
    result: dict[str, str] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        match = _DESCRIPTION_FIELD_RE.search(block)
        if match:
            result[finding_id] = match.group(1).strip()
    return result


def extract_recommendation_by_id(report_markdown: str) -> dict[str, str]:
    """Fn -> the report's own `**Recommendation:**` text."""
    result: dict[str, str] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        match = _RECOMMENDATION_FIELD_RE.search(block)
        if match:
            result[finding_id] = match.group(1).strip()
    return result


def parse_location(location: str) -> tuple[str, str | None]:
    """"`app/db.py:42`" -> ("app/db.py", "42"); a location with no line
    number, or text that doesn't cleanly split into a single file:line
    (e.g. a finding spanning several call sites, like
    "`app.py:35`, `cli.py:308`"), degrades to (location_stripped, None)
    rather than raising or silently dropping part of it -- backticks are
    stripped either way since they're Markdown code-span syntax, never
    part of a real path.
    """
    stripped = location.strip()
    match = _LOCATION_RE.match(stripped)
    if not match:
        return stripped.replace("`", ""), None
    return match.group("file").strip(), match.group("line")


def _normalize_path(file_path: str) -> str:
    return file_path.strip().lstrip("./").lower()


def fingerprint_for_row(row: dict[str, str], *, line_bucket: str | None = None) -> str:
    """CWE + normalized file path (see module docstring for why not title
    or line), optionally widened with a coarse line-bucket suffix when the
    caller has detected this row would otherwise collide with another
    finding of the same CWE in the same file within the same run.
    """
    file_path, _line = parse_location(row["location"])
    cwe = row.get("cwe", "").strip().lower()
    raw = f"{cwe}|{_normalize_path(file_path)}"
    if line_bucket is not None:
        raw += f"|{line_bucket}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def findings_with_fingerprints(report_markdown: str) -> list[dict[str, str]]:
    """One dict per Findings Register row, joined with its Detailed
    Findings block (description/recommendation) and its fingerprint --
    computed with the per-run collision guard: only rows that share both
    CWE and file with at least one other row *in this same report* get a
    line-bucket appended to their fingerprint, so two real findings never
    silently collapse into one lifecycle entry. This is what both
    runner.py's post-run lifecycle hook and web/sast_dashboard.py consume,
    so the join logic lives in exactly one place.
    """
    rows = extract_findings_register_rows(report_markdown)
    descriptions = extract_description_by_id(report_markdown)
    recommendations = extract_recommendation_by_id(report_markdown)

    # Group indices by (cwe, file) to detect same-run collisions before
    # computing any fingerprint.
    groups: dict[tuple[str, str], list[int]] = {}
    parsed_locations: list[tuple[str, str | None]] = []
    for row in rows:
        file_path, line = parse_location(row["location"])
        parsed_locations.append((file_path, line))
        key = (row.get("cwe", "").strip().lower(), _normalize_path(file_path))
        groups.setdefault(key, []).append(len(parsed_locations) - 1)

    results = []
    for index, row in enumerate(rows):
        file_path, line = parsed_locations[index]
        key = (row.get("cwe", "").strip().lower(), _normalize_path(file_path))
        line_bucket = None
        if len(groups[key]) > 1 and line is not None:
            line_bucket = str(int(line) // 20)
        fingerprint = fingerprint_for_row(row, line_bucket=line_bucket)

        results.append(
            {
                **row,
                "location_file": file_path,
                "location_line": line,
                "fingerprint": fingerprint,
                "description": descriptions.get(row["id"], ""),
                "recommendation": recommendations.get(row["id"], ""),
            }
        )
    return results
