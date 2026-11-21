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

The fingerprint is skill id + CWE + normalized file path + a hash of the
source *code region* around the reported line (when the scan target is
available on disk). It is deliberately NOT the finding's title,
description, or raw line number:

- Title/description are prose the model regenerates each run; keying on them
  would treat paraphrase as "fixed + new finding."
- Line number alone is unstable when unrelated edits shift line numbers.
- When `workdir` is passed (local `secfoo run`), `code_region.hash_code_region`
  hashes a small normalized window of actual source at the reported line so
  two distinct issues in the same file stay separate even with the same CWE.
- When `workdir` is unavailable (e.g. cloud ingest with report only), the
  fingerprint falls back to CWE + path plus the same-run line-bucket collision
  guard documented below.

Known failure modes: CWE reclassification or file rename still look like
close+reopen; a fix that changes the hashed snippet closes correctly; cloud-
only ingest without the repo on disk cannot compute a region hash.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import NamedTuple

from secfoo.report.code_region import hash_code_region
from secfoo.report.markdown import detail_blocks, example_finding_ids, prose_source
from secfoo.report.markdown import section as _extract_section

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
# Code-free one-line description of the vulnerable construct, stored on
# the structured findings tables and emitted by `secfoo findings export`.
# It is the one per-finding field written to be comparable across repos
# (no paths, identifiers, or code). Absent from reports that predate this
# contract field.
_CONSTRUCT_FIELD_RE = re.compile(r"\*\*Construct:\*\*\s*([^\n]+)")

# One site's trailing ":42", ":42-48" (hyphen or en/em dash) or ":42:7"
# (a column, ignored). Peeled off the end of a site repeatedly, so the
# leftmost number left over is the start line and the path never keeps a
# trailing ":range".
_LINE_TAIL_RE = re.compile(r"\s*:\s*(?P<start>\d+)(?:\s*[-\u2013\u2014]\s*(?P<end>\d+))?\s*$")
# A site that is only a line or range ("61", ":61", "61-70"), which reuses
# the previous site's path: "`app/data/user-dao.js:25, :61`".
_BARE_LINES_RE = re.compile(r":?\s*(?P<start>\d+)(?:\s*[-\u2013\u2014]\s*(?P<end>\d+))?")
# The single-site pattern used before #112, kept only to recompute the
# identity rows stored under it had (pre_112_fingerprint).
_PRE_112_LOCATION_RE = re.compile(r"`?(?P<file>[^:`]+?)(?::(?P<line>\d+))?`?\s*$")
# Sites are separated by commas or semicolons; a path never contains one.
_SITE_SEPARATOR_RE = re.compile(r"[,;]")


class SourceLocation(NamedTuple):
    """One site of a finding: a path and an optional line range. Lines stay
    strings, as in the location_line column; end_line is set only for a
    real range (start < end)."""

    path: str
    start_line: str | None = None
    end_line: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {"path": self.path, "start_line": self.start_line, "end_line": self.end_line}


def _line_range(start: str | None, end: str | None) -> tuple[str | None, str | None]:
    if start is None:
        return None, None
    start = start.lstrip("0") or "0"
    end = end.lstrip("0") or "0" if end is not None else None
    # A reversed or one-line range is just its start line. Compared as
    # (length, text) since int() refuses very long digit strings (#121).
    if end is None or (len(end), end) <= (len(start), start):
        return start, None
    return start, end


def extract_findings_register_rows(report_markdown: str) -> list[dict[str, str]]:
    """One dict per row of the SAST contract's Findings Register table --
    id/title/severity/cwe/owasp/cvss_vector/location/verdict, all stripped
    strings. Reports from other skills, or predating this contract
    version (no CVSS Vector column), simply yield an empty list -- this
    module never falls back to guessing a vector for an older report.
    """
    section = prose_source(_extract_section(report_markdown, "Findings Register"))
    rows = []
    for match in _FINDINGS_REGISTER_ROW_RE.finditer(section):
        rows.append({key: value.strip() for key, value in match.groupdict().items()})
    # Keep legacy register rows without narratives, but never persist an
    # identifier whose only detail heading belongs to a quoted/code example.
    examples = example_finding_ids(report_markdown)
    real_ids = {key for key, _ in _iter_detail_blocks(report_markdown)}
    rows = [row for row in rows if row["id"] not in examples or row["id"] in real_ids]
    return rows


def _iter_detail_blocks(report_markdown: str) -> list[tuple[str, str]]:
    """(Fn, block_text) for each Detailed Findings entry -- the text
    between one `### [SEVERITY] Fn:` heading and the next.
    """
    section = _extract_section(report_markdown, "Detailed Findings")
    return [(key, prose_source(block)) for key, block in detail_blocks(section, _DETAIL_HEADING_RE)]


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


def extract_construct_by_id(report_markdown: str) -> dict[str, str]:
    """Fn -> the report's own `**Construct:**` text."""
    result: dict[str, str] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        match = _CONSTRUCT_FIELD_RE.search(block)
        if match:
            result[finding_id] = match.group(1).strip()
    return result


def parse_locations(location: str) -> list[SourceLocation]:
    """Every site in a register Location cell, in order (#112).

    "`server.js:78-102`, `app/routes/session.js:116`" ->
    [("server.js", "78", "102"), ("app/routes/session.js", "116", None)].
    Understands `path`, `path:line`, `path:start-end`, `path:line:col`,
    backticked sites, and comma- or semicolon-separated lists; a site that
    is only a line (":61", "61") reuses the previous site's path. Pieces
    with no letter or digit (a trailing "…") are dropped. A cell with no
    site at all yields [].
    """
    sites: list[SourceLocation] = []
    for piece in _SITE_SEPARATOR_RE.split(location.replace("`", "")):
        piece = piece.strip()
        if not any(ch.isalnum() for ch in piece):
            continue
        bare = _BARE_LINES_RE.fullmatch(piece)
        if bare:
            if sites:
                start, end = _line_range(bare.group("start"), bare.group("end"))
                sites.append(SourceLocation(sites[-1].path, start, end))
            continue
        path, start, end = piece, None, None
        while match := _LINE_TAIL_RE.search(path):
            start, end = match.group("start"), match.group("end")
            path = path[: match.start()]
        path = path.strip()
        if not path:
            continue
        start, end = _line_range(start, end)
        sites.append(SourceLocation(path, start, end))
    return sites


def parse_location(location: str) -> tuple[str, str | None]:
    """The first site of a Location cell as (path, start_line):
    "`app/db.py:42`" -> ("app/db.py", "42"), and
    "`config/env/all.js:8-9`, `db-reset.js:15`" -> ("config/env/all.js", "8").
    This is what location_file/location_line and the fingerprint use; the
    full list is parse_locations(). A cell with no parsable site degrades
    to (text without backticks, None) rather than raising.
    """
    sites = parse_locations(location)
    if not sites:
        return location.strip().replace("`", ""), None
    return sites[0].path, sites[0].start_line


def locations_json(location: str) -> str:
    """parse_locations() as the JSON list stored in the `locations` column
    ("[]" when the cell has no site; NULL in that column means a row stored
    before #112 that the migration has not re-derived yet)."""
    return json.dumps([site.as_dict() for site in parse_locations(location)])


def pre_112_path(location: str) -> str | None:
    """The path the pre-#112 parser stored for this cell, or None when it
    is the same path parse_location() gives today. That parser could still
    "match" a list: "app/db.py, app/cli.py" became one file named
    "app/db.py, app/cli.py", so a regex match alone does not mean the
    identity is unchanged."""
    stripped = location.strip()
    match = _PRE_112_LOCATION_RE.match(stripped)
    old_path = match.group("file").strip() if match else stripped.replace("`", "")
    if _normalize_path(old_path) == _normalize_path(parse_location(location)[0]):
        return None
    return old_path


def pre_112_fingerprint(row: dict[str, str]) -> str | None:
    """The fingerprint a multi-site or ranged location got before #112,
    when the old parser took (most of) the cell as the path -- a path that
    never exists, so no region hash was ever added. runner.py rekeys an
    open row from it so an upgrade does not show those findings as closed
    + new. None when the old parser read the same path as today."""
    old_path = pre_112_path(row["location"])
    if old_path is None:
        return None
    raw = "|".join([SKILL_ID, row.get("cwe", "").strip().lower(), _normalize_path(old_path)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _normalize_path(file_path: str) -> str:
    return file_path.strip().lstrip("./").lower()


def fingerprint_for_row(
    row: dict[str, str],
    *,
    line_bucket: str | None = None,
    region_hash: str | None = None,
) -> str:
    """Stable cross-run identity from contract fields + optional source hash."""
    file_path, _line = parse_location(row["location"])
    cwe = row.get("cwe", "").strip().lower()
    parts = [SKILL_ID, cwe, _normalize_path(file_path)]
    if region_hash:
        parts.append(region_hash)
    elif line_bucket is not None:
        parts.append(f"linebucket:{line_bucket}")
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def legacy_fingerprint_for_row(row: dict[str, str], *, line_bucket: str | None = None) -> str:
    """Pre-region-hash identity (CWE + path [+ line bucket]). Used to rekey open rows on upgrade."""
    return fingerprint_for_row(row, line_bucket=line_bucket, region_hash=None)


def findings_with_fingerprints(
    report_markdown: str,
    *,
    workdir: Path | None = None,
) -> list[dict[str, str]]:
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
    constructs = extract_construct_by_id(report_markdown)

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
        region_hash = None
        if workdir is not None and line is not None:
            region_hash = hash_code_region(workdir, file_path, line)

        line_bucket = None
        if region_hash is None and len(groups[key]) > 1 and line is not None:
            line_bucket = str(int(line) // 20)
        fingerprint = fingerprint_for_row(row, line_bucket=line_bucket, region_hash=region_hash)
        legacy_fingerprint = legacy_fingerprint_for_row(row, line_bucket=line_bucket)

        results.append(
            {
                **row,
                "location_file": file_path,
                "location_line": line,
                "locations": locations_json(row["location"]),
                "code_region_hash": region_hash,
                "fingerprint": fingerprint,
                "legacy_fingerprint": legacy_fingerprint,
                "pre_112_fingerprint": pre_112_fingerprint(row),
                "description": descriptions.get(row["id"], ""),
                "recommendation": recommendations.get(row["id"], ""),
                "construct": constructs.get(row["id"], ""),
            }
        )
    return results
