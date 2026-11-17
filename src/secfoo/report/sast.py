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
import re
from pathlib import Path

from secfoo.report.architecture import _extract_section
from secfoo.report.code_region import hash_code_region

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

# Bare line or range token without a file path (e.g. "61" or "61-65" in
# "`artifacts/db-reset.js:18,27,35`"), which inherits the previous site's path.
_BARE_SPAN_RE = re.compile(
    r"^(?:[Ll](?:ine)?s?\s*)?(?P<start>[0-9]+)(?:\s*(?:[-–—]|\.\.\.?)\s*(?:[Ll](?:ine)?s?\s*)?(?P<end>[0-9]+))?$"
)

# Trailing `:line` or `:start-end` suffix on a path (including bare `:61`
# where the prefix before `:` is empty, and chained `:line:col` suffixes).
_TRAILING_SPAN_RE = re.compile(
    r":\s*(?:[Ll](?:ine)?s?\s*)?(?P<neg>[-–—])?\s*(?P<start>\d+)"
    r"(?:\s*(?:[-–—]|\.\.\.?)\s*(?:[Ll](?:ine)?s?\s*)?(?P<end>\d*)(?:\s*[-–—]\s*\d+)*)?\s*$"
)


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


def extract_construct_by_id(report_markdown: str) -> dict[str, str]:
    """Fn -> the report's own `**Construct:**` text."""
    result: dict[str, str] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        match = _CONSTRUCT_FIELD_RE.search(block)
        if match:
            result[finding_id] = match.group(1).strip()
    return result


def _parse_line_span(
    start_text: str | None,
    end_text: str | None = None,
    *,
    negative: bool = False,
) -> tuple[int | None, int | None]:
    """Normalize parsed start/end strings into 1-based `(start_line, end_line)`."""
    if negative or not start_text or not (start_text.isascii() and start_text.isdigit()):
        return None, None
    start = int(start_text)
    if start < 1:
        return None, None
    end: int | None = None
    if end_text and end_text.isascii() and end_text.isdigit():
        parsed_end = int(end_text)
        if parsed_end >= 1 and parsed_end != start:
            if parsed_end < start:
                start, end = parsed_end, start
            else:
                end = parsed_end
    return start, end


def parse_locations(location: str) -> list[tuple[str, int | None, int | None]]:
    """Parse a Markdown Location cell into `(path, start_line, end_line)` sites.

    Handles `path:line`, `path:start-end`, `path:line,line`, backticked spans,
    comma/semicolon-separated multi-file lists, bare `:61` continuations that
    inherit the previous path, and trailing ellipsis markers (`...` / `…`).
    """
    cleaned = location.replace("`", "")
    sites: list[tuple[str, int | None, int | None]] = []
    prev_path: str | None = None

    for raw_token in re.split(r"[,;]", cleaned):
        token = raw_token.strip()
        if not token or token in {"...", "…"}:
            continue

        if prev_path is not None:
            bare_match = _BARE_SPAN_RE.fullmatch(token)
            if bare_match:
                start, end = _parse_line_span(bare_match.group("start"), bare_match.group("end"))
                if start is not None:
                    sites.append((prev_path, start, end))
                    continue

        path_part = token
        peeled: list[tuple[str | None, str, str | None]] = []
        while True:
            trimmed = path_part.rstrip()
            if trimmed.endswith(":"):
                path_part = trimmed.rstrip(":").rstrip()
                continue
            span_match = _TRAILING_SPAN_RE.search(path_part)
            if not span_match:
                break
            peeled.append((span_match.group("neg"), span_match.group("start"), span_match.group("end")))
            path_part = path_part[: span_match.start()].rstrip()

        start_line: int | None = None
        end_line: int | None = None
        if peeled:
            neg, start_raw, end_raw = peeled[-1]
            start_line, end_line = _parse_line_span(start_raw, end_raw, negative=bool(neg))

        path_part = path_part.strip()
        if not path_part:
            if prev_path is not None and start_line is not None:
                sites.append((prev_path, start_line, end_line))
            continue

        if path_part in {"...", "…"}:
            continue

        prev_path = path_part
        sites.append((path_part, start_line, end_line))

    return sites


def locations_to_dicts(
    sites: list[tuple[str, int | None, int | None]],
) -> list[dict[str, str | int | None]]:
    """Serialize `(path, start_line, end_line)` tuples for JSON storage/export."""
    return [
        {"path": path, "start_line": start_line, "end_line": end_line}
        for path, start_line, end_line in sites
    ]


def locations_from_raw(
    location_file: str | None,
    location_line: str | None = None,
) -> list[dict[str, str | int | None]]:
    """Derive structured `locations` dicts from stored `(location_file, location_line)`."""
    if not location_file or not location_file.strip():
        return []
    sites = parse_locations(location_file)
    if not sites:
        return []
    if location_line is not None and len(sites) == 1 and sites[0][1] is None:
        line_token = location_line.strip().lstrip(":").strip()
        span_match = _BARE_SPAN_RE.fullmatch(line_token)
        if span_match:
            start, end = _parse_line_span(span_match.group("start"), span_match.group("end"))
            if start is not None:
                sites = [(sites[0][0], start, end)]
    return locations_to_dicts(sites)


def format_location_site(site: dict[str, object] | tuple[str, int | None, int | None]) -> str:
    """Render one location site as `path`, `path:line`, or `path:start-end`."""
    if isinstance(site, tuple):
        path, start, end = site
    else:
        path = str(site.get("path") or "")
        start = site.get("start_line")  # type: ignore[assignment]
        end = site.get("end_line")  # type: ignore[assignment]
    if not path:
        return ""
    if isinstance(start, int) and not isinstance(start, bool) and start > 0:
        if isinstance(end, int) and not isinstance(end, bool) and end > start:
            return f"{path}:{start}-{end}"
        return f"{path}:{start}"
    return path


def parse_location(location: str) -> tuple[str, str | None]:
    """Return `(first_path, first_start_line)` from a Markdown Location cell.

    Multi-site cells (`server.js:135-137, app/views/layout.html:75`) and line
    ranges (`config/env/all.js:8-9`) resolve to their primary site (`("server.js",
    "135")`, `("config/env/all.js", "8")`) so fingerprinting and `hash_code_region`
    operate on a real file path and integer start line; callers that need every
    site use `parse_locations`.
    """
    sites = parse_locations(location)
    if not sites:
        return "", None
    first_path, first_start, _first_end = sites[0]
    return first_path, (str(first_start) if first_start is not None else None)


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
) -> list[dict[str, object]]:
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
    parsed_sites_per_row: list[list[tuple[str, int | None, int | None]]] = []
    parsed_locations: list[tuple[str, str | None]] = []
    for row in rows:
        sites = parse_locations(row["location"])
        parsed_sites_per_row.append(sites)
        if sites:
            file_path = sites[0][0]
            line = str(sites[0][1]) if sites[0][1] is not None else None
        else:
            file_path, line = "", None
        parsed_locations.append((file_path, line))
        key = (row.get("cwe", "").strip().lower(), _normalize_path(file_path))
        groups.setdefault(key, []).append(len(parsed_locations) - 1)

    results: list[dict[str, object]] = []
    for index, row in enumerate(rows):
        file_path, line = parsed_locations[index]
        sites = parsed_sites_per_row[index]
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
                "locations": locations_to_dicts(sites),
                "code_region_hash": region_hash,
                "fingerprint": fingerprint,
                "legacy_fingerprint": legacy_fingerprint,
                "description": descriptions.get(row["id"], ""),
                "recommendation": recommendations.get(row["id"], ""),
                "construct": constructs.get(row["id"], ""),
            }
        )
    return results
