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
                "code_region_hash": region_hash,
                "fingerprint": fingerprint,
                "legacy_fingerprint": legacy_fingerprint,
                "description": descriptions.get(row["id"], ""),
                "recommendation": recommendations.get(row["id"], ""),
            }
        )
    return results
