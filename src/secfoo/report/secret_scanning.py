"""Extracts Secret Scanning report data from raw Markdown for the
per-activity dashboard: the Findings Register table and Detailed Findings
narrative (evidence, exposure, remediation).

Best-effort only — reports without these sections yield empty results
rather than raising, so the dashboard degrades gracefully.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from secfoo.report.architecture import _extract_section
from secfoo.report.code_region import hash_code_region
from secfoo.report.sast import _normalize_path, parse_location

SKILL_ID = "secret-scanning"

# Findings Register: | ID | Secret type | Location | Source | Validity |
# Severity |. Anchored on an "Sn" ID so header/separator rows never match.
_FINDINGS_REGISTER_ROW_RE = re.compile(
    r"^\|\s*(?P<id>S\d+)\s*\|(?P<secret_type>[^|]*)\|(?P<location>[^|]*)\|"
    r"(?P<source>[^|]*)\|(?P<validity>[^|]*)\|(?P<severity>[^|]*)\|\s*$",
    re.MULTILINE,
)

# Detailed Findings heading: "### [SEVERITY] S1: <secret type> in <location>"
_DETAIL_HEADING_RE = re.compile(r"^###\s*\[[A-Za-z]+\]\s*(?P<id>S\d+):", re.MULTILINE)

_EVIDENCE_FIELD_RE = re.compile(r"\*\*Evidence:\*\*\s*([^\n]+)")
_EXPOSURE_FIELD_RE = re.compile(r"\*\*Exposure:\*\*\s*([^\n]+)")
_REMEDIATION_FIELD_RE = re.compile(r"\*\*Remediation:\*\*\s*([^\n]+)")
# Code-free description of how the secret is stored/used -- see
# report/sast.py's _CONSTRUCT_FIELD_RE.
_CONSTRUCT_FIELD_RE = re.compile(r"\*\*Construct:\*\*\s*([^\n]+)")


def extract_findings_register_rows(report_markdown: str) -> list[dict[str, str]]:
    """One dict per row of the Secret Scanning contract's Findings
    Register table -- id/secret_type/location/source/validity/severity,
    all stripped strings. Reports from other skills, or predating this
    contract version, simply yield an empty list.
    """
    section = _extract_section(report_markdown, "Findings Register")
    rows = []
    for match in _FINDINGS_REGISTER_ROW_RE.finditer(section):
        rows.append({key: value.strip() for key, value in match.groupdict().items()})
    return rows


def _iter_detail_blocks(report_markdown: str) -> list[tuple[str, str]]:
    """(Sn, block_text) for each Detailed Findings entry -- the text
    between one `### [SEVERITY] Sn:` heading and the next.
    """
    section = _extract_section(report_markdown, "Detailed Findings")
    headings = list(_DETAIL_HEADING_RE.finditer(section))
    blocks = []
    for i, heading in enumerate(headings):
        start = heading.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(section)
        blocks.append((heading.group("id"), section[start:end]))
    return blocks


def extract_narrative_by_id(report_markdown: str) -> dict[str, dict[str, str]]:
    """Sn -> {"evidence": ..., "exposure": ..., "remediation": ...} -- the
    report's own redacted-evidence fragment, exposure analysis, and
    remediation text. Missing fields are simply absent from the per-id
    dict rather than empty strings.
    """
    result: dict[str, dict[str, str]] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        fields: dict[str, str] = {}
        evidence_match = _EVIDENCE_FIELD_RE.search(block)
        if evidence_match:
            fields["evidence"] = evidence_match.group(1).strip()
        exposure_match = _EXPOSURE_FIELD_RE.search(block)
        if exposure_match:
            fields["exposure"] = exposure_match.group(1).strip()
        remediation_match = _REMEDIATION_FIELD_RE.search(block)
        if remediation_match:
            fields["remediation"] = remediation_match.group(1).strip()
        if fields:
            result[finding_id] = fields
    return result


def extract_construct_by_id(report_markdown: str) -> dict[str, str]:
    """Sn -> the report's own `**Construct:**` text."""
    result: dict[str, str] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        match = _CONSTRUCT_FIELD_RE.search(block)
        if match:
            result[finding_id] = match.group(1).strip()
    return result


def findings_with_narrative(report_markdown: str) -> list[dict[str, str]]:
    """One dict per Findings Register row, joined with its Detailed
    Findings block (evidence/exposure/remediation) -- what
    web/secret_scanning_dashboard.py consumes.
    """
    narrative_by_id = extract_narrative_by_id(report_markdown)
    results = []
    for row in extract_findings_register_rows(report_markdown):
        narrative = narrative_by_id.get(row["id"], {})
        results.append(
            {
                **row,
                "evidence": narrative.get("evidence", ""),
                "exposure": narrative.get("exposure", ""),
                "remediation": narrative.get("remediation", ""),
            }
        )
    return results


# Leading characters of the report's redacted evidence kept on a
# persisted row. The contract already asks for at most ~8, but a model
# that over-shares shouldn't turn the findings table into a secret store.
EVIDENCE_KEEP_CHARS = 8


def redact_evidence(evidence: str | None) -> str | None:
    """Re-redacts the report's own evidence fragment to its first
    EVIDENCE_KEEP_CHARS non-markup characters, whatever the model wrote."""
    if not evidence:
        return None
    cleaned = evidence.strip().strip("`").strip()
    for marker in ("...", "…"):
        cleaned = cleaned.split(marker, 1)[0]
    cleaned = cleaned.strip().strip("`")
    if not cleaned:
        return None
    return cleaned[:EVIDENCE_KEEP_CHARS] + "..."


def _normalize_secret_type(secret_type: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", secret_type.lower()).strip("-")


def fingerprint_for_row(
    row: dict[str, str],
    *,
    file_path: str,
    region_hash: str | None = None,
    line_bucket: str | None = None,
) -> str:
    """Skill + secret type + normalized location (+ code-region hash, or
    the same-run line-bucket collision guard) -- same rationale as
    report/sast.py's fingerprint: never the model's prose."""
    parts = [SKILL_ID, _normalize_secret_type(row.get("secret_type", "")), _normalize_path(file_path)]
    if region_hash:
        parts.append(region_hash)
    elif line_bucket is not None:
        parts.append(f"linebucket:{line_bucket}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def findings_with_fingerprints(
    report_markdown: str, *, workdir: Path | None = None
) -> list[dict[str, str | None]]:
    """findings_with_narrative() plus parsed location, re-redacted
    evidence, construct, and a fingerprint -- what
    runner.update_secret_findings persists."""
    constructs = extract_construct_by_id(report_markdown)
    rows = findings_with_narrative(report_markdown)
    parsed = [parse_location(row["location"]) for row in rows]
    groups: dict[tuple[str, str], int] = {}
    for row, (file_path, _line) in zip(rows, parsed):
        key = (_normalize_secret_type(row["secret_type"]), _normalize_path(file_path))
        groups[key] = groups.get(key, 0) + 1

    results = []
    for row, (file_path, line) in zip(rows, parsed):
        key = (_normalize_secret_type(row["secret_type"]), _normalize_path(file_path))
        region_hash = None
        if workdir is not None and line is not None and row.get("source", "").lower() != "history":
            region_hash = hash_code_region(workdir, file_path, line)
        line_bucket = None
        if region_hash is None and groups[key] > 1 and line is not None:
            line_bucket = str(int(line) // 20)
        results.append(
            {
                **row,
                "evidence": redact_evidence(row.get("evidence")),
                "location_file": file_path,
                "location_line": line,
                "code_region_hash": region_hash,
                "construct": constructs.get(row["id"], ""),
                "fingerprint": fingerprint_for_row(
                    row, file_path=file_path, region_hash=region_hash, line_bucket=line_bucket
                ),
            }
        )
    return results
