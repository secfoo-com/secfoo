"""Extracts Secret Scanning report data from raw Markdown for the
per-activity dashboard: the Findings Register table and Detailed Findings
narrative (evidence, exposure, remediation).

Best-effort only — reports without these sections yield empty results
rather than raising, so the dashboard degrades gracefully.
"""

from __future__ import annotations

import re

from secfoo.report.architecture import _extract_section

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
