"""Extracts SCA-report-specific structured data from a report's raw
Markdown for the per-activity dashboard: the dependency inventory (for
ecosystem lookup), the risk register (the actual findings table), and
what the LLM itself wrote in the `**CVE:**` field of each detailed
finding. Best-effort only -- a report that doesn't carry these (a
different skill's report, or an older report predating this contract
version) just yields an empty list/dict rather than raising, so the
dashboard degrades gracefully instead of erroring. Mirrors
`report/architecture.py`'s extraction idiom exactly.

Also the single source of truth for resolving a Risk Register row's
ecosystem (joining it back against that same report's own Dependency
Inventory table, since Risk Register itself has no Ecosystem column) and
for turning a whole report into the set of OSV.dev lookup keys it needs --
shared by runner.py's post-run enrichment hook and web/sca_dashboard.py's
dashboard builder, so that join logic lives in exactly one place rather
than being duplicated between "core" and "web" callers.
"""

from __future__ import annotations

import hashlib
import re

from secfoo import osv
from secfoo.report.architecture import _extract_section

SKILL_ID = "sca-reachability"

# Dependency Inventory: | Package | Version | Direct/Transitive | Ecosystem
# | Source manifest |. No ID column to anchor on (unlike Risk Register's
# `D1`), so header/separator rows are filtered out after matching -- see
# _is_table_furniture.
_DEPENDENCY_INVENTORY_ROW_RE = re.compile(
    r"^\|(?P<package>[^|]+)\|(?P<version>[^|]+)\|(?P<directness>[^|]+)\|"
    r"(?P<ecosystem>[^|]+)\|(?P<source_manifest>[^|]+)\|\s*$",
    re.MULTILINE,
)

# Risk Register: | ID | Package | Version | Issue | Severity | Reachability
# | Fixed in |. Anchored on a "Dn" ID so header/separator rows never match.
_RISK_REGISTER_ROW_RE = re.compile(
    r"^\|\s*(?P<id>D\d+)\s*\|(?P<package>[^|]*)\|(?P<version>[^|]*)\|(?P<issue>[^|]*)\|"
    r"(?P<severity>[^|]*)\|(?P<reachability>[^|]*)\|(?P<fixed_in>[^|]*)\|\s*$",
    re.MULTILINE,
)

# Detailed Findings heading: "### [SEVERITY] D1: package@version -- title"
_DETAIL_HEADING_RE = re.compile(r"^###\s*\[[A-Za-z]+\]\s*(?P<id>D\d+):", re.MULTILINE)

# Within one finding's block: "- **Package / version:**, **CVE:** <value>, **Severity:** ..."
_CVE_FIELD_RE = re.compile(r"\*\*CVE:\*\*\s*([^\n,]+)")

# These two are each their own bullet line ("- **Reachability:** ... evidence"),
# not comma-separated like CVE, so they run to end of line rather than to
# the next comma.
_REACHABILITY_FIELD_RE = re.compile(r"\*\*Reachability:\*\*\s*([^\n]+)")
_RECOMMENDATION_FIELD_RE = re.compile(r"\*\*Recommendation:\*\*\s*([^\n]+)")
# Code-free description of the vulnerable usage -- see report/sast.py's
# _CONSTRUCT_FIELD_RE for why this field exists.
_CONSTRUCT_FIELD_RE = re.compile(r"\*\*Construct:\*\*\s*([^\n]+)")

# A CVE/GHSA/OSV-style identifier. Anything else the model wrote in the
# CVE field ("unverified", prose) is not an identity.
_ADVISORY_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+)$", re.IGNORECASE)
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")

_SEPARATOR_CELL_RE = re.compile(r"^[\s:\-]+$")


def _is_table_furniture(first_cell: str) -> bool:
    """True for a Markdown table's own header ("Package") or separator
    ("---", ":---:", ...) row, which the row regex above -- having no ID
    column to anchor on, unlike Risk Register -- would otherwise match as
    if it were real data.
    """
    stripped = first_cell.strip()
    if stripped.lower() == "package":
        return True
    return bool(_SEPARATOR_CELL_RE.match(stripped)) and "-" in stripped


def extract_dependency_inventory_rows(report_markdown: str) -> list[dict[str, str]]:
    """One dict per row of the SCA contract's Dependency Inventory table --
    package/version/directness/ecosystem/source_manifest, all stripped
    strings. This is what a Risk Register row's ecosystem gets joined
    against, since the Risk Register table itself has no Ecosystem column.
    """
    section = _extract_section(report_markdown, "Dependency Inventory")
    rows = []
    for match in _DEPENDENCY_INVENTORY_ROW_RE.finditer(section):
        data = {key: value.strip() for key, value in match.groupdict().items()}
        if _is_table_furniture(data["package"]):
            continue
        rows.append(data)
    return rows


def extract_risk_register_rows(report_markdown: str) -> list[dict[str, str]]:
    """One dict per row of the SCA contract's Risk Register table --
    id/package/version/issue/severity/reachability/fixed_in, all stripped
    strings. Reports from other skills, or from an SCA report predating
    this contract version, simply yield an empty list.
    """
    section = _extract_section(report_markdown, "Risk Register")
    rows = []
    for match in _RISK_REGISTER_ROW_RE.finditer(section):
        rows.append({key: value.strip() for key, value in match.groupdict().items()})
    return rows


def _iter_detail_blocks(report_markdown: str) -> list[tuple[str, str]]:
    """(Dn, block_text) for each Detailed Findings entry -- the text
    between one `### [SEVERITY] Dn:` heading and the next. Shared by every
    per-finding-block extractor below so the heading-splitting logic
    exists exactly once.
    """
    section = _extract_section(report_markdown, "Detailed Findings")
    headings = list(_DETAIL_HEADING_RE.finditer(section))
    blocks = []
    for i, heading in enumerate(headings):
        start = heading.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(section)
        blocks.append((heading.group("id"), section[start:end]))
    return blocks


def extract_cve_by_dependency_id(report_markdown: str) -> dict[str, str]:
    """Dn -> the report's own `**CVE:**` text ("unverified" or a
    real-looking ID the LLM wrote). This is DISPLAY text only -- it is
    never auto-correlated against real OSV IDs, since an LLM-written
    "looks like a CVE" string is not the same as a database match.
    """
    result: dict[str, str] = {}
    for dep_id, block in _iter_detail_blocks(report_markdown):
        match = _CVE_FIELD_RE.search(block)
        if match:
            result[dep_id] = match.group(1).strip().rstrip(".")
    return result


def extract_narrative_by_dependency_id(report_markdown: str) -> dict[str, dict[str, str]]:
    """Dn -> {"reachability_evidence": ..., "recommendation": ...}, the
    report's own explanation of why this finding matters and what to do
    about it -- the risk-narrative text a vulnerability detail page shows
    alongside the structured Risk Register fields. Missing fields are
    simply absent from the per-id dict rather than empty strings.
    """
    result: dict[str, dict[str, str]] = {}
    for dep_id, block in _iter_detail_blocks(report_markdown):
        fields: dict[str, str] = {}
        reachability_match = _REACHABILITY_FIELD_RE.search(block)
        if reachability_match:
            fields["reachability_evidence"] = reachability_match.group(1).strip()
        recommendation_match = _RECOMMENDATION_FIELD_RE.search(block)
        if recommendation_match:
            fields["recommendation"] = recommendation_match.group(1).strip()
        construct_match = _CONSTRUCT_FIELD_RE.search(block)
        if construct_match:
            fields["construct"] = construct_match.group(1).strip()
        if fields:
            result[dep_id] = fields
    return result


def inventory_lookup(report_markdown: str) -> dict[tuple[str, str], str]:
    """(package.lower(), version) -> ecosystem, from one report's own
    Dependency Inventory table.
    """
    return {
        (row["package"].strip().lower(), row["version"].strip()): row["ecosystem"].strip()
        for row in extract_dependency_inventory_rows(report_markdown)
    }


def resolve_ecosystem(
    package: str, version: str, inventory_by_package_version: dict[tuple[str, str], str]
) -> tuple[str | None, str | None]:
    """(ecosystem_raw, ecosystem_osv) for one Risk Register row -- both
    None if the package@version isn't in that report's own inventory;
    ecosystem_osv alone is None if the raw value doesn't normalize to a
    recognized OSV ecosystem. Never a guess either way.
    """
    ecosystem_raw = inventory_by_package_version.get((package.strip().lower(), version.strip()))
    ecosystem_osv_value = osv.normalize_ecosystem(ecosystem_raw) if ecosystem_raw else None
    return ecosystem_raw, ecosystem_osv_value


def osv_keys_for_report(report_markdown: str) -> set[tuple[str, str, str]]:
    """Every (ecosystem, package, version) triple this one report's Risk
    Register flags that has a recognized OSV ecosystem -- exactly what
    `osv.enrich_lookups` should be asked to look up for this report.
    Shared by runner.py's post-run enrichment hook and
    web/sca_dashboard.py's dashboard builder.
    """
    inventory_by_package_version = inventory_lookup(report_markdown)
    keys: set[tuple[str, str, str]] = set()
    for row in extract_risk_register_rows(report_markdown):
        _ecosystem_raw, ecosystem_osv_value = resolve_ecosystem(
            row["package"], row["version"], inventory_by_package_version
        )
        if ecosystem_osv_value:
            keys.add((ecosystem_osv_value, row["package"].strip(), row["version"].strip()))
    return keys


def is_advisory_id(value: str | None) -> bool:
    return bool(value) and bool(_ADVISORY_ID_RE.match(value.strip()))


def fingerprint_for_row(
    row: dict[str, str], *, ecosystem: str | None, advisory_id: str | None, issue_key: str | None = None
) -> str:
    """Stable cross-run identity for one Risk Register row: skill +
    ecosystem + package, plus the advisory ID when the report named a real
    one. Deliberately NOT the version -- a bump that doesn't fix the issue
    is still the same open finding, and a bump that does fix it simply
    stops being reported and closes it. `issue_key` is the same-run
    collision guard (see findings_with_fingerprints).
    """
    parts = [SKILL_ID, (ecosystem or "").strip().lower(), row["package"].strip().lower()]
    if advisory_id:
        parts.append(advisory_id.strip().upper())
    elif issue_key:
        parts.append(f"issue:{issue_key}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def findings_with_fingerprints(report_markdown: str) -> list[dict[str, str | None]]:
    """One dict per Risk Register row, joined with its ecosystem (from the
    same report's Dependency Inventory), its Detailed Findings narrative
    (CVE, reachability evidence, recommendation, construct) and its
    fingerprint -- what runner.update_sca_findings persists.

    Same-run collision guard, mirroring report/sast.py: only when two rows
    in this one report share ecosystem + package and neither names a real
    advisory ID does the normalized issue text get appended, so two real
    findings never silently collapse into one lifecycle entry.
    """
    rows = extract_risk_register_rows(report_markdown)
    inventory = inventory_lookup(report_markdown)
    cves = extract_cve_by_dependency_id(report_markdown)
    narratives = extract_narrative_by_dependency_id(report_markdown)

    prepared = []
    groups: dict[tuple[str, str], int] = {}
    for row in rows:
        ecosystem_raw, ecosystem_osv_value = resolve_ecosystem(row["package"], row["version"], inventory)
        ecosystem = ecosystem_osv_value or ecosystem_raw
        cve_text = cves.get(row["id"], "")
        advisory_id = cve_text.strip() if is_advisory_id(cve_text) else None
        key = ((ecosystem or "").lower(), row["package"].strip().lower())
        if advisory_id is None:
            groups[key] = groups.get(key, 0) + 1
        prepared.append((row, ecosystem, cve_text, advisory_id, key))

    results = []
    for row, ecosystem, cve_text, advisory_id, key in prepared:
        issue_key = None
        if advisory_id is None and groups.get(key, 0) > 1:
            issue_key = _NON_ALNUM_RE.sub("-", row["issue"].lower()).strip("-")
        narrative = narratives.get(row["id"], {})
        results.append(
            {
                **row,
                "ecosystem": ecosystem,
                "cve": cve_text or None,
                "reachability_evidence": narrative.get("reachability_evidence", ""),
                "recommendation": narrative.get("recommendation", ""),
                "construct": narrative.get("construct", ""),
                "fingerprint": fingerprint_for_row(
                    row, ecosystem=ecosystem, advisory_id=advisory_id, issue_key=issue_key
                ),
            }
        )
    return results
