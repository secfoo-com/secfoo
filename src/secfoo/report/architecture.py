"""Extracts architecture-review-specific signals from a report's raw
Markdown for the per-activity dashboard: the data flow diagram, the design
verdict, and how many trust boundaries were identified. Best-effort only --
a report that doesn't carry these (a different skill's report, or an older
report predating this contract version) just yields None/zero rather than
raising, so the dashboard degrades gracefully instead of erroring.
"""

from __future__ import annotations

import re

_MERMAID_BLOCK_RE = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)
_DESIGN_VERDICT_RE = re.compile(r"\*\*Design verdict:\*\*\s*([^\n]+)", re.IGNORECASE)
_BOUNDARY_ID_RE = re.compile(r"^\|\s*(B\d+)\s*\|", re.MULTILINE)

# The real CSA Cloud Controls Matrix v4 domains -- 17 total, in the order
# the Security Architecture Review contract asks the CCM Domain Conformance
# table to use. Not a taxonomy secfoo invented: these are the standard
# CCM v4 domain codes and names.
CCM_DOMAINS = [
    ("A&A", "Audit & Assurance"),
    ("AIS", "Application & Interface Security"),
    ("BCR", "Business Continuity Management and Operational Resilience"),
    ("CCC", "Change Control and Configuration Management"),
    ("CEK", "Cryptography, Encryption & Key Management"),
    ("DCS", "Datacenter Security"),
    ("DSP", "Data Security and Privacy Lifecycle Management"),
    ("GRC", "Governance, Risk and Compliance"),
    ("HRS", "Human Resources Security"),
    ("IAM", "Identity & Access Management"),
    ("IPY", "Interoperability & Portability"),
    ("IVS", "Infrastructure & Virtualization Security"),
    ("LOG", "Logging and Monitoring"),
    ("SEF", "Security Incident Management, E-Discovery, and Cloud Forensics"),
    ("STA", "Supply Chain Management, Transparency, and Accountability"),
    ("TVM", "Threat & Vulnerability Management"),
    ("UEM", "Universal Endpoint Management"),
]
_CCM_CODES = {code for code, _ in CCM_DOMAINS}

# Matches a Findings Register row: | ID | Finding | Severity | Category |
# Standard | Verdict |. Anchored on an ID like "A1" so it doesn't pick up
# rows from other tables (Security Controls Matrix, CCM table, etc.) that
# happen to share a similar pipe shape.
_FINDINGS_REGISTER_ROW_RE = re.compile(
    r"^\|\s*[A-Za-z]\d+\s*\|(?P<finding>[^|]*)\|(?P<severity>[^|]*)\|"
    r"(?P<category>[^|]*)\|(?P<standard>[^|]*)\|(?P<verdict>[^|]*)\|\s*$",
    re.MULTILINE,
)

# | Domain name | CODE | Conformance | Evidence |
_CCM_ROW_RE = re.compile(
    r"^\|[^|]*\|\s*(?P<code>[A-Z&]{2,4})\s*\|(?P<conformance>[^|]*)\|", re.MULTILINE
)

# Threat Modeling's Threat Register: | ID | Threat | Archetype | Asset
# Class | Boundary | STRIDE | Severity | Disposition | Test Reference |
_THREAT_REGISTER_ROW_RE = re.compile(
    r"^\|\s*(?P<id>T\d+)\s*\|(?P<threat>[^|]*)\|(?P<archetype>[^|]*)\|(?P<asset_class>[^|]*)\|"
    r"(?P<boundary>[^|]*)\|(?P<stride>[^|]*)\|(?P<severity>[^|]*)\|(?P<disposition>[^|]*)\|"
    r"(?P<test_reference>[^|]*)\|\s*$",
    re.MULTILINE,
)

_MODEL_DEPTH_RE = re.compile(r"\*\*Model depth:\*\*\s*([^\n]+)", re.IGNORECASE)

# Threat Modeling's Assumptions table: | ID | Assumption | Validity | Note |
_ASSUMPTION_ROW_RE = re.compile(
    r"^\|\s*[A-Za-z]\d+\s*\|(?P<assumption>[^|]*)\|(?P<validity>[^|]*)\|(?P<note>[^|]*)\|\s*$",
    re.MULTILINE,
)

_EXCLUDED_STANDARD_VALUES = {"n/a", "na", "none", "general practice", "-", ""}
_CONFORMANCE_SCORE = {"conformant": 100.0, "partial": 50.0, "non-conformant": 0.0}


def _extract_section(report_markdown: str, title: str) -> str:
    """Text between a `## [N.] <title>` heading and the next `## ` heading.
    The section number prefix is optional in the match so this stays
    correct if sections get renumbered later. Empty string if not found.
    """
    pattern = re.compile(
        rf"^##\s*(?:\d+\.\s*)?{re.escape(title)}.*?\n(.*?)(?=^##\s|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(report_markdown)
    return match.group(1) if match else ""


def extract_mermaid_diagram(report_markdown: str) -> str | None:
    """First Mermaid diagram in the report, if any (Security Architecture
    Review and Threat Modeling both produce one; other skills don't).
    """
    match = _MERMAID_BLOCK_RE.search(report_markdown)
    return match.group(1).strip() if match else None


def extract_design_verdict(report_markdown: str) -> str | None:
    """The Security Architecture Review contract's closing verdict line
    (Sound / Sound with conditions / Not sound). Other skills don't
    produce this line, so this is None for their reports.
    """
    match = _DESIGN_VERDICT_RE.search(report_markdown)
    return match.group(1).strip().rstrip(".") if match else None


def count_trust_boundaries(report_markdown: str) -> int:
    """Distinct Bn boundary IDs appearing in a table row -- the Security
    Architecture Review contract's diagram/table cross-referencing scheme
    (see skills/renderer.py). Reports that don't use it count 0.
    """
    return len(set(_BOUNDARY_ID_RE.findall(report_markdown)))


def extract_verdict_counts(report_markdown: str) -> dict[str, int]:
    """Confirmed/Conditional/Latent counts from the Findings Register
    table specifically -- not prose, which might use these words in
    passing. Used as a proxy for finding disposition: Confirmed reads as
    an open, exploitable-as-is finding; Conditional as a claimed-but-not-
    independently-reverified mitigation (a stated precondition reduces
    exploitability); Latent as not currently reachable.
    """
    section = _extract_section(report_markdown, "Findings Register")
    counts = {"confirmed": 0, "conditional": 0, "latent": 0}
    for match in _FINDINGS_REGISTER_ROW_RE.finditer(section):
        verdict = match.group("verdict").strip().lower()
        if verdict in counts:
            counts[verdict] += 1
    return counts


def extract_root_causes(report_markdown: str) -> list[str]:
    """Category value for each row in the Findings Register table -- the
    closest thing to a root-cause tag the contract already produces
    (Authentication, Authorization, Secrets Management, ...).
    """
    section = _extract_section(report_markdown, "Findings Register")
    return [
        match.group("category").strip()
        for match in _FINDINGS_REGISTER_ROW_RE.finditer(section)
        if match.group("category").strip()
    ]


def extract_standards_deviated(report_markdown: str) -> list[str]:
    """Standard value for each row in the Findings Register table,
    excluding "N/A"-style placeholders for findings with no specific
    standard reference.
    """
    section = _extract_section(report_markdown, "Findings Register")
    values = []
    for match in _FINDINGS_REGISTER_ROW_RE.finditer(section):
        standard = match.group("standard").strip()
        if standard.lower() not in _EXCLUDED_STANDARD_VALUES:
            values.append(standard)
    return values


def extract_ccm_conformance(report_markdown: str) -> dict[str, str]:
    """CCM domain code -> conformance value (Conformant / Partial /
    Non-conformant / "Not Assessed (process-assured)" / Not Applicable),
    from the CCM Domain Conformance table. Only recognized domain codes
    are kept -- an unrecognized code is more likely a parsing false
    positive than a real 18th domain.
    """
    section = _extract_section(report_markdown, "CCM Domain Conformance")
    result: dict[str, str] = {}
    for match in _CCM_ROW_RE.finditer(section):
        code = match.group("code").strip()
        if code in _CCM_CODES:
            result[code] = match.group("conformance").strip()
    return result


def conformance_to_score(value: str) -> float | None:
    """Numeric score (0/50/100) for a conformance value, or None when it's
    process-assured / not applicable -- those are hatched on the heatmap
    rather than averaged into a numeric conformance %, since scoring
    "not assessed" as 0% would misrepresent it as a failure.
    """
    lowered = value.lower()
    for key, score in _CONFORMANCE_SCORE.items():
        if lowered.startswith(key):
            return score
    return None


def is_process_assured(value: str) -> bool:
    return "process-assured" in value.lower()


def extract_threat_register_rows(report_markdown: str) -> list[dict[str, str]]:
    """One dict per row of the Threat Modeling contract's Threat Register
    table -- id/threat/archetype/asset_class/boundary/stride/severity/
    disposition/test_reference, all stripped strings. Reports from other
    skills, or from a threat-modeling report predating this contract
    version, simply yield an empty list.
    """
    section = _extract_section(report_markdown, "Threat Register")
    rows = []
    for match in _THREAT_REGISTER_ROW_RE.finditer(section):
        rows.append({key: value.strip() for key, value in match.groupdict().items()})
    return rows


def extract_model_depth(report_markdown: str) -> str | None:
    """The Threat Modeling contract's self-declared model depth (Full /
    Feature-level / Lightweight), normalized to one of those three labels
    when the agent's phrasing starts with a recognizable one -- otherwise
    the raw stated value, rather than silently discarding it.
    """
    match = _MODEL_DEPTH_RE.search(report_markdown)
    if match is None:
        return None
    value = match.group(1).strip().rstrip(".")
    lowered = value.lower()
    if lowered.startswith("full"):
        return "Full"
    if lowered.startswith("feature"):
        return "Feature-level"
    if lowered.startswith("light"):
        return "Lightweight"
    return value


def extract_assumption_validity_counts(report_markdown: str) -> dict[str, int]:
    """Holds/Falsified/Unverified counts from the Assumptions table."""
    section = _extract_section(report_markdown, "Assumptions")
    counts = {"holds": 0, "falsified": 0, "unverified": 0}
    for match in _ASSUMPTION_ROW_RE.finditer(section):
        validity = match.group("validity").strip().lower()
        if validity in counts:
            counts[validity] += 1
    return counts


def extract_falsified_assumptions(report_markdown: str) -> list[str]:
    """Assumption text for each row marked Falsified -- the model's own
    admission of where it was wrong.
    """
    section = _extract_section(report_markdown, "Assumptions")
    return [
        match.group("assumption").strip()
        for match in _ASSUMPTION_ROW_RE.finditer(section)
        if match.group("validity").strip().lower() == "falsified"
    ]


def classify_design_verdict(value: str | None) -> str | None:
    """Buckets a Design verdict line into the "approve / with conditions /
    reject" gate-decision framing -- single source of truth shared by the
    dashboard's gate-decision mix and the design-verdict badge coloring
    (web/templating.py), so the two never drift apart.

    "not sound" is checked before "sound" since the latter is a substring
    of the former.
    """
    v = (value or "").strip().lower()
    if v.startswith("not sound"):
        return "reject"
    if "condition" in v:
        return "conditions"
    if v.startswith("sound"):
        return "approve"
    return None
