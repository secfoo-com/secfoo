"""Pure extraction for Responsible AI Compliance reports.

The skill's own deliverable is a dimension-coverage table plus findings
tagged with a dimension and (optionally) a governance framework -- not a
code-finding register with a CWE column. This module reads those structures
from a report's Markdown without touching the database, in the same
best-effort style as `report/sast.py`: a report that predates the contract
(or is malformed) yields empty structures rather than raising, so callers
can degrade gracefully.

The only cross-structure helper here is `ai_bom_diff`, which compares the
models the report says the system actually uses with the models declared in
an attached AI-BOM. It is deliberately a pure comparison: neither side is
trusted as authoritative, so a mismatch is presented for a human to review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from secfoo.report.markdown import MalformedReportError, detail_blocks, prose_source
from secfoo.report.markdown import section as _section
from secfoo.report.severity import extract_overall_risk_rating

SKILL_ID = "responsible-ai-compliance"

# The seven dimensions in skills/definitions/responsible-ai-compliance.md,
# in the order the contract requires in the coverage table.
DIMENSIONS: tuple[str, ...] = (
    "Documentation",
    "Bias & fairness",
    "Human oversight",
    "Transparency to end users",
    "Data provenance & consent",
    "Framework alignment",
    "Auditability & recourse",
)

VALID_STATUSES = frozenset({"adequate", "partial", "missing", "not applicable"})

_DETAIL_HEADING_RE = re.compile(r"^###\s*\[[A-Za-z]+\]\s*(?P<id>F\d+):", re.MULTILINE)
_ROW_ID_RE = re.compile(r"^F\d+$")
_FIELD_RES = {
    "dimension": re.compile(r"\*\*Dimension:\*\*\s*([^\n]+)"),
    "framework": re.compile(r"\*\*Framework:\*\*\s*([^\n]+)"),
    "stakes": re.compile(r"\*\*Stakes:\*\*\s*([^\n]+)"),
    "description": re.compile(r"\*\*Description:\*\*\s*([^\n]+)"),
    "recommendation": re.compile(r"\*\*Recommendation:\*\*\s*([^\n]+)"),
}


@dataclass(frozen=True)
class AIProfile:
    """What the report says the system actually is and does."""

    models: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()
    decides: str = ""
    affected: str = ""
    stakes_tier: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "models": list(self.models),
            "providers": list(self.providers),
            "decides": self.decides,
            "affected": self.affected,
            "stakes_tier": self.stakes_tier,
        }


@dataclass(frozen=True)
class DimensionCoverage:
    dimension: str
    status: str
    evidence: str = ""
    finding_ids: tuple[str, ...] = ()
    stakes_tier: str = ""


@dataclass(frozen=True)
class RaiFinding:
    finding_id: str
    title: str
    severity: str
    dimension: str = ""
    framework: str = ""
    stakes: str = ""
    description: str = ""
    recommendation: str = ""


@dataclass(frozen=True)
class ResponsibleAiReport:
    overall_rating: str | None = None
    profile: AIProfile = field(default_factory=AIProfile)
    dimensions: tuple[DimensionCoverage, ...] = ()
    findings: tuple[RaiFinding, ...] = ()
    remediation_roadmap: str = ""


def _prose_section(text: str, title: str) -> str:
    try:
        return prose_source(_section(text, title))
    except MalformedReportError:
        # A broken fenced block elsewhere in the report must not hide the
        # structured data we can still read.
        return ""


def _split_row(line: str) -> list[str]:
    """Split a Markdown table row, allowing escaped pipes inside cells."""
    if not line.strip().startswith("|"):
        return []
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line.strip().strip("|"):
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    cells.append("".join(current).strip())
    return cells


def _is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell or "") for cell in cells)


def _table_rows(section_text: str) -> list[list[str]]:
    rows = []
    for line in section_text.splitlines():
        cells = _split_row(line)
        if not cells or _is_separator(cells):
            continue
        rows.append(cells)
    return rows


def _canonical_dimension(value: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.strip().lower()).strip()
    aliases = {
        "documentation": "Documentation",
        "bias fairness": "Bias & fairness",
        "bias and fairness": "Bias & fairness",
        "human oversight": "Human oversight",
        "transparency to end users": "Transparency to end users",
        "transparency": "Transparency to end users",
        "data provenance consent": "Data provenance & consent",
        "data provenance and consent": "Data provenance & consent",
        "framework alignment": "Framework alignment",
        "auditability recourse": "Auditability & recourse",
        "auditability and recourse": "Auditability & recourse",
    }
    return aliases.get(normalized)


def _normalize_status(value: str) -> str:
    text = value.strip().lower().replace("_", " ")
    text = re.sub(r"\s+", " ", text)
    if text.startswith(("n a", "not applicable")) or text in {"na", "n/a", "--", "-"}:
        return "not applicable"
    return text if text in VALID_STATUSES else ""


def _split_models(cell: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """`gpt-4o (OpenAI), Claude (Anthropic)` -> models + providers."""
    models: list[str] = []
    providers: list[str] = []
    for part in re.split(r"[,;\n]", cell):
        part = part.strip().strip("`*")
        if not part:
            continue
        match = re.match(r"^(?P<model>[^(]+?)\s*\((?P<provider>[^)]+)\)\s*$", part)
        if match:
            models.append(match.group("model").strip())
            providers.append(match.group("provider").strip())
        else:
            models.append(part)
    return tuple(models), tuple(providers)


def extract_ai_profile(report_markdown: str) -> AIProfile:
    """Read the two-column AI System Profile table. Unknown labels are
    ignored rather than guessed -- the schema should stay the source of
    truth for what a profile contains.
    """
    fields: dict[str, str] = {}
    for row in _table_rows(_prose_section(report_markdown, "AI System Profile")):
        if len(row) < 2:
            continue
        label = row[0].strip().lower()
        value = " ".join(row[1:]).strip()
        if "model" in label or "provider" in label:
            fields.setdefault("models", value)
        elif "decid" in label or "influenc" in label:
            fields.setdefault("decides", value)
        elif "affect" in label or "who" in label:
            fields.setdefault("affected", value)
        elif "stake" in label:
            fields.setdefault("stakes_tier", value)
    models, providers = _split_models(fields.get("models", "").replace(" and ", ", "))
    return AIProfile(
        models=models,
        providers=providers,
        decides=fields.get("decides", ""),
        affected=fields.get("affected", ""),
        stakes_tier=fields.get("stakes_tier", ""),
    )


def extract_dimension_coverage(report_markdown: str) -> tuple[DimensionCoverage, ...]:
    """One row per dimension the report actually lists in the Dimension
    Coverage table, in contract order. Rows with an unrecognised dimension
    or status are skipped (never silently promoted to 'adequate').
    """
    rows: list[DimensionCoverage] = []
    seen: set[str] = set()
    for cells in _table_rows(_prose_section(report_markdown, "Dimension Coverage")):
        if len(cells) < 2:
            continue
        dimension = _canonical_dimension(cells[0])
        status = _normalize_status(cells[1])
        if dimension is None or not status or dimension in seen:
            continue
        finding_ids = tuple(re.findall(r"\bF\d+\b", cells[3] if len(cells) > 3 else ""))
        rows.append(
            DimensionCoverage(
                dimension=dimension,
                status=status,
                evidence=cells[2] if len(cells) > 2 else "",
                finding_ids=finding_ids,
            )
        )
        seen.add(dimension)
    return tuple(sorted(rows, key=lambda row: DIMENSIONS.index(row.dimension)))


def extract_findings_register_rows(report_markdown: str) -> list[dict[str, str]]:
    """The Findings Register's ID / Finding / Severity / Dimension /
    Framework rows. Old CWE-shaped registers still yield findings, but their
    CWE and verdict columns must not be mistaken for a dimension/framework.
    """
    table = _table_rows(_prose_section(report_markdown, "Findings Register"))
    header = next((cells for cells in table if cells and cells[0].strip().lower() == "id"), [])
    legacy = any("cwe" in cell.lower() for cell in header) and not any(
        "dimension" in cell.lower() for cell in header
    )

    rows: list[dict[str, str]] = []
    for cells in table:
        if len(cells) < 5 or not _ROW_ID_RE.fullmatch(cells[0]):
            continue
        rows.append(
            {
                "id": cells[0],
                "title": cells[1].strip(),
                "severity": cells[2].strip(),
                "dimension": "" if legacy else cells[3].strip(),
                "framework": "" if legacy else cells[4].strip(),
            }
        )
    return rows


def _iter_detail_blocks(report_markdown: str) -> list[tuple[str, str]]:
    for title in ("Detailed Findings", "Findings"):
        blocks = detail_blocks(
            _prose_section(report_markdown, title), _DETAIL_HEADING_RE
        )
        if blocks:
            return [(key, prose_source(text)) for key, text in blocks]
    return []


def extract_findings(report_markdown: str) -> tuple[RaiFinding, ...]:
    """Register rows enriched with the report's own detail fields."""
    details = dict(_iter_detail_blocks(report_markdown))
    findings: list[RaiFinding] = []
    for row in extract_findings_register_rows(report_markdown):
        block = details.get(row["id"], "")
        fields = {
            name: (match.group(1).strip() if (match := regex.search(block)) else "")
            for name, regex in _FIELD_RES.items()
        }
        findings.append(
            RaiFinding(
                finding_id=row["id"],
                title=row["title"],
                severity=row["severity"],
                dimension=fields["dimension"] or row["dimension"],
                framework=fields["framework"] or row["framework"],
                stakes=fields["stakes"],
                description=fields["description"],
                recommendation=fields["recommendation"],
            )
        )
    return tuple(findings)


def parse_responsible_ai_report(report_markdown: str) -> ResponsibleAiReport:
    """All structured Responsible AI data from one report. Pure and
    best-effort: never raises on an incomplete or older report.
    """
    try:
        rating = extract_overall_risk_rating(report_markdown)
    except MalformedReportError:
        rating = None
    return ResponsibleAiReport(
        overall_rating=rating,
        profile=extract_ai_profile(report_markdown),
        dimensions=extract_dimension_coverage(report_markdown),
        findings=extract_findings(report_markdown),
        remediation_roadmap=_prose_section(report_markdown, "Remediation Roadmap").strip(),
    )


def _model_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def ai_bom_diff(
    profile: AIProfile, bom_items: list[dict[str, str | None]]
) -> dict[str, list[str]]:
    """Compare the profile's models with the models in an attached AI-BOM.

    Returns `code_only`, `bom_only` and `shared`, each a sorted list of
    display names. Only `kind == 'model'` items participate; a tool isn't a
    model and would otherwise show up as a false mismatch. Names are compared
    case- and punctuation-insensitively, but the original spelling is shown.
    """
    bom_models: dict[str, str] = {}
    for item in bom_items:
        if item.get("kind") != "model":
            continue
        name = (item.get("name") or "").strip()
        if name:
            bom_models.setdefault(_model_key(name), name)
    code_models: dict[str, str] = {}
    for name in profile.models:
        if name:
            code_models.setdefault(_model_key(name), name)
    return {
        "code_only": sorted(
            (name for key, name in code_models.items() if key not in bom_models), key=str.lower
        ),
        "bom_only": sorted(
            (name for key, name in bom_models.items() if key not in code_models), key=str.lower
        ),
        "shared": sorted(
            (name for key, name in code_models.items() if key in bom_models), key=str.lower
        ),
    }
