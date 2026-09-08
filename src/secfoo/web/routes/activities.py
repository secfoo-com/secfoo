"""Per-activity dashboard pages (Security Architecture, SAST, SCA, Secret
Scanning, ...).

One generic route rather than a template per activity: every activity has
the same shape of question -- which projects have been scanned with it, how
recently, and what did it find -- so the page is driven entirely by the
skill definition and its runs. Adding a new definitions/*.md gets a working
page for free.

Security Architecture Review and Threat Modeling additionally get an
extended dashboard (coverage, exceptions/dispositions, heatmaps, gate
decisions or STRIDE coverage, ...) rendered as an included partial -- see
architecture_dashboard.py and threat_modeling_dashboard.py for why these
are special-cased rather than generic.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from secfoo.report.architecture import count_trust_boundaries, extract_design_verdict, extract_mermaid_diagram
from secfoo.skills.loader import SkillLoadError, load_skill
from secfoo.storage.repository import RunRepository
from secfoo.web import architecture_dashboard as arch_dashboard
from secfoo.web import sast_dashboard
from secfoo.web import sca_dashboard
from secfoo.web import secret_scanning_dashboard
from secfoo.web import threat_modeling_dashboard as tm_dashboard
from secfoo.web.templating import severity_rows, templates

router = APIRouter()

_GATE_MIX_COLORS = {
    "approve": "var(--color-success)",
    "conditions": "var(--color-warning)",
    "reject": "var(--color-error)",
}

# Matches severity_badge_class()'s color mapping in templating.py (high ->
# badge--error, medium -> badge--warning, low -> badge--teal) so the SCA
# severity donut uses the same colors as every other severity display in
# the app, not a second palette invented for this one panel.
_SCA_SEVERITY_COLORS = {
    "high": "var(--color-error)",
    "medium": "var(--color-warning)",
    "low": "var(--color-teal-500)",
}

_SAST_CVSS_COLORS = {
    "critical": "var(--color-error)",
    "high": "var(--color-error)",
    "medium": "var(--color-warning)",
    "low": "var(--color-teal-500)",
    "none": "var(--color-gray-400)",
}


def _attach_architecture_signals(projects: list[dict]) -> bool:
    """Extracts diagram/verdict/boundary-count from each project's latest
    successful report, mutating the rollup dicts in place. Not gated on
    skill_id -- extraction is a no-op (None/0) for reports that don't carry
    these, so this works for any activity without hardcoding which ones,
    and automatically picks up new diagram-bearing skills.

    Returns whether at least one project has a diagram, so the template
    can skip the whole diagrams section when there's nothing to show.
    """
    any_diagram = False
    for project in projects:
        project["diagram_source"] = None
        project["design_verdict"] = None
        project["boundary_count"] = 0
        report_path = project.get("latest_success_report_path")
        if not report_path or not Path(report_path).is_file():
            continue
        text = Path(report_path).read_text()
        project["diagram_source"] = extract_mermaid_diagram(text)
        project["design_verdict"] = extract_design_verdict(text)
        project["boundary_count"] = count_trust_boundaries(text)
        if project["diagram_source"]:
            any_diagram = True
    return any_diagram


def _donut_gradient(counts: dict[str, int], color_map: dict[str, str]) -> str:
    """A `conic-gradient()` value for the .donut component: color stops
    proportional to each count. Falls back to a flat gray ring when
    there's no data yet, rather than an empty/broken gradient.
    """
    total = sum(counts.values())
    if total == 0:
        return "var(--color-gray-200) 0% 100%"
    segments = []
    cursor = 0.0
    for key, color in color_map.items():
        value = counts.get(key, 0)
        if value == 0:
            continue
        start, end = cursor, cursor + (value / total * 100)
        segments.append(f"{color} {start:.1f}% {end:.1f}%")
        cursor = end
    return ", ".join(segments)


@router.get("/activities/{skill_id}")
def activity_detail(request: Request, skill_id: str, diagram_project: int | None = None):
    try:
        skill = load_skill(skill_id)
    except SkillLoadError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    with RunRepository() as repo:
        projects = repo.activity_summary_by_project(skill_id)
        severity = repo.activity_severity_totals(skill_id)
        dash = arch_dashboard.build(repo) if skill_id == arch_dashboard.SKILL_ID else None
        tm_dash = tm_dashboard.build(repo) if skill_id == tm_dashboard.SKILL_ID else None
        sca_dash = sca_dashboard.build(repo) if skill_id == sca_dashboard.SKILL_ID else None
        sast_dash = sast_dashboard.build(repo) if skill_id == sast_dashboard.SKILL_ID else None
        secret_dash = (
            secret_scanning_dashboard.build(repo) if skill_id == secret_scanning_dashboard.SKILL_ID else None
        )

    diagrams_available = _attach_architecture_signals(projects)

    # A gallery rendering every project's diagram at once doesn't scale
    # past a couple of projects -- instead show one at a time, picked via
    # a `?diagram_project=` query param (a plain GET <select>, same pattern
    # as the Assessments list filters), defaulting to the first project
    # that actually has a diagram.
    diagram_projects = [p for p in projects if p.get("diagram_source")]
    selected_diagram_project = next(
        (p for p in diagram_projects if p["project_id"] == diagram_project), None
    ) or (diagram_projects[0] if diagram_projects else None)

    # Deferred import: secfoo.web.app imports this module's router, so a
    # top-level import here would be circular.
    from secfoo.web.app import mermaid_bundle_available

    context = {
        "skill": skill,
        "projects": projects,
        "severity": severity,
        "severity_rows": severity_rows(
            severity.critical, severity.high, severity.medium, severity.low, severity.info
        ),
        "run_count": sum(p["run_count"] for p in projects),
        "diagrams_available": diagrams_available,
        "diagram_projects": diagram_projects,
        "selected_diagram_project": selected_diagram_project,
        "mermaid_available": mermaid_bundle_available(),
        "dash": dash,
        "tm_dash": tm_dash,
        "sca_dash": sca_dash,
        "sast_dash": sast_dash,
        "secret_dash": secret_dash,
    }
    if dash is not None:
        context["gate_mix_gradient"] = _donut_gradient(dash.gate_mix, _GATE_MIX_COLORS)
        context["past_due_sla_days"] = arch_dashboard.PAST_DUE_SLA_DAYS
    if tm_dash is not None:
        context["past_due_sla_days"] = tm_dashboard.PAST_DUE_SLA_DAYS
    if sca_dash is not None:
        context["sca_severity_gradient"] = _donut_gradient(sca_dash.severity_counts, _SCA_SEVERITY_COLORS)
    if sast_dash is not None:
        context["sast_cvss_gradient"] = _donut_gradient(sast_dash.cvss_band_counts, _SAST_CVSS_COLORS)
    if secret_dash is not None:
        context["secret_severity_gradient"] = _donut_gradient(secret_dash.severity_counts, _SCA_SEVERITY_COLORS)

    return templates.TemplateResponse(request, "activities/detail.html", context)


@router.get("/activities/sast/findings")
def sast_findings_list(
    request: Request,
    status: str = "open",
    q: str | None = None,
    project_id: int | None = None,
):
    """The full, filterable SAST findings register -- the program
    dashboard itself only ever shows a short "Top findings" preview (see
    sast_dashboard.html); this is where "View all findings" lands, with a
    project filter the dashboard preview deliberately doesn't have (it's
    already cross-project by design).
    """
    with RunRepository() as repo:
        projects = repo.activity_summary_by_project(sast_dashboard.SKILL_ID)
        findings = repo.list_sast_findings(project_id=project_id, status=status, search=q or None)
        open_count = len(repo.list_sast_findings(project_id=project_id, status="open"))
        closed_count = len(repo.list_sast_findings(project_id=project_id, status="closed"))

    return templates.TemplateResponse(
        request,
        "activities/sast_findings_list.html",
        {
            "projects": projects,
            "findings": findings,
            "selected_status": status,
            "selected_project_id": project_id,
            "search": q or "",
            "open_count": open_count,
            "closed_count": closed_count,
        },
    )


@router.get("/activities/sast/findings/{fingerprint}")
def sast_finding_detail(request: Request, fingerprint: str):
    with RunRepository() as repo:
        findings = repo.list_sast_findings()
    finding = next((f for f in findings if f.fingerprint == fingerprint), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    return templates.TemplateResponse(
        request, "activities/sast_finding_detail.html", {"finding": finding}
    )


@router.get("/activities/{skill_id}/vulnerabilities")
def sca_vulnerabilities_list(request: Request, skill_id: str, project_id: int | None = None):
    """The full SCA vulnerability register, filterable by project -- what
    the program dashboard's "Top vulnerabilities" preview links out to.
    Filtering happens post-aggregation, over sca_dashboard.build()'s
    already-deduplicated cross-project rows (checking each vulnerability's
    own affected_projects), not by re-querying per project -- a
    vulnerability affecting several projects should only ever appear once
    even when a project filter narrows which rows qualify.
    """
    if skill_id != sca_dashboard.SKILL_ID:
        raise HTTPException(status_code=404, detail="Not found")

    with RunRepository() as repo:
        projects = repo.activity_summary_by_project(sca_dashboard.SKILL_ID)
        dash = sca_dashboard.build(repo)

    vulnerabilities = dash.vulnerabilities
    if project_id is not None:
        vulnerabilities = [
            v for v in vulnerabilities if any(p["project_id"] == project_id for p in v.affected_projects)
        ]

    return templates.TemplateResponse(
        request,
        "activities/sca_vulnerabilities_list.html",
        {
            "skill_id": skill_id,
            "projects": projects,
            "vulnerabilities": vulnerabilities,
            "selected_project_id": project_id,
        },
    )


@router.get("/activities/{skill_id}/vulnerabilities/{key}")
def sca_vulnerability_detail(request: Request, skill_id: str, key: str):
    if skill_id != sca_dashboard.SKILL_ID:
        raise HTTPException(status_code=404, detail="Not found")

    with RunRepository() as repo:
        dash = sca_dashboard.build(repo)

    vulnerability = dash.vulnerabilities_by_key.get(key)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return templates.TemplateResponse(
        request,
        "activities/sca_vulnerability_detail.html",
        {"skill_id": skill_id, "vulnerability": vulnerability},
    )


@router.get("/activities/secret-scanning/findings")
def secret_scanning_findings_list(request: Request, project_id: int | None = None):
    """The full secret findings register, filterable by project -- what
    the program dashboard's "Top findings" preview links out to, same
    pattern as SAST's and SCA's findings-list pages.
    """
    with RunRepository() as repo:
        projects = repo.activity_summary_by_project(secret_scanning_dashboard.SKILL_ID)
        dash = secret_scanning_dashboard.build(repo)

    findings = dash.findings
    if project_id is not None:
        findings = [f for f in findings if f.project_id == project_id]

    return templates.TemplateResponse(
        request,
        "activities/secret_scanning_findings_list.html",
        {"projects": projects, "findings": findings, "selected_project_id": project_id},
    )


@router.get("/activities/secret-scanning/findings/{key}")
def secret_scanning_finding_detail(request: Request, key: str):
    with RunRepository() as repo:
        dash = secret_scanning_dashboard.build(repo)

    finding = dash.findings_by_key.get(key)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    return templates.TemplateResponse(
        request, "activities/secret_scanning_finding_detail.html", {"finding": finding}
    )
