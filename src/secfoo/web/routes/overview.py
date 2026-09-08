from __future__ import annotations

from fastapi import APIRouter, Request

from secfoo.storage.repository import RunRepository
from secfoo.web.templating import ordered_skills, severity_rows, templates
from secfoo.web.top_findings import build_top_findings

router = APIRouter()


@router.get("/")
def overview(request: Request):
    with RunRepository() as repo:
        projects = repo.list_projects()
        assessments = repo.list_assessments(limit=10)
        severity = repo.severity_totals()
        coverage_raw = repo.skill_coverage()
        third_party_count = repo.count_assessments(assessment_type="third_party")
        responsible_ai_count = repo.count_assessments_with_responsible_ai_risk()
        models_count, tools_count = repo.ai_bom_counts_total()
        top_findings = build_top_findings(repo)

    # Coverage is "projects that have had this activity run", so the
    # denominator is the project count -- see RunRepository.skill_coverage.
    total_projects = len(projects)
    skill_coverage = [
        {
            "id": skill.id,
            "label": skill.nav_label,
            "covered": coverage_raw.get(skill.id, 0),
            "total": total_projects,
        }
        for skill in ordered_skills()
    ]

    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "projects": projects,
            "assessments": assessments,
            "severity": severity,
            "severity_rows": severity_rows(severity.critical, severity.high, severity.medium, severity.low, severity.info),
            "skill_coverage": skill_coverage,
            "third_party_count": third_party_count,
            "responsible_ai_count": responsible_ai_count,
            "models_count": models_count,
            "tools_count": tools_count,
            "top_findings": top_findings,
        },
    )
