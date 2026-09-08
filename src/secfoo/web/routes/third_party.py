from __future__ import annotations

from fastapi import APIRouter, Request

from secfoo.storage.repository import RunRepository
from secfoo.web import third_party_dashboard
from secfoo.web.templating import templates

router = APIRouter()


@router.get("/third-party")
def third_party(request: Request):
    with RunRepository() as repo:
        assessments = repo.list_assessments(assessment_type="third_party")
        counts = {"total": repo.count_assessments(assessment_type="third_party")}
        models_count, tools_count = repo.ai_bom_counts_total()
        dash = third_party_dashboard.build(repo)

    return templates.TemplateResponse(
        request,
        "third_party.html",
        {
            "assessments": assessments,
            "counts": counts,
            "models_count": models_count,
            "tools_count": tools_count,
            "dash": dash,
        },
    )
