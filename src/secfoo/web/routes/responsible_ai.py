from __future__ import annotations

from fastapi import APIRouter, Request

from secfoo.storage.repository import RunRepository
from secfoo.web.templating import templates

router = APIRouter()


@router.get("/responsible-ai")
def responsible_ai(request: Request):
    with RunRepository() as repo:
        all_assessments = repo.list_assessments(limit=500)

    flagged = [a for a in all_assessments if a.responsible_ai_risk is not None]
    high_risk = sum(1 for a in flagged if a.responsible_ai_risk == "high-risk")
    provisional = sum(1 for a in flagged if a.responsible_ai_status == "provisional")

    return templates.TemplateResponse(
        request,
        "responsible_ai.html",
        {"assessments": flagged, "high_risk": high_risk, "provisional": provisional, "total": len(flagged)},
    )
