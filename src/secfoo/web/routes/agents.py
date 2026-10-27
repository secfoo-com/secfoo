from __future__ import annotations

from fastapi import APIRouter, Request

from secfoo.storage.repository import RunRepository
from secfoo.web.run_status import agent_health
from secfoo.web.templating import templates

router = APIRouter()


@router.get("/agents")
def agents_page(request: Request):
    with RunRepository() as repo:
        stats = repo.agent_run_stats()
    return templates.TemplateResponse(request, "agents.html", {"agents": agent_health(stats)})
