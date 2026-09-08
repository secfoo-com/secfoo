from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from secfoo.storage.repository import RunRepository
from secfoo.web.templating import ordered_skills, templates

router = APIRouter()


@router.get("/projects/{project_id}")
def project_detail(request: Request, project_id: int):
    with RunRepository() as repo:
        project = repo.get_project(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        runs = repo.list_runs(project_id=project_id, limit=200)
        coverage = repo.project_activity_coverage(project_id)

    # Every known activity, covered or not -- an activity this project has
    # never had run is exactly the gap worth showing.
    activities = [
        {"skill": skill, "summary": coverage.get(skill.id)}
        for skill in ordered_skills()
    ]

    return templates.TemplateResponse(
        request,
        "project.html",
        {"project": project, "runs": runs, "activities": activities},
    )
