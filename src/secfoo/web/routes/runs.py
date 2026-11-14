from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from secfoo.config import STORE_DIR
from secfoo.report.markdown import render_report_html
from secfoo.storage.repository import RunRepository
from secfoo.web.run_status import ACTIVE_STATUSES, blocked_hint, elapsed_seconds, run_steps
from secfoo.web.templating import templates

router = APIRouter()


def _store_file(path: str) -> Path:
    """Report and prompt paths come from the local database. A poisoned
    row must not turn the dashboard into an arbitrary file read."""
    resolved = Path(path).expanduser().resolve()
    root = STORE_DIR.resolve()
    if not resolved.is_file() or not resolved.is_relative_to(root):
        raise HTTPException(status_code=404, detail="Report not found")
    return resolved


@router.get("/runs/{run_uuid}")
def run_detail(request: Request, run_uuid: str):
    with RunRepository() as repo:
        record = repo.get_run(run_uuid)
        if record is None:
            raise HTTPException(status_code=404, detail="Run not found")
        definition_changed = False
        if record.skill_sha256:
            previous_sha256 = repo.previous_skill_sha256(
                skill_id=record.skill_id, before_started_at=record.started_at, exclude_run_uuid=record.run_uuid,
            )
            definition_changed = previous_sha256 is not None and previous_sha256 != record.skill_sha256

    report_html = ""
    report_file = None
    if record.report_path:
        try:
            report_file = _store_file(record.report_path)
        except HTTPException:
            report_file = None
    if report_file is not None:
        text = report_file.read_text(encoding="utf-8", errors="replace")
        if text.strip():
            report_html = render_report_html(text)

    from secfoo.web.app import mermaid_bundle_available

    return templates.TemplateResponse(
        request,
        "run_detail.html",
        {
            "run": record,
            "steps": run_steps(record),
            "blocked": blocked_hint(record),
            "elapsed": elapsed_seconds(record),
            "is_active": record.status in ACTIVE_STATUSES,
            "report_html": report_html,
            "definition_changed": definition_changed,
            "mermaid_available": mermaid_bundle_available(),
        },
    )


@router.get("/runs/{run_uuid}/report.md")
def run_report_download(run_uuid: str):
    with RunRepository() as repo:
        record = repo.get_run(run_uuid)
    if record is None or not record.report_path:
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(_store_file(record.report_path), media_type="text/markdown", filename=f"{run_uuid}.md")


@router.get("/runs/{run_uuid}/status.json")
def run_status_json(run_uuid: str):
    """Polled by static/js/live-run.js while a run is in flight, so the run
    page can tick its step list without reloading the whole report view."""
    with RunRepository() as repo:
        record = repo.get_run(run_uuid)
    if record is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return JSONResponse(
        {
            "status": record.status,
            "active": record.status in ACTIVE_STATUSES,
            "elapsed_seconds": elapsed_seconds(record),
            "steps": [{"label": s.label, "state": s.state, "detail": s.detail} for s in run_steps(record)],
        }
    )


@router.get("/runs/{run_uuid}/prompt.md")
def run_prompt_download(run_uuid: str):
    """The exact prompt the agent was given -- part of the run receipt, so a
    reviewer can see what was asked, not just what came back."""
    with RunRepository() as repo:
        record = repo.get_run(run_uuid)
    if record is None or not record.prompt_path:
        raise HTTPException(status_code=404, detail="Prompt not found")
    return FileResponse(_store_file(record.prompt_path), media_type="text/markdown", filename=f"{run_uuid}-prompt.md")
