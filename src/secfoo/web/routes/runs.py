from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

from secfoo.report.markdown import render_report_html
from secfoo.storage.repository import RunRepository
from secfoo.web.templating import templates

router = APIRouter()


@router.get("/runs/{run_uuid}")
def run_detail(request: Request, run_uuid: str):
    with RunRepository() as repo:
        record = repo.get_run(run_uuid)
    if record is None:
        raise HTTPException(status_code=404, detail="Run not found")

    report_html = ""
    if record.report_path and Path(record.report_path).exists():
        text = Path(record.report_path).read_text()
        if text.strip():
            report_html = render_report_html(text)

    from secfoo.web.app import mermaid_bundle_available

    return templates.TemplateResponse(
        request,
        "run_detail.html",
        {
            "run": record,
            "report_html": report_html,
            "mermaid_available": mermaid_bundle_available(),
        },
    )


@router.get("/runs/{run_uuid}/report.md")
def run_report_download(run_uuid: str):
    with RunRepository() as repo:
        record = repo.get_run(run_uuid)
    if record is None or not record.report_path or not Path(record.report_path).exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(record.report_path, media_type="text/markdown", filename=f"{run_uuid}.md")
