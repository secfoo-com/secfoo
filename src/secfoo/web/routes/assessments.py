from __future__ import annotations

import shutil
import tempfile
import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse

from secfoo import docext
from secfoo.agents.registry import ADAPTERS, get_adapter
from secfoo.aibom import AIBOMParseError, parse_ai_bom
from secfoo.attachments import infer_attachment_kind
from secfoo.config import attachment_dir
from secfoo.runner import _project_display_name, execute_runs
from secfoo.settings import ConfigError, load_config
from secfoo.skills.loader import SkillLoadError, load_all_skills, load_skill
from secfoo.skills.renderer import merge_excludes
from secfoo.storage.repository import RunRepository
from secfoo.targets.resolver import TargetResolutionError, resolve_target
from secfoo.web.templating import severity_rows, templates
from secfoo.web.third_party_dashboard import SKILL_ID as THIRD_PARTY_RISK_SKILL_ID

router = APIRouter()

_ACTIVE_RUN_STATUSES = {"pending", "running"}


def _extracted_text_path(file_path: Path) -> Path:
    return file_path.with_suffix(file_path.suffix + ".extracted.txt")


def _resolved_agent_and_depth() -> tuple[str, str]:
    try:
        defaults = load_config().defaults
        return defaults.agent or "claude", defaults.depth or "quick"
    except ConfigError:
        # A malformed config shouldn't block the auto-trigger -- fall back
        # to the same defaults the CLI itself falls back to.
        return "claude", "quick"


def _run_third_party_risk_assessment(assessment_id: int, project_id: int) -> None:
    """Background-thread target, fired right after a vendor document
    upload to a third-party assessment: builds a fresh temp directory
    containing one .txt file per vendor_doc attachment's already-extracted
    text, then runs the Third-Party Risk Assessment skill against that
    directory as its "target" -- reusing execute_runs' entire existing
    pipeline (agent CLI reading files with its own Read/Grep/Glob tools)
    unmodified, since a vendor-document review has no real codebase of its
    own to point at. `project_id` pins the run to the assessment's real,
    existing project (see runner.execute_runs' `project_id` param) rather
    than a bogus project derived from the temp directory's own path. The
    temp directory is always cleaned up afterward, success or failure.
    """
    with RunRepository() as repo:
        attachments = [
            a for a in repo.list_attachments(assessment_id) if a.attachment_kind == "vendor_doc"
        ]

    tmp_dir = Path(tempfile.mkdtemp(prefix=f"secfoo-vendor-{assessment_id}-"))
    try:
        wrote_any = False
        for attachment in attachments:
            extracted_path = _extracted_text_path(Path(attachment.file_path))
            text = extracted_path.read_text() if extracted_path.exists() else ""
            if not text.strip():
                continue
            out_path = tmp_dir / f"{Path(attachment.original_name).stem}.txt"
            out_path.write_text(f"Source document: {attachment.original_name}\n\n{text}")
            wrote_any = True

        if not wrote_any:
            # Every vendor doc either failed to extract or had no text
            # (e.g. a scanned/image-only PDF) -- nothing to assess yet.
            return

        agent_id, depth = _resolved_agent_and_depth()
        execute_runs(
            skill_ids=[THIRD_PARTY_RISK_SKILL_ID],
            target=str(tmp_dir),
            confluence_urls=[],
            agent_id=agent_id,
            depth=depth,
            assessment_id=assessment_id,
            project_id=project_id,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _run_form_context() -> dict:
    return {
        "skills": sorted(load_all_skills().values(), key=lambda s: s.name),
        "agent_options": [
            {"id": agent_id, "available": get_adapter(agent_id).is_available()} for agent_id in ADAPTERS
        ],
    }


@router.get("/assessments")
def assessments_list(
    request: Request,
    type: Optional[str] = None,  # noqa: A002 -- matches the query param name
    status: Optional[str] = None,
    q: Optional[str] = None,
):
    with RunRepository() as repo:
        assessments = repo.list_assessments(assessment_type=type or None, status=status or None, search=q)
        counts = {
            "all": repo.count_assessments(),
            "internal": repo.count_assessments(assessment_type="internal"),
            "third_party": repo.count_assessments(assessment_type="third_party"),
        }
    return templates.TemplateResponse(
        request,
        "assessments/list.html",
        {
            "assessments": assessments,
            "counts": counts,
            "active_type": type or "all",
            "active_status": status or "",
            "search": q or "",
        },
    )


@router.get("/assessments/new")
def assessment_new_form(request: Request):
    return templates.TemplateResponse(request, "assessments/new.html", {})


@router.post("/assessments")
def assessments_create(
    project_name: str = Form(...),
    project: str = Form(...),
    assessment_type: str = Form(...),
    status: str = Form("ready"),
    application_id: str = Form(""),
    sar_number: str = Form(""),
    reviewer: str = Form(""),
    review_date: str = Form(""),
    notes: str = Form(""),
):
    try:
        resolved = resolve_target(project)
    except TargetResolutionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    with RunRepository() as repo:
        project_id = repo.upsert_project(
            identifier=resolved.display_name,
            display_name=_project_display_name(resolved),
            kind=resolved.kind.value,
        )
        if project_name.strip():
            repo.rename_project(project_id, project_name.strip())
        assessment_id = repo.create_assessment(
            project_id=project_id,
            assessment_type=assessment_type,
            status=status,
            application_id=application_id or None,
            sar_number=sar_number or None,
            reviewer=reviewer or None,
            review_date=review_date or None,
            notes=notes or None,
        )
    # Create → Run is a guided, one-page-at-a-time flow: land on the Run
    # Assessment page next rather than the detail page, so the natural next
    # action is right in front of the user instead of one more click away.
    return RedirectResponse(url=f"/assessments/{assessment_id}/runs/new", status_code=303)


@router.get("/assessments/{assessment_id}")
def assessment_detail(request: Request, assessment_id: int):
    with RunRepository() as repo:
        assessment = repo.get_assessment(assessment_id)
        if assessment is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        runs = repo.list_runs(assessment_id=assessment_id, limit=200)
        attachments = repo.list_attachments(assessment_id)
        models_count, tools_count = repo.ai_bom_counts(assessment_id)

    has_running_run = any(r.status in _ACTIVE_RUN_STATUSES for r in runs)

    return templates.TemplateResponse(
        request,
        "assessments/detail.html",
        {
            "assessment": assessment,
            "runs": runs,
            "attachments": attachments,
            "models_count": models_count,
            "tools_count": tools_count,
            "has_running_run": has_running_run,
            "severity_rows": severity_rows(
                assessment.critical_count,
                assessment.high_count,
                assessment.medium_count,
                assessment.low_count,
                assessment.info_count,
            ),
        },
    )


@router.get("/assessments/{assessment_id}/runs/new")
def assessment_run_form(request: Request, assessment_id: int):
    with RunRepository() as repo:
        assessment = repo.get_assessment(assessment_id)
        if assessment is None:
            raise HTTPException(status_code=404, detail="Assessment not found")

    return templates.TemplateResponse(
        request,
        "assessments/run.html",
        {"assessment": assessment, **_run_form_context()},
    )


@router.post("/assessments/{assessment_id}/runs")
def assessment_trigger_run(
    assessment_id: int,
    skill: list[str] = Form(...),
    agent: str = Form(...),
    depth: str = Form("quick"),
    confluence: str = Form(""),
    exclude: str = Form(""),
):
    """Kicks off a real skill run (the same underlying execute_runs() the
    CLI's `secfoo run` uses) attached to this assessment. Runs happen in a
    background thread so the request returns immediately -- an agent CLI
    invocation can take minutes, and runner.py already creates each run row
    with status='running' before the agent is invoked, so the detail page
    (which auto-refreshes while a run is in flight) reflects progress
    without the browser tab blocking on the HTTP response.
    """
    with RunRepository() as repo:
        assessment = repo.get_assessment(assessment_id)
        if assessment is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        project = repo.get_project(assessment.project_id)

    for skill_id in skill:
        try:
            load_skill(skill_id)
        except SkillLoadError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if agent not in ADAPTERS:
        raise HTTPException(status_code=400, detail=f"Unknown agent {agent!r}. Available: {', '.join(sorted(ADAPTERS))}")
    if depth not in ("quick", "standard"):
        raise HTTPException(status_code=400, detail=f"Unknown depth {depth!r}. Expected 'quick' or 'standard'.")

    confluence_urls = [line.strip() for line in confluence.splitlines() if line.strip()]
    try:
        config_excludes = load_config().defaults.exclude
    except ConfigError:
        # A malformed config shouldn't block a run from the UI -- the CLI
        # surfaces the error loudly, and exclusions are an optimization.
        config_excludes = []
    exclude_paths = merge_excludes(config_excludes, exclude.splitlines())

    thread = threading.Thread(
        target=execute_runs,
        kwargs={
            "skill_ids": skill,
            "target": project.identifier,
            "confluence_urls": confluence_urls,
            "agent_id": agent,
            "depth": depth,
            "assessment_id": assessment_id,
            "exclude_paths": exclude_paths,
        },
        daemon=True,
    )
    thread.start()

    return RedirectResponse(url=f"/assessments/{assessment_id}", status_code=303)


@router.post("/assessments/{assessment_id}/attachments")
def assessment_upload(assessment_id: int, file: UploadFile):
    trigger_third_party_review = False

    with RunRepository() as repo:
        assessment = repo.get_assessment(assessment_id)
        if assessment is None:
            raise HTTPException(status_code=404, detail="Assessment not found")

        # file.filename is client-controlled (the multipart Content-Disposition
        # header) -- strip it to a bare basename before using it in a
        # filesystem path. Path("x") / "/etc/passwd" evaluates to
        # Path("/etc/passwd") (an absolute right-hand side discards the
        # left), and "../" sequences escape dest_dir just as readily, so
        # using the raw filename directly here would be a path-traversal /
        # arbitrary-file-write bug (confirmed by a real threat-assessment
        # run against this exact route).
        filename = Path(file.filename or "upload").name
        if not filename or filename in (".", ".."):
            raise HTTPException(status_code=400, detail="Invalid filename")
        kind = infer_attachment_kind(filename)
        dest_dir = attachment_dir(assessment_id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / filename
        if dest.resolve().parent != dest_dir.resolve():
            raise HTTPException(status_code=400, detail="Invalid filename")
        with dest.open("wb") as fh:
            shutil.copyfileobj(file.file, fh)

        if kind == "vendor_doc" and dest.stat().st_size > docext.MAX_UPLOAD_BYTES:
            dest.unlink(missing_ok=True)
            max_mb = docext.MAX_UPLOAD_BYTES // (1024 * 1024)
            raise HTTPException(status_code=413, detail=f"File too large (max {max_mb}MB)")

        new_attachment_id = repo.add_attachment(
            assessment_id=assessment_id, file_path=str(dest), original_name=filename, attachment_kind=kind
        )

        if kind == "ai_bom":
            try:
                summary = parse_ai_bom(dest)
            except AIBOMParseError:
                # Uploaded either way -- the file is still useful reference
                # material even if it doesn't parse as valid AI-BOM.
                pass
            else:
                items = [{"kind": "model", **m} for m in summary.models] + [
                    {"kind": "tool", **t} for t in summary.tools
                ]
                repo.add_ai_bom_items(new_attachment_id, items)

        if kind == "vendor_doc":
            # Extracted once here and cached alongside the original file
            # (rather than re-extracted on every subsequent upload/trigger)
            # -- a vendor doc's content doesn't change after upload.
            text = docext.extract_text(dest)
            _extracted_text_path(dest).write_text(text)
            if assessment.assessment_type == "third_party":
                trigger_third_party_review = True

    if trigger_third_party_review:
        # Auto-triggered, not a separate "Run Assessment" click -- an
        # uploaded vendor document should start informing the assessment
        # immediately. Same background-thread-so-the-request-returns-
        # immediately shape as assessment_trigger_run below (an agent CLI
        # invocation can take minutes); each new upload re-runs the skill
        # against the full current set of vendor documents rather than
        # trying to incrementally update a prior run.
        thread = threading.Thread(
            target=_run_third_party_risk_assessment,
            kwargs={"assessment_id": assessment_id, "project_id": assessment.project_id},
            daemon=True,
        )
        thread.start()

    return RedirectResponse(url=f"/assessments/{assessment_id}", status_code=303)


@router.post("/assessments/{assessment_id}/delete")
def assessment_delete(assessment_id: int):
    with RunRepository() as repo:
        if repo.get_assessment(assessment_id) is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        repo.delete_assessment(assessment_id)
    return {"ok": True}
