"""Orchestrates skill x target x agent: resolves the target, renders each
skill's prompt, invokes the chosen agent adapter, and persists results.

Selected skills run concurrently (one thread per skill, bounded by how many
skills were selected) rather than one after another, since each is an
independent read-only pass over the same target and the slow part is
waiting on an external agent CLI, not local CPU work.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from secfoo import cloud, cvss, osv
from secfoo.agents.registry import get_adapter
from secfoo.config import ensure_store_dirs, run_dir
from secfoo.report.markdown import strip_preamble
from secfoo.report.sast import SKILL_ID as SAST_SKILL_ID
from secfoo.report.sast import findings_with_fingerprints
from secfoo.report.sca import SKILL_ID as SCA_SKILL_ID
from secfoo.report.sca import osv_keys_for_report
from secfoo.report.severity import count_severities
from secfoo.skills.loader import load_skill
from secfoo.skills.renderer import TargetContext, render_prompt
from secfoo.storage.repository import RunRepository
from secfoo.targets.github import clone_shallow
from secfoo.targets.resolver import ResolvedTarget, TargetKind, resolve_target

logger = logging.getLogger(__name__)

STDERR_EXCERPT_LIMIT = 2000


@dataclass
class RunOutcome:
    run_uuid: str
    skill_id: str
    skill_name: str
    agent_id: str
    status: str
    exit_code: int | None
    duration_seconds: float | None
    report_path: str | None


def _project_display_name(resolved: ResolvedTarget) -> str:
    if resolved.kind is TargetKind.GITHUB:
        cleaned = resolved.display_name.rstrip("/")
        if cleaned.endswith(".git"):
            cleaned = cleaned[: -len(".git")]
        match = re.search(r"github\.com[/:]([^/]+/[^/]+)$", cleaned)
        return match.group(1) if match else cleaned
    return Path(resolved.display_name).name or resolved.display_name


def _try_cloud_sync(repo: RunRepository, run_uuid: str) -> None:
    """Best-effort push to the enterprise portal, if `secfoo cloud login`
    has configured one. A portal outage, missing config, or any other
    failure here must never fail the local run -- `secfoo cloud status`
    and `secfoo cloud sync` are how a user checks/retries, not this hook.
    """
    try:
        config = cloud.load_cloud_config()
        if config is None:
            return
        cloud.sync_run(repo, run_uuid, config)
    except Exception:
        pass


def _try_osv_enrich(repo: RunRepository, report_text: str) -> None:
    """Best-effort OSV.dev enrichment right after a successful
    sca-reachability run -- populates the shared cache so the dashboard's
    own (small, capped) top-up pass normally has nothing left to do. A
    `secfoo run` is already dominated by a minutes-long LLM call, so a
    bounded OSV pass here is a rounding error; same failure-tolerance
    contract as _try_cloud_sync, a network hiccup must never fail the
    local run.
    """
    try:
        keys = osv_keys_for_report(report_text)
        if keys:
            osv.enrich_lookups(repo, list(keys))
    except Exception:
        pass


def update_sast_findings(repo: RunRepository, *, project_id: int, run_id: int, report_text: str) -> None:
    """Matches this run's Findings Register against the project's
    currently-open sast_findings rows by fingerprint (report/sast.py),
    upserting seen-again/new findings and closing whatever was open but
    not seen this run. Unlike _try_cloud_sync/_try_osv_enrich, this is
    pure local DB + CPU work with no network dependency -- its caller logs
    a failure here instead of silently swallowing it (see the call site in
    _run_single_skill), since a silent regression would mean the entire
    Open/Closed Findings feature quietly stops updating without anyone
    noticing.

    Deliberately public (no leading underscore): portal/routes/ingest.py
    calls this too, right after a pushed run is recorded -- the SAST
    dashboard reads only from sast_findings (never re-parsed report text
    at render time, see sast_dashboard.py's module docstring), so without
    this second call site a run pushed via `secfoo cloud sync` would sit
    in the tenant's `runs` table with a real report but never update
    Open/Closed Findings at all.
    """
    findings = findings_with_fingerprints(report_text)
    seen_fingerprints = []
    for row in findings:
        vector = row.get("cvss_vector", "").strip()
        score = None
        if vector:
            try:
                score = cvss.base_score(vector)
            except cvss.CvssError:
                # A malformed vector (an off-contract or older report)
                # still gets tracked as a finding -- just without a score,
                # not dropped and not defaulted to a guessed number.
                score = None
        repo.upsert_sast_finding(
            project_id=project_id,
            fingerprint=row["fingerprint"],
            current_ref=row["id"],
            title=row["title"],
            severity=row["severity"],
            cwe=row.get("cwe") or None,
            owasp=row.get("owasp") or None,
            verdict=row.get("verdict") or None,
            location_file=row["location_file"],
            location_line=row.get("location_line"),
            cvss_vector=vector or None,
            cvss_score=score,
            description=row.get("description") or None,
            recommendation=row.get("recommendation") or None,
            run_id=run_id,
        )
        seen_fingerprints.append(row["fingerprint"])

    repo.close_stale_sast_findings(
        project_id=project_id,
        run_id=run_id,
        seen_fingerprints=seen_fingerprints,
        closed_at=datetime.now(timezone.utc).isoformat(),
    )


@contextmanager
def _target_workdir(resolved: ResolvedTarget) -> Iterator[Path]:
    if resolved.kind is TargetKind.GITHUB:
        with clone_shallow(resolved.display_name) as tmp_dir:
            yield tmp_dir
    else:
        assert resolved.path is not None
        yield resolved.path


def _run_single_skill(
    *,
    skill_id: str,
    project_id: int,
    agent_id: str,
    target_ctx: TargetContext,
    confluence_urls: list[str],
    depth: Literal["quick", "standard"],
    timeout: int | None,
    db_path,
    on_skill_start: Callable[[str], None] | None,
    on_skill_complete: Callable[[str, str], None] | None,
    assessment_id: int | None = None,
    exclude_paths: list[str] | None = None,
) -> RunOutcome:
    skill = load_skill(skill_id)
    prompt = render_prompt(skill, target_ctx, depth=depth, exclude_paths=exclude_paths)

    # A fresh connection per worker thread: sqlite3 connections may not be
    # shared across threads.
    repo = RunRepository(db_path=db_path)
    try:
        run_uuid = repo.create_run(
            project_id=project_id,
            skill_id=skill.id,
            skill_name=skill.name,
            agent_id=agent_id,
            confluence_urls=confluence_urls,
            assessment_id=assessment_id,
        )

        report_dir = run_dir(run_uuid)
        report_dir.mkdir(parents=True, exist_ok=True)
        prompt_path = report_dir / "prompt.md"
        prompt_path.write_text(prompt)

        if on_skill_start:
            on_skill_start(skill.name)

        adapter = get_adapter(agent_id)
        result = adapter.run(prompt, workdir=target_ctx.local_path, timeout=timeout)

        if on_skill_complete:
            on_skill_complete(skill.name, result.status)

        (report_dir / "stdout.log").write_text(result.stdout)
        (report_dir / "stderr.log").write_text(result.stderr)
        report_path = report_dir / "report.md"
        report_text = strip_preamble(result.raw_report)
        report_path.write_text(report_text)
        severity = count_severities(report_text)

        repo.complete_run(
            run_uuid,
            status=result.status,
            exit_code=result.exit_code,
            duration_seconds=result.duration_seconds,
            report_path=str(report_path),
            prompt_path=str(prompt_path),
            stderr_excerpt=(result.stderr or "")[:STDERR_EXCERPT_LIMIT] or None,
            critical_count=severity.critical,
            high_count=severity.high,
            medium_count=severity.medium,
            low_count=severity.low,
            info_count=severity.info,
        )

        if result.status == "success":
            _try_cloud_sync(repo, run_uuid)
            if skill.id == SCA_SKILL_ID:
                _try_osv_enrich(repo, report_text)
            if skill.id == SAST_SKILL_ID:
                try:
                    completed_run = repo.get_run(run_uuid)
                    update_sast_findings(
                        repo, project_id=project_id, run_id=completed_run.id, report_text=report_text
                    )
                except Exception:
                    logger.exception("Failed to update SAST finding lifecycle for run %s", run_uuid)

        return RunOutcome(
            run_uuid=run_uuid,
            skill_id=skill.id,
            skill_name=skill.name,
            agent_id=agent_id,
            status=result.status,
            exit_code=result.exit_code,
            duration_seconds=result.duration_seconds,
            report_path=str(report_path),
        )
    finally:
        repo.close()


def execute_runs(
    *,
    skill_ids: list[str],
    target: str | None,
    confluence_urls: list[str],
    agent_id: str,
    depth: Literal["quick", "standard"] = "quick",
    timeout: int | None = None,
    repo: RunRepository | None = None,
    on_skill_start: Callable[[str], None] | None = None,
    on_skill_complete: Callable[[str, str], None] | None = None,
    assessment_id: int | None = None,
    exclude_paths: list[str] | None = None,
    project_id: int | None = None,
    project_display_name: str | None = None,
    assessment_application_id: str | None = None,
) -> list[RunOutcome]:
    """Run each skill in `skill_ids` concurrently against `agent_id`.

    `on_skill_start(skill_name)` fires right before an agent CLI is invoked
    for a skill, and `on_skill_complete(skill_name, status)` fires right
    after -- callers (e.g. the CLI) use these to show live progress, since
    an individual agent invocation can take minutes with no output of its
    own. Both may be called concurrently from different threads.

    `project_id`, when given, attaches every run to that EXISTING project
    instead of the one `resolve_target(target)` would normally
    create/reuse from `target` itself -- `target` still supplies the
    actual files-to-scan directory (resolved and read exactly as usual),
    it just isn't treated as this project's identity. Used by the
    Third-Party Risk Assessment auto-trigger (web/routes/assessments.py),
    whose "target" is a synthetic temp directory of extracted vendor
    document text, not the vendor's real project.

    `assessment_id`, when left as None, is not simply "no assessment" --
    a fresh internal assessment case file is created for the resolved
    project and every skill in `skill_ids` attaches to it. This is what
    makes an ad-hoc `secfoo run` (no `--assessment` flag) show up as a
    real case file (and, for skills like responsible-ai-compliance,
    actually appear on their dashboard) instead of silently existing only
    as a standalone run. Callers that already manage their own assessment
    lifecycle (e.g. the Third-Party Risk Assessment auto-trigger above)
    pass `assessment_id` explicitly and skip this.

    `project_display_name` and `assessment_application_id` feed that same
    auto-creation: a caller (the CLI, interactively) can supply a
    human-chosen project name and application ID instead of leaving the
    project stuck with its auto-derived name and the assessment with no
    application ID -- both of which make a case file much harder to find
    again later. Ignored when `project_id` or `assessment_id` is given
    explicitly, since those name an already-identified project/assessment.

    Auto-creation also consolidates by `assessment_application_id`: if an
    assessment for this project already carries that same application ID
    (from an earlier `secfoo run` against the same target with the same
    --app-id), the new run attaches to THAT assessment instead of minting
    a fresh one every time -- otherwise every rescan of the same system
    would fragment into its own separate, mostly-empty case file.
    """
    ensure_store_dirs()
    owns_repo = repo is None
    repo = repo or RunRepository()
    try:
        resolved = resolve_target(target)
        if project_id is None:
            project_id = repo.upsert_project(
                identifier=resolved.display_name,
                display_name=_project_display_name(resolved),
                kind=resolved.kind.value,
            )
            if project_display_name:
                repo.rename_project(project_id, project_display_name)
        if assessment_id is None:
            existing_assessment = None
            if assessment_application_id:
                existing_assessment = repo.find_assessment_by_application_id(
                    project_id=project_id, application_id=assessment_application_id
                )
            if existing_assessment is not None:
                assessment_id = existing_assessment.id
            else:
                assessment_id = repo.create_assessment(
                    project_id=project_id,
                    assessment_type="internal",
                    status="in_progress",
                    application_id=assessment_application_id,
                )
        db_path = repo.db_path

        with _target_workdir(resolved) as workdir:
            target_ctx = TargetContext(
                kind=resolved.kind.value,  # type: ignore[arg-type]
                local_path=workdir,
                display_source=resolved.display_name,
                confluence_urls=confluence_urls,
            )
            with ThreadPoolExecutor(max_workers=max(1, len(skill_ids))) as pool:
                futures = [
                    pool.submit(
                        _run_single_skill,
                        skill_id=skill_id,
                        project_id=project_id,
                        agent_id=agent_id,
                        target_ctx=target_ctx,
                        confluence_urls=confluence_urls,
                        depth=depth,
                        timeout=timeout,
                        db_path=db_path,
                        on_skill_start=on_skill_start,
                        on_skill_complete=on_skill_complete,
                        assessment_id=assessment_id,
                        exclude_paths=exclude_paths,
                    )
                    for skill_id in skill_ids
                ]
                # Iterating futures in submission order still reflects real
                # concurrency (each already runs in the pool); this just
                # keeps the returned list in the order skills were requested.
                outcomes = [f.result() for f in futures]
        return outcomes
    finally:
        if owns_repo:
            repo.close()
