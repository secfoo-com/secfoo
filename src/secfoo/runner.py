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
import time
import traceback
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from secfoo import cloud, cvss, memory, osv
from secfoo.agents.registry import get_adapter
from secfoo.config import ensure_store_dirs, run_dir
from secfoo.report import sca as sca_report
from secfoo.report import secret_scanning as secret_report
from secfoo.report.markdown import strip_preamble
from secfoo.report.sast import SKILL_ID as SAST_SKILL_ID
from secfoo.report.sast import findings_with_fingerprints
from secfoo.report.sca import SKILL_ID as SCA_SKILL_ID
from secfoo.report.sca import osv_keys_for_report
from secfoo.report.secret_scanning import SKILL_ID as SECRET_SKILL_ID
from secfoo.report.severity import count_severities
from secfoo.skills.loader import load_skill
from secfoo.skills.renderer import TargetContext, render_prompt
from secfoo.stack import Stack, detect_stack, language_for_ecosystem, language_for_path
from secfoo.storage.repository import RunRepository
from secfoo.targets.github import clone_shallow
from secfoo.targets.resolver import ResolvedTarget, TargetKind, resolve_target

logger = logging.getLogger(__name__)

STDERR_EXCERPT_LIMIT = 2000


def _git_head_commit(path: Path) -> str | None:
    """Return the HEAD commit SHA for a git repo at `path`, or None if
    the directory isn't a git repo or git isn't available."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


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
    cost_usd: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    # Severity counts parsed from the report's `### [SEVERITY] Fn:` headings,
    # so CI gates (`secfoo run --fail-on`) don't have to re-read the report.
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


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


def _stack_fields(stack: Stack | None, language: str | None) -> dict[str, str | None]:
    """language + framework columns for one finding. Framework is the
    comma-joined frameworks detected for that finding's own language, or
    None when unknown (cloud ingest has no workdir to detect from)."""
    frameworks = stack.frameworks_for(language) if stack is not None else []
    return {"language": language, "framework": ",".join(frameworks) or None}


def _closed_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def update_sast_findings(
    repo: RunRepository,
    *,
    project_id: int,
    run_id: int,
    report_text: str,
    workdir: Path | None = None,
    stack: Stack | None = None,
) -> None:
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
    findings = findings_with_fingerprints(report_text, workdir=workdir)
    seen_fingerprints = []
    for row in findings:
        legacy_fp = row.get("legacy_fingerprint")
        if legacy_fp and legacy_fp != row["fingerprint"]:
            repo.rekey_open_sast_fingerprint(
                project_id=project_id,
                old_fingerprint=legacy_fp,
                new_fingerprint=row["fingerprint"],
            )
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
            code_region_hash=row.get("code_region_hash"),
            cvss_vector=vector or None,
            cvss_score=score,
            description=row.get("description") or None,
            recommendation=row.get("recommendation") or None,
            run_id=run_id,
            construct=row.get("construct") or None,
            **_stack_fields(stack, language_for_path(row["location_file"])),
        )
        seen_fingerprints.append(row["fingerprint"])

    repo.close_stale_sast_findings(
        project_id=project_id,
        run_id=run_id,
        seen_fingerprints=seen_fingerprints,
        closed_at=_closed_now(),
    )


def update_sca_findings(
    repo: RunRepository,
    *,
    project_id: int,
    run_id: int,
    report_text: str,
    stack: Stack | None = None,
) -> None:
    """update_sast_findings' lifecycle for the SCA Risk Register."""
    seen_fingerprints = []
    for row in sca_report.findings_with_fingerprints(report_text):
        repo.upsert_sca_finding(
            project_id=project_id,
            fingerprint=row["fingerprint"],
            run_id=run_id,
            current_ref=row["id"],
            package=row["package"],
            version=row.get("version") or None,
            ecosystem=row.get("ecosystem") or None,
            issue=row.get("issue") or None,
            severity=row["severity"],
            reachability=row.get("reachability") or None,
            fixed_in=row.get("fixed_in") or None,
            cve=row.get("cve") or None,
            reachability_evidence=row.get("reachability_evidence") or None,
            recommendation=row.get("recommendation") or None,
            construct=row.get("construct") or None,
            **_stack_fields(stack, language_for_ecosystem(row.get("ecosystem"))),
        )
        seen_fingerprints.append(row["fingerprint"])
    repo.close_stale_findings(
        SCA_SKILL_ID, project_id=project_id, run_id=run_id, seen_fingerprints=seen_fingerprints,
        closed_at=_closed_now(),
    )


def update_secret_findings(
    repo: RunRepository,
    *,
    project_id: int,
    run_id: int,
    report_text: str,
    workdir: Path | None = None,
    stack: Stack | None = None,
) -> None:
    """update_sast_findings' lifecycle for the Secret Scanning register."""
    seen_fingerprints = []
    for row in secret_report.findings_with_fingerprints(report_text, workdir=workdir):
        repo.upsert_secret_finding(
            project_id=project_id,
            fingerprint=row["fingerprint"],
            run_id=run_id,
            current_ref=row["id"],
            secret_type=row["secret_type"],
            location_file=row["location_file"],
            location_line=row.get("location_line"),
            code_region_hash=row.get("code_region_hash"),
            source=row.get("source") or None,
            validity=row.get("validity") or None,
            severity=row["severity"],
            evidence=row.get("evidence"),
            exposure=row.get("exposure") or None,
            remediation=row.get("remediation") or None,
            construct=row.get("construct") or None,
            **_stack_fields(stack, language_for_path(row["location_file"])),
        )
        seen_fingerprints.append(row["fingerprint"])
    repo.close_stale_findings(
        SECRET_SKILL_ID, project_id=project_id, run_id=run_id, seen_fingerprints=seen_fingerprints,
        closed_at=_closed_now(),
    )


def _mark_run_crashed(repo: RunRepository, run_uuid: str, *, duration_seconds: float) -> None:
    """Close out a run whose skill raised before complete_run(): status
    'failed', with the traceback kept as the stderr excerpt. Never raises,
    so it can't mask the original exception."""
    try:
        repo.complete_run(
            run_uuid,
            status="failed",
            exit_code=None,
            duration_seconds=duration_seconds,
            report_path=None,
            prompt_path=None,
            stderr_excerpt=f"secfoo crashed during this run:\n{traceback.format_exc()}"[-STDERR_EXCERPT_LIMIT:],
        )
    except Exception:
        logger.exception("Failed to mark crashed run %s as failed", run_uuid)


STRUCTURED_FINDINGS_SKILLS = frozenset({SAST_SKILL_ID, SCA_SKILL_ID, SECRET_SKILL_ID})


def update_structured_findings(
    repo: RunRepository,
    *,
    skill_id: str,
    project_id: int,
    run_id: int,
    report_text: str,
    workdir: Path | None = None,
    stack: Stack | None = None,
) -> None:
    """Dispatches one successful run's report to its skill's findings
    lifecycle (a no-op for skills without one). The single entry point both
    callers use -- _run_single_skill after a local run, and
    portal/routes/ingest.py after a pushed one (no workdir there, so no
    region hashes or framework detection)."""
    if skill_id == SAST_SKILL_ID:
        update_sast_findings(
            repo, project_id=project_id, run_id=run_id, report_text=report_text, workdir=workdir, stack=stack
        )
    elif skill_id == SCA_SKILL_ID:
        update_sca_findings(repo, project_id=project_id, run_id=run_id, report_text=report_text, stack=stack)
    elif skill_id == SECRET_SKILL_ID:
        update_secret_findings(
            repo, project_id=project_id, run_id=run_id, report_text=report_text, workdir=workdir, stack=stack
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
    stack: Stack | None = None,
) -> RunOutcome:
    skill = load_skill(skill_id)
    memory_enabled = memory.is_active_for_agent(agent_id)
    prompt = render_prompt(
        skill, target_ctx, depth=depth, exclude_paths=exclude_paths, memory_enabled=memory_enabled, stack=stack
    )

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
        started = time.monotonic()

        # The row now says 'running' and only complete_run() moves it on, so
        # anything raised before that point (adapter crash, disk error, a
        # report parser) must still close the row out -- otherwise it reads
        # as "running" in `secfoo list` and the dashboard forever.
        try:
            report_dir = run_dir(run_uuid)
            report_dir.mkdir(parents=True, exist_ok=True)
            prompt_path = report_dir / "prompt.md"
            prompt_path.write_text(prompt, encoding="utf-8")

            if on_skill_start:
                on_skill_start(skill.name)

            adapter = get_adapter(agent_id)
            result = adapter.run(prompt, workdir=target_ctx.local_path, timeout=timeout)
            # Memory Bank: capture HEAD SHA so future runs can diff against this baseline.
            target_commit = _git_head_commit(target_ctx.local_path)

            if on_skill_complete:
                on_skill_complete(skill.name, result.status)

            (report_dir / "stdout.log").write_text(result.stdout, encoding="utf-8")
            (report_dir / "stderr.log").write_text(result.stderr, encoding="utf-8")
            report_path = report_dir / "report.md"
            report_text = strip_preamble(result.raw_report)
            report_path.write_text(report_text, encoding="utf-8")
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
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                cost_usd=result.cost_usd,
                target_commit=target_commit,  # Memory Bank: persisted for incremental diff rescans.
                memory_enabled=memory_enabled,
            )
        except BaseException:
            # BaseException so Ctrl+C mid-run is recorded too; re-raised
            # either way, so callers see exactly what they did before.
            _mark_run_crashed(repo, run_uuid, duration_seconds=time.monotonic() - started)
            raise

        if result.status == "success":
            _try_cloud_sync(repo, run_uuid)
            if skill.id == SCA_SKILL_ID:
                _try_osv_enrich(repo, report_text)
            if skill.id in STRUCTURED_FINDINGS_SKILLS:
                try:
                    completed_run = repo.get_run(run_uuid)
                    update_structured_findings(
                        repo,
                        skill_id=skill.id,
                        project_id=project_id,
                        run_id=completed_run.id,
                        report_text=report_text,
                        workdir=target_ctx.local_path,
                        stack=stack,
                    )
                except Exception:
                    logger.exception("Failed to update %s finding lifecycle for run %s", skill.id, run_uuid)

        return RunOutcome(
            run_uuid=run_uuid,
            skill_id=skill.id,
            skill_name=skill.name,
            agent_id=agent_id,
            status=result.status,
            exit_code=result.exit_code,
            duration_seconds=result.duration_seconds,
            report_path=str(report_path),
            cost_usd=result.cost_usd,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            critical_count=severity.critical,
            high_count=severity.high,
            medium_count=severity.medium,
            low_count=severity.low,
            info_count=severity.info,
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
            # Once per target, not per skill: every skill scans the same tree.
            stack = detect_stack(workdir)
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
                        stack=stack,
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
