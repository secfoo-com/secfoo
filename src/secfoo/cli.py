from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from secfoo import cloud as cloud_module
from secfoo import mcp as mcp_module
from secfoo.agents.registry import ADAPTERS, get_adapter
from secfoo.aibom import AIBOMParseError, parse_ai_bom
from secfoo.attachments import infer_attachment_kind
from secfoo.cloud import CloudConfig, CloudError
from secfoo.config import CLOUD_CONFIG_PATH, attachment_dir
from secfoo.runner import _project_display_name, execute_runs
from secfoo.settings import CONFIG_PATH, ConfigError, load_config
from secfoo.skills.loader import load_all_skills
from secfoo.skills.renderer import merge_excludes as _merge_excludes
from secfoo.storage.repository import RunRepository
from secfoo.targets.resolver import TargetResolutionError, resolve_target

app = typer.Typer(name="secfoo", help="Context-based security architectural assessment.")
mcp_app = typer.Typer(name="mcp", help="Manage MCP servers configured in ~/.secfoo/config.toml.")
config_app = typer.Typer(name="config", help="Manage ~/.secfoo/config.toml.")
assessment_app = typer.Typer(name="assessment", help="Manage assessment case files.")
exception_app = typer.Typer(name="exception", help="Manage risk-acceptance exceptions.")
miss_app = typer.Typer(name="miss", help="Record threats a threat model missed, found post-build.")
accept_app = typer.Typer(name="accept", help="Record a human risk acceptance for a specific threat.")
cloud_app = typer.Typer(name="cloud", help="Connect to the secfoo enterprise portal.")
vendor_app = typer.Typer(name="vendor", help="Fetch optional local assets for the dashboard.")
app.add_typer(mcp_app, name="mcp")
app.add_typer(config_app, name="config")
app.add_typer(assessment_app, name="assessment")
app.add_typer(exception_app, name="exception")
app.add_typer(miss_app, name="miss")
app.add_typer(accept_app, name="accept")
app.add_typer(cloud_app, name="cloud")
app.add_typer(vendor_app, name="vendor")
console = Console()
err_console = Console(stderr=True)

CONFIG_EXAMPLE_PATH = Path(__file__).parent / "config.example.toml"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Derived from the skill definition files rather than hand-listed, so
# dropping a new definitions/*.md in registers it with the CLI (and its
# --help choices) automatically. Hand-maintaining this enum alongside the
# files is exactly the kind of drift that ships a skill the web UI offers
# but the CLI rejects.
SkillId = Enum(  # type: ignore[misc]
    "SkillId",
    {skill.id.upper().replace("-", "_"): skill.id for skill in load_all_skills().values()},
    type=str,
)


class AgentId(str, Enum):
    CLAUDE = "claude"
    CURSOR = "agent"
    ANTIGRAVITY = "agy"
    GEMINI = "gemini"


class DepthId(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"


class AssessmentTypeId(str, Enum):
    INTERNAL = "internal"
    THIRD_PARTY = "third-party"


class AssessmentStatusId(str, Enum):
    READY = "ready"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


def _db_assessment_type(value: AssessmentTypeId) -> str:
    return value.value.replace("-", "_")


def _is_interactive() -> bool:
    """False under CI/scripted use (and test runners) -- gates the
    project-name/application-id prompts in `run` so headless invocations
    never block on stdin. A separate function (rather than an inline
    `sys.stdin.isatty()`) so tests can force each branch: real terminals
    replace stdin with something click's CliRunner controls, which the
    test process can't reliably make isatty() report True for.
    """
    return sys.stdin.isatty()


def _resolve_project_id(repo: RunRepository, target: str | None) -> int:
    resolved = resolve_target(target)
    return repo.upsert_project(
        identifier=resolved.display_name,
        display_name=_project_display_name(resolved),
        kind=resolved.kind.value,
    )


_STATUS_STYLE = {
    "success": "green",
    "failed": "red",
    "timeout": "yellow",
    "binary_not_found": "red",
    "running": "cyan",
}


@app.command()
def run(
    skill: list[SkillId] = typer.Option(
        ..., "--skill", "-s", help="Security skill to run. Repeatable."
    ),
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="GitHub URL or local directory. Defaults to the current directory."
    ),
    confluence: list[str] = typer.Option(
        [], "--confluence", "-c", help="Confluence page URL for extra context. Repeatable."
    ),
    agent: Optional[AgentId] = typer.Option(
        None,
        "--agent",
        "-a",
        help="Which agent CLI runs the assessment. Falls back to [defaults].agent in "
        "~/.secfoo/config.toml, then to claude.",
    ),
    depth: Optional[DepthId] = typer.Option(
        None,
        "--depth",
        "-d",
        help="quick: fast triage, top findings only (good when time is limited). "
        "standard: thorough, full checklist coverage, takes longer. Falls back to "
        "[defaults].depth in ~/.secfoo/config.toml, then to quick.",
    ),
    timeout: Optional[int] = typer.Option(
        None,
        "--timeout",
        help="Per-skill timeout in seconds. Falls back to [defaults].timeout in "
        "~/.secfoo/config.toml, then to the agent's own default.",
    ),
    assessment: Optional[int] = typer.Option(
        None,
        "--assessment",
        help="Attach this run to an existing assessment case file. "
        "See `secfoo assessment create`.",
    ),
    project_name: Optional[str] = typer.Option(
        None,
        "--project-name",
        help="Friendly name for this project, shown across the dashboard instead "
        "of the raw URL/path. Only used when --assessment is omitted (a fresh "
        "assessment is being auto-created); prompted for interactively if left "
        "unset on a terminal.",
    ),
    app_id: Optional[str] = typer.Option(
        None,
        "--app-id",
        help="Application ID to record on the auto-created assessment (e.g. from "
        "your asset inventory/CMDB). Only used when --assessment is omitted; "
        "prompted for interactively if left unset on a terminal.",
    ),
    exclude: list[str] = typer.Option(
        [],
        "--exclude",
        "-x",
        help="Path to exclude from the scan (e.g. a vendored or unrelated "
        "checked-out repo). Repeatable, and added on top of [defaults].exclude "
        "in ~/.secfoo/config.toml and the built-in exclusions.",
    ),
) -> None:
    """Run one or more security skills against a target using the chosen agent.

    Multiple --skill flags run concurrently, not one after another.
    """
    for url in confluence:
        if not url.strip().lower().startswith(("http://", "https://")):
            console.print(f"[yellow]Warning:[/] {url!r} doesn't look like a URL — passing it through anyway.")

    # No --assessment means execute_runs() will auto-create one for this run.
    # On a real terminal, ask for the two fields that make that case file
    # actually trackable later instead of silently falling back to a
    # URL/path-derived name and no application ID.
    if assessment is None and _is_interactive():
        if project_name is None:
            try:
                default_name = _project_display_name(resolve_target(target))
            except TargetResolutionError:
                default_name = None
            project_name = Prompt.ask("Project name", default=default_name, console=console) or None
        if app_id is None:
            app_id = Prompt.ask("Application ID (optional)", default="", console=console) or None

    try:
        file_defaults = load_config().defaults
    except ConfigError as exc:
        err_console.print(f"[red]Error in {CONFIG_PATH}:[/] {exc}")
        raise typer.Exit(code=1) from None

    if agent is None:
        agent = AgentId(file_defaults.agent) if file_defaults.agent else AgentId.CLAUDE
    if depth is None:
        depth = DepthId(file_defaults.depth) if file_defaults.depth else DepthId.QUICK
    if timeout is None:
        timeout = file_defaults.timeout
    # Exclusions are additive rather than override: --exclude adds to the
    # config's list, so naming one path can't silently drop the others.
    exclude_paths = _merge_excludes(file_defaults.exclude, exclude)

    task_ids: dict[str, int] = {}
    progress = Progress(SpinnerColumn(finished_text=" "), TextColumn("{task.description}"), console=console)

    def handle_start(skill_name: str) -> None:
        task_ids[skill_name] = progress.add_task(f"Running [bold]{skill_name}[/] via {agent.value}...", total=None)

    def handle_complete(skill_name: str, result_status: str) -> None:
        style = _STATUS_STYLE.get(result_status, "white")
        task_id = task_ids.get(skill_name)
        if task_id is not None:
            progress.update(
                task_id,
                description=f"[{style}]{result_status}[/] — {skill_name}",
                total=1,
                completed=1,
            )
            progress.stop_task(task_id)

    with progress:
        try:
            outcomes = execute_runs(
                skill_ids=[s.value for s in skill],
                target=target,
                confluence_urls=confluence,
                agent_id=agent.value,
                depth=depth.value,
                timeout=timeout,
                on_skill_start=handle_start,
                on_skill_complete=handle_complete,
                assessment_id=assessment,
                exclude_paths=exclude_paths,
                project_display_name=project_name,
                assessment_application_id=app_id,
            )
        except TargetResolutionError as exc:
            err_console.print(f"[red]Error:[/] {exc}")
            raise typer.Exit(code=1) from None

    table = Table(title="Assessment results")
    table.add_column("Skill")
    table.add_column("Status")
    table.add_column("Duration")
    table.add_column("Run ID")

    any_failed = False
    for outcome in outcomes:
        style = _STATUS_STYLE.get(outcome.status, "white")
        duration = f"{outcome.duration_seconds:.1f}s" if outcome.duration_seconds else "-"
        table.add_row(outcome.skill_name, f"[{style}]{outcome.status}[/]", duration, outcome.run_uuid)
        if outcome.status != "success":
            any_failed = True

    console.print(table)
    console.print("Run [bold]secfoo serve[/] to view full reports in your browser.")
    if any_failed:
        raise typer.Exit(code=1)


@app.command(name="list")
def list_runs(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Filter by project name/URL substring."),
    limit: int = typer.Option(50, "--limit", help="Maximum runs to show."),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by run status."),
) -> None:
    """List past assessment runs."""
    with RunRepository() as repo:
        project_id = None
        if project:
            matches = [
                p for p in repo.list_projects()
                if project.lower() in p.display_name.lower() or project.lower() in p.identifier.lower()
            ]
            if not matches:
                console.print(f"[yellow]No project matches {project!r}.[/]")
                return
            project_id = matches[0].id

        runs = repo.list_runs(project_id=project_id, limit=limit, status=status)

    if not runs:
        console.print("No runs found.")
        return

    table = Table(title="Assessment runs")
    table.add_column("Started")
    table.add_column("Project")
    table.add_column("Skill")
    table.add_column("Agent")
    table.add_column("Status")
    table.add_column("Run ID")

    for r in runs:
        style = _STATUS_STYLE.get(r.status, "white")
        table.add_row(
            r.started_at.split("T")[0] + " " + r.started_at.split("T")[1][:8],
            r.project_display_name or "",
            r.skill_name,
            r.agent_id,
            f"[{style}]{r.status}[/]",
            r.run_uuid,
        )
    console.print(table)


@app.command()
def show(
    run_uuid: str,
    json_output: bool = typer.Option(False, "--json", help="Print the run record as JSON instead of the report."),
) -> None:
    """Show a single assessment run's report."""
    with RunRepository() as repo:
        record = repo.get_run(run_uuid)

    if record is None:
        err_console.print(f"[red]No run found with id {run_uuid!r}.[/]")
        raise typer.Exit(code=1)

    if json_output:
        console.print_json(json.dumps(record.__dict__))
        return

    console.print(f"[bold]{record.skill_name}[/] via {record.agent_id} — status: {record.status}")
    if record.report_path and Path(record.report_path).exists():
        console.print(Path(record.report_path).read_text())
    else:
        console.print("[yellow]No report content available for this run.[/]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8787, "--port"),
) -> None:
    """Launch the local web dashboard."""
    import uvicorn

    from secfoo.web.app import create_app

    console.print(f"Serving dashboard at [bold]http://{host}:{port}[/]")
    uvicorn.run(create_app(), host=host, port=port)


@app.command()
def agents() -> None:
    """List known agent adapters and whether their CLI is installed."""
    table = Table(title="Agent adapters")
    table.add_column("Agent ID")
    table.add_column("Binary")
    table.add_column("Available")

    for agent_id in ADAPTERS:
        adapter = get_adapter(agent_id)
        available = adapter.is_available()
        style = "green" if available else "red"
        table.add_row(agent_id, adapter.binary, f"[{style}]{'yes' if available else 'no'}[/]")
    console.print(table)


@assessment_app.command(name="create")
def assessment_create(
    project: Optional[str] = typer.Option(
        None,
        "--project",
        "-p",
        help="Public GitHub repo URL or local directory. Defaults to the current directory.",
    ),
    name: Optional[str] = typer.Option(
        None, "--name", help="Friendly project name to display. Defaults to the name derived from --project."
    ),
    assessment_type: AssessmentTypeId = typer.Option(..., "--type", help="internal or third-party."),
    status: AssessmentStatusId = typer.Option(AssessmentStatusId.READY.value, "--status"),
    app_id: Optional[str] = typer.Option(None, "--app-id", help="Application ID."),
    sar: Optional[str] = typer.Option(None, "--sar", help="Security Assessment Request number."),
    reviewer: Optional[str] = typer.Option(None, "--reviewer"),
    review_date: Optional[str] = typer.Option(None, "--review-date"),
    notes: Optional[str] = typer.Option(None, "--notes"),
) -> None:
    """Create a new assessment case file that runs (and file attachments) can attach to."""
    try:
        with RunRepository() as repo:
            project_id = _resolve_project_id(repo, project)
            if name:
                repo.rename_project(project_id, name)
            assessment_id = repo.create_assessment(
                project_id=project_id,
                assessment_type=_db_assessment_type(assessment_type),
                status=status.value,
                application_id=app_id,
                sar_number=sar,
                reviewer=reviewer,
                review_date=review_date,
                notes=notes,
            )
    except TargetResolutionError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None
    console.print(f"Created assessment [bold]{assessment_id}[/].")


@assessment_app.command(name="list")
def assessment_list(
    assessment_type: Optional[AssessmentTypeId] = typer.Option(None, "--type"),
    status: Optional[AssessmentStatusId] = typer.Option(None, "--status"),
    search: Optional[str] = typer.Option(None, "--search"),
) -> None:
    """List assessment case files."""
    with RunRepository() as repo:
        assessments = repo.list_assessments(
            assessment_type=_db_assessment_type(assessment_type) if assessment_type else None,
            status=status.value if status else None,
            search=search,
        )

    if not assessments:
        console.print("No assessments found.")
        return

    table = Table(title="Assessments")
    table.add_column("ID")
    table.add_column("Project")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Application ID")
    table.add_column("Security Assessment Request")
    table.add_column("Findings")
    for a in assessments:
        findings = f"{a.critical_count}C {a.high_count}H {a.medium_count}M {a.low_count}L {a.info_count}I"
        table.add_row(
            str(a.id),
            a.project_display_name or "",
            a.assessment_type,
            a.status,
            a.application_id or "-",
            a.sar_number or "-",
            findings,
        )
    console.print(table)


@assessment_app.command(name="show")
def assessment_show(assessment_id: int) -> None:
    """Show a single assessment's details, attachments, and attached runs."""
    with RunRepository() as repo:
        a = repo.get_assessment(assessment_id)
        if a is None:
            err_console.print(f"[red]No assessment found with id {assessment_id}.[/]")
            raise typer.Exit(code=1)
        attachments = repo.list_attachments(assessment_id)
        runs = repo.list_runs(assessment_id=assessment_id, limit=200)

    console.print(f"[bold]Assessment {a.id}[/] — {a.project_display_name} ({a.assessment_type})")
    console.print(f"Status: {a.status}")
    console.print(f"Application ID: {a.application_id or '-'}")
    console.print(f"Security Assessment Request: {a.sar_number or '-'}")
    console.print(f"Reviewer: {a.reviewer or '-'}    Review date: {a.review_date or '-'}")
    if a.notes:
        console.print(f"Notes: {a.notes}")
    console.print(
        f"Findings: {a.critical_count} critical, {a.high_count} high, {a.medium_count} medium, "
        f"{a.low_count} low, {a.info_count} info"
    )
    if a.responsible_ai_risk:
        console.print(f"Responsible AI: {a.responsible_ai_risk} ({a.responsible_ai_status})")

    if runs:
        table = Table(title="Attached runs")
        table.add_column("Started")
        table.add_column("Skill")
        table.add_column("Agent")
        table.add_column("Status")
        table.add_column("Run ID")
        for r in runs:
            style = _STATUS_STYLE.get(r.status, "white")
            table.add_row(r.started_at.split("T")[0], r.skill_name, r.agent_id, f"[{style}]{r.status}[/]", r.run_uuid)
        console.print(table)

    if attachments:
        table = Table(title="Attachments")
        table.add_column("File")
        table.add_column("Kind")
        table.add_column("Uploaded")
        for att in attachments:
            table.add_row(att.original_name, att.attachment_kind, att.uploaded_at.split("T")[0])
        console.print(table)


@assessment_app.command(name="update")
def assessment_update(
    assessment_id: int,
    status: Optional[AssessmentStatusId] = typer.Option(None, "--status"),
    app_id: Optional[str] = typer.Option(None, "--app-id"),
    sar: Optional[str] = typer.Option(None, "--sar"),
    reviewer: Optional[str] = typer.Option(None, "--reviewer"),
    review_date: Optional[str] = typer.Option(None, "--review-date"),
    notes: Optional[str] = typer.Option(None, "--notes"),
) -> None:
    """Update fields on an existing assessment."""
    fields: dict[str, object] = {}
    if status is not None:
        fields["status"] = status.value
    if app_id is not None:
        fields["application_id"] = app_id
    if sar is not None:
        fields["sar_number"] = sar
    if reviewer is not None:
        fields["reviewer"] = reviewer
    if review_date is not None:
        fields["review_date"] = review_date
    if notes is not None:
        fields["notes"] = notes

    if not fields:
        err_console.print("[yellow]Nothing to update — pass at least one field.[/]")
        raise typer.Exit(code=1)

    with RunRepository() as repo:
        if repo.get_assessment(assessment_id) is None:
            err_console.print(f"[red]No assessment found with id {assessment_id}.[/]")
            raise typer.Exit(code=1)
        repo.update_assessment(assessment_id, **fields)
    console.print(f"Updated assessment [bold]{assessment_id}[/].")


@assessment_app.command(name="upload")
def assessment_upload(assessment_id: int, file_path: Path) -> None:
    """Attach a file to an assessment. AI-BOM files (name containing
    'ai-bom', .json or .csv) are parsed immediately into a model/tool
    inventory.
    """
    if not file_path.exists():
        err_console.print(f"[red]File not found: {file_path}[/]")
        raise typer.Exit(code=1)

    with RunRepository() as repo:
        if repo.get_assessment(assessment_id) is None:
            err_console.print(f"[red]No assessment found with id {assessment_id}.[/]")
            raise typer.Exit(code=1)

        kind = infer_attachment_kind(file_path.name)
        dest_dir = attachment_dir(assessment_id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / file_path.name
        shutil.copyfile(file_path, dest)

        attachment_id = repo.add_attachment(
            assessment_id=assessment_id,
            file_path=str(dest),
            original_name=file_path.name,
            attachment_kind=kind,
        )

        if kind == "ai_bom":
            try:
                summary = parse_ai_bom(dest)
            except AIBOMParseError as exc:
                err_console.print(f"[yellow]Uploaded, but AI-BOM parsing failed:[/] {exc}")
            else:
                items = [{"kind": "model", **m} for m in summary.models] + [
                    {"kind": "tool", **t} for t in summary.tools
                ]
                repo.add_ai_bom_items(attachment_id, items)
                console.print(f"Parsed {len(summary.models)} model(s), {len(summary.tools)} tool(s).")

    console.print(f"Uploaded [bold]{file_path.name}[/] to assessment {assessment_id}.")


@assessment_app.command(name="delete")
def assessment_delete(assessment_id: int) -> None:
    """Delete an assessment. Attached runs are detached, not deleted; attachments are removed."""
    with RunRepository() as repo:
        if repo.get_assessment(assessment_id) is None:
            err_console.print(f"[red]No assessment found with id {assessment_id}.[/]")
            raise typer.Exit(code=1)
        repo.delete_assessment(assessment_id)
    console.print(f"Deleted assessment [bold]{assessment_id}[/].")


@exception_app.command(name="create")
def exception_create(
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="Public GitHub repo URL or local directory. Defaults to the current directory."
    ),
    title: str = typer.Option(..., "--title", help="Short description of what's being accepted."),
    justification: str = typer.Option(..., "--justification", help="Why this risk is being accepted."),
    granted_by: str = typer.Option(..., "--granted-by", help="Who approved this exception."),
    expires_at: str = typer.Option(..., "--expires-at", help="Expiry date, YYYY-MM-DD."),
    standard_or_control: Optional[str] = typer.Option(
        None, "--control", help="CCM domain code or standard clause this exception covers, e.g. IAM or 'SOC 2 CC6.1'."
    ),
    assessment_id: Optional[int] = typer.Option(None, "--assessment", help="Optionally scope to one assessment."),
) -> None:
    """Grant a risk acceptance / waiver against a project."""
    try:
        with RunRepository() as repo:
            project_id = _resolve_project_id(repo, project)
            new_id = repo.create_exception(
                project_id=project_id,
                title=title,
                justification=justification,
                granted_by=granted_by,
                expires_at=expires_at,
                standard_or_control=standard_or_control,
                assessment_id=assessment_id,
            )
    except TargetResolutionError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None
    console.print(f"Created exception [bold]{new_id}[/], expiring {expires_at}.")


@exception_app.command(name="list")
def exception_list(
    status: Optional[str] = typer.Option(None, "--status", help="active or revoked."),
) -> None:
    """List exceptions, soonest-expiring first."""
    with RunRepository() as repo:
        exceptions = repo.list_exceptions(status=status)

    if not exceptions:
        console.print("No exceptions found.")
        return

    table = Table(title="Exceptions")
    table.add_column("ID")
    table.add_column("Project")
    table.add_column("Title")
    table.add_column("Control")
    table.add_column("Status")
    table.add_column("Expires")
    for e in exceptions:
        past_expiry = e.status == "active" and e.expires_at < _now_iso()
        style = "red" if past_expiry else "white"
        table.add_row(
            str(e.id),
            e.project_display_name or "",
            e.title,
            e.standard_or_control or "-",
            e.status,
            f"[{style}]{e.expires_at}[/]",
        )
    console.print(table)


@exception_app.command(name="show")
def exception_show(exception_id: int) -> None:
    """Show a single exception's details."""
    with RunRepository() as repo:
        e = repo.get_exception(exception_id)
    if e is None:
        err_console.print(f"[red]No exception found with id {exception_id}.[/]")
        raise typer.Exit(code=1)

    console.print(f"[bold]Exception {e.id}[/] — {e.project_display_name}")
    console.print(f"Title: {e.title}")
    console.print(f"Control/standard: {e.standard_or_control or '-'}")
    console.print(f"Justification: {e.justification}")
    console.print(f"Granted by: {e.granted_by}")
    console.print(f"Status: {e.status}")
    console.print(f"Created: {e.created_at.split('T')[0]}    Expires: {e.expires_at}")


@exception_app.command(name="update")
def exception_update(
    exception_id: int,
    status: Optional[str] = typer.Option(None, "--status", help="active or revoked."),
    expires_at: Optional[str] = typer.Option(None, "--expires-at"),
    justification: Optional[str] = typer.Option(None, "--justification"),
) -> None:
    """Update an exception -- e.g. revoke it, or extend its expiry."""
    fields: dict[str, object] = {}
    if status is not None:
        fields["status"] = status
    if expires_at is not None:
        fields["expires_at"] = expires_at
    if justification is not None:
        fields["justification"] = justification

    if not fields:
        err_console.print("[yellow]Nothing to update — pass at least one field.[/]")
        raise typer.Exit(code=1)

    with RunRepository() as repo:
        if repo.get_exception(exception_id) is None:
            err_console.print(f"[red]No exception found with id {exception_id}.[/]")
            raise typer.Exit(code=1)
        repo.update_exception(exception_id, **fields)
    console.print(f"Updated exception [bold]{exception_id}[/].")


@exception_app.command(name="delete")
def exception_delete(exception_id: int) -> None:
    """Delete an exception record."""
    with RunRepository() as repo:
        if repo.get_exception(exception_id) is None:
            err_console.print(f"[red]No exception found with id {exception_id}.[/]")
            raise typer.Exit(code=1)
        repo.delete_exception(exception_id)
    console.print(f"Deleted exception [bold]{exception_id}[/].")


@miss_app.command(name="create")
def miss_create(
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="Public GitHub repo URL or local directory. Defaults to the current directory."
    ),
    title: str = typer.Option(..., "--title", help="What was found."),
    discovered_at: str = typer.Option(..., "--discovered-at", help="When it was found, YYYY-MM-DD."),
    description: Optional[str] = typer.Option(None, "--description"),
    discovered_by: Optional[str] = typer.Option(None, "--discovered-by", help="Who/what found it (incident, pen test, ...)."),
    run: Optional[str] = typer.Option(None, "--run", help="Run UUID of the threat model that should have caught this, if known."),
) -> None:
    """Record a threat found after build that an earlier threat model missed.

    Nothing in a report can know what it missed -- this is recorded by
    hand, the same rationale as `secfoo exception create`.
    """
    try:
        with RunRepository() as repo:
            project_id = _resolve_project_id(repo, project)
            run_id = None
            if run:
                run_record = repo.get_run(run)
                if run_record is None:
                    err_console.print(f"[red]No run found with id {run}.[/]")
                    raise typer.Exit(code=1)
                run_id = run_record.id
            new_id = repo.create_post_build_finding(
                project_id=project_id, title=title, discovered_at=discovered_at,
                description=description, discovered_by=discovered_by, run_id=run_id,
            )
    except TargetResolutionError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None
    console.print(f"Recorded post-build finding [bold]{new_id}[/].")


@miss_app.command(name="list")
def miss_list() -> None:
    """List threats found post-build, most recent first."""
    with RunRepository() as repo:
        findings = repo.list_post_build_findings()

    if not findings:
        console.print("No post-build findings recorded.")
        return

    table = Table(title="Post-build findings")
    table.add_column("ID")
    table.add_column("Project")
    table.add_column("Title")
    table.add_column("Discovered by")
    table.add_column("Discovered")
    for f in findings:
        table.add_row(
            str(f.id), f.project_display_name or "", f.title, f.discovered_by or "-", f.discovered_at,
        )
    console.print(table)


@miss_app.command(name="show")
def miss_show(finding_id: int) -> None:
    """Show a single post-build finding's details."""
    with RunRepository() as repo:
        f = repo.get_post_build_finding(finding_id)
    if f is None:
        err_console.print(f"[red]No post-build finding found with id {finding_id}.[/]")
        raise typer.Exit(code=1)

    console.print(f"[bold]Post-build finding {f.id}[/] — {f.project_display_name}")
    console.print(f"Title: {f.title}")
    if f.description:
        console.print(f"Description: {f.description}")
    console.print(f"Discovered by: {f.discovered_by or '-'}    Discovered: {f.discovered_at}")
    if f.run_id:
        console.print(f"Missed by run (internal id): {f.run_id}")


@miss_app.command(name="delete")
def miss_delete(finding_id: int) -> None:
    """Delete a post-build finding record."""
    with RunRepository() as repo:
        if repo.get_post_build_finding(finding_id) is None:
            err_console.print(f"[red]No post-build finding found with id {finding_id}.[/]")
            raise typer.Exit(code=1)
        repo.delete_post_build_finding(finding_id)
    console.print(f"Deleted post-build finding [bold]{finding_id}[/].")


@accept_app.command(name="create")
def accept_create(
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="Public GitHub repo URL or local directory. Defaults to the current directory."
    ),
    threat_id: str = typer.Option(..., "--threat-id", help="The Threat Register row ID from the report, e.g. T4."),
    title: str = typer.Option(..., "--title", help="Short description of the threat being accepted."),
    justification: str = typer.Option(..., "--justification", help="Why this risk is being accepted."),
    accepted_by: str = typer.Option(..., "--accepted-by", help="Who is accepting this risk."),
    expires_at: Optional[str] = typer.Option(None, "--expires-at", help="Optional review-by date, YYYY-MM-DD."),
    run: Optional[str] = typer.Option(None, "--run", help="Run UUID this threat came from, if known."),
) -> None:
    """Record a human risk acceptance for one threat from a Threat Register.

    This is the loop-back a person actually uses to accept a threat -- a
    named owner and justification, tracked independently of whatever
    Disposition the model itself wrote into the report. Same rationale as
    `secfoo exception create` for architecture findings.
    """
    try:
        with RunRepository() as repo:
            project_id = _resolve_project_id(repo, project)
            run_id = None
            if run:
                run_record = repo.get_run(run)
                if run_record is None:
                    err_console.print(f"[red]No run found with id {run}.[/]")
                    raise typer.Exit(code=1)
                run_id = run_record.id
            new_id = repo.create_threat_acceptance(
                project_id=project_id, threat_ref=threat_id, title=title, justification=justification,
                accepted_by=accepted_by, expires_at=expires_at, run_id=run_id,
            )
    except TargetResolutionError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None
    console.print(f"Recorded acceptance [bold]{new_id}[/] for {threat_id}, accepted by {accepted_by}.")


@accept_app.command(name="list")
def accept_list(
    status: Optional[str] = typer.Option(None, "--status", help="active or revoked."),
) -> None:
    """List recorded threat acceptances, most recent first."""
    with RunRepository() as repo:
        acceptances = repo.list_threat_acceptances(status=status)

    if not acceptances:
        console.print("No threat acceptances recorded.")
        return

    table = Table(title="Threat acceptances")
    table.add_column("ID")
    table.add_column("Project")
    table.add_column("Threat")
    table.add_column("Title")
    table.add_column("Accepted by")
    table.add_column("Status")
    for a in acceptances:
        table.add_row(
            str(a.id), a.project_display_name or "", a.threat_ref, a.title, a.accepted_by, a.status,
        )
    console.print(table)


@accept_app.command(name="show")
def accept_show(acceptance_id: int) -> None:
    """Show a single threat acceptance's details."""
    with RunRepository() as repo:
        a = repo.get_threat_acceptance(acceptance_id)
    if a is None:
        err_console.print(f"[red]No threat acceptance found with id {acceptance_id}.[/]")
        raise typer.Exit(code=1)

    console.print(f"[bold]Threat acceptance {a.id}[/] — {a.project_display_name}")
    console.print(f"Threat: {a.threat_ref} — {a.title}")
    console.print(f"Justification: {a.justification}")
    console.print(f"Accepted by: {a.accepted_by}")
    console.print(f"Status: {a.status}")
    console.print(f"Created: {a.created_at.split('T')[0]}    Expires: {a.expires_at or '-'}")


@accept_app.command(name="update")
def accept_update(
    acceptance_id: int,
    status: Optional[str] = typer.Option(None, "--status", help="active or revoked."),
    expires_at: Optional[str] = typer.Option(None, "--expires-at"),
    justification: Optional[str] = typer.Option(None, "--justification"),
) -> None:
    """Update a threat acceptance -- e.g. revoke it, or extend its review date."""
    fields: dict[str, object] = {}
    if status is not None:
        fields["status"] = status
    if expires_at is not None:
        fields["expires_at"] = expires_at
    if justification is not None:
        fields["justification"] = justification

    if not fields:
        err_console.print("[yellow]Nothing to update — pass at least one field.[/]")
        raise typer.Exit(code=1)

    with RunRepository() as repo:
        if repo.get_threat_acceptance(acceptance_id) is None:
            err_console.print(f"[red]No threat acceptance found with id {acceptance_id}.[/]")
            raise typer.Exit(code=1)
        repo.update_threat_acceptance(acceptance_id, **fields)
    console.print(f"Updated threat acceptance [bold]{acceptance_id}[/].")


@accept_app.command(name="delete")
def accept_delete(acceptance_id: int) -> None:
    """Delete a threat acceptance record."""
    with RunRepository() as repo:
        if repo.get_threat_acceptance(acceptance_id) is None:
            err_console.print(f"[red]No threat acceptance found with id {acceptance_id}.[/]")
            raise typer.Exit(code=1)
        repo.delete_threat_acceptance(acceptance_id)
    console.print(f"Deleted threat acceptance [bold]{acceptance_id}[/].")


@cloud_app.command(name="login")
def cloud_login(
    api_key: str = typer.Option(..., "--api-key", help="Ingest-scoped key from your enterprise portal admin."),
    portal_url: str = typer.Option(
        cloud_module.DEFAULT_PORTAL_URL, "--portal-url", help="Override if your org uses a non-default portal."
    ),
) -> None:
    """Connect this machine to the secfoo enterprise portal.

    Validates the key against the portal, then writes it to
    ~/.secfoo/cloud.toml. Every future successful `secfoo run` on this
    machine is pushed to the portal automatically; nothing local changes
    -- `secfoo serve` keeps working exactly as before.
    """
    config = CloudConfig(api_key=api_key, portal_url=portal_url)
    try:
        info = cloud_module.whoami(config)
    except CloudError as exc:
        err_console.print(f"[red]Login failed:[/] {exc}")
        raise typer.Exit(code=1) from None

    if info.get("scope") != "ingest":
        err_console.print(
            f"[red]That key is scoped for {info.get('scope')!r}, not 'ingest'.[/] "
            "Use an ingest key for `secfoo cloud login` -- a view key is for logging into the portal in a browser."
        )
        raise typer.Exit(code=1)

    cloud_module.save_cloud_config(config)
    console.print(
        f"Connected to [bold]{info.get('tenant_display_name', info.get('tenant_slug'))}[/] at {portal_url}."
    )


@cloud_app.command(name="logout")
def cloud_logout() -> None:
    """Disconnect this machine from the enterprise portal (removes cloud.toml)."""
    if not CLOUD_CONFIG_PATH.exists():
        console.print("Not connected to a portal.")
        return
    cloud_module.delete_cloud_config()
    console.print("Disconnected. Local runs and secfoo serve are unaffected.")


@cloud_app.command(name="status")
def cloud_status() -> None:
    """Show portal connection status and how many local runs are unsynced."""
    config = cloud_module.load_cloud_config()
    if config is None:
        console.print("Not connected. Run [bold]secfoo cloud login --api-key <key>[/] to connect.")
        return

    with RunRepository() as repo:
        unsynced = repo.list_unsynced_runs()

    try:
        info = cloud_module.whoami(config)
    except CloudError as exc:
        err_console.print(f"[yellow]Connected to {config.portal_url}, but couldn't reach it just now:[/] {exc}")
        console.print(f"Unsynced local runs: {len(unsynced)}")
        return

    console.print(f"Connected to [bold]{info.get('tenant_display_name', info.get('tenant_slug'))}[/] at {config.portal_url}.")
    console.print(f"Unsynced local runs: {len(unsynced)}")


@cloud_app.command(name="sync")
def cloud_sync() -> None:
    """Push any local runs not yet synced to the portal."""
    config = cloud_module.load_cloud_config()
    if config is None:
        err_console.print("[yellow]Not connected.[/] Run [bold]secfoo cloud login --api-key <key>[/] first.")
        raise typer.Exit(code=1)

    with RunRepository() as repo:
        unsynced = repo.list_unsynced_runs()
        if not unsynced:
            console.print("Nothing to sync -- every local run is already synced.")
            return

        synced_count = 0
        for run in unsynced:
            try:
                cloud_module.sync_run(repo, run.run_uuid, config)
                synced_count += 1
            except CloudError as exc:
                err_console.print(f"[yellow]Failed to sync {run.run_uuid}:[/] {exc}")

    console.print(f"Synced {synced_count}/{len(unsynced)} run(s).")


MERMAID_CDN_URL = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"


@vendor_app.command(name="mermaid")
def vendor_mermaid(
    url: str = typer.Option(MERMAID_CDN_URL, "--url", help="Where to fetch the bundle from."),
    force: bool = typer.Option(False, "--force", help="Re-download even if already present."),
) -> None:
    """Download Mermaid so architecture diagrams render in the dashboard.

    Not bundled by default because it's ~3.5MB -- an order of magnitude
    larger than the rest of secfoo. Without it, diagrams still appear in
    reports as readable Mermaid source; this just renders them visually.
    The file is fetched once and served locally afterwards, so the
    dashboard never calls out to a third party while you read a report.
    """
    import urllib.error
    import urllib.request

    from secfoo.web.app import MERMAID_BUNDLE, VENDOR_DIR

    if MERMAID_BUNDLE.is_file() and not force:
        console.print(f"Already present: {MERMAID_BUNDLE}. Use --force to re-download.")
        return

    console.print(f"Downloading {url} ...")
    try:
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310  # nosec B310 -- pinned https CDN URL for mermaid bundle
            payload = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        err_console.print(f"[red]Download failed:[/] {exc}")
        err_console.print(
            "If this machine has no outbound access, fetch the file elsewhere and copy it to:\n"
            f"  {MERMAID_BUNDLE}"
        )
        raise typer.Exit(code=1) from None

    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    MERMAID_BUNDLE.write_bytes(payload)
    console.print(f"Wrote {MERMAID_BUNDLE} ({len(payload) / 1_000_000:.1f} MB).")
    console.print("Diagrams will now render in [bold]secfoo serve[/] (restart it if it's running).")


@config_app.command(name="init")
def config_init(
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config.toml."),
) -> None:
    """Write a starter ~/.secfoo/config.toml (defaults + an MCP server example)."""
    if CONFIG_PATH.exists() and not force:
        err_console.print(f"[yellow]{CONFIG_PATH} already exists.[/] Use --force to overwrite it.")
        raise typer.Exit(code=1)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(CONFIG_EXAMPLE_PATH.read_text())
    console.print(f"Wrote {CONFIG_PATH}. Edit it, then run [bold]secfoo mcp list[/] to confirm.")


@mcp_app.command(name="list")
def mcp_list() -> None:
    """Show MCP servers configured in ~/.secfoo/config.toml."""
    try:
        cfg = load_config()
    except ConfigError as exc:
        err_console.print(f"[red]Error in {CONFIG_PATH}:[/] {exc}")
        raise typer.Exit(code=1) from None

    if not cfg.mcp_servers:
        console.print(f"No MCP servers configured. Add a [[mcp_servers]] entry to {CONFIG_PATH}.")
        return

    table = Table(title="Configured MCP servers")
    table.add_column("Name")
    table.add_column("Target")
    table.add_column("Transport")
    for server in cfg.mcp_servers:
        table.add_row(server.name, server.url or server.command or "", server.transport)
    console.print(table)
    console.print(
        "\n[bold]claude[/] picks these up automatically on every run (--mcp-config, "
        "scoped to that run only).\nFor [bold]gemini[/] or [bold]agent[/] (Cursor), run "
        "[bold]secfoo mcp sync --agent <agent>[/] once to register them persistently."
    )


@mcp_app.command(name="sync")
def mcp_sync(
    agent: AgentId = typer.Option(..., "--agent", "-a", help="Which agent's MCP config to update."),
) -> None:
    """Register configured MCP servers persistently into gemini's or Cursor's own
    config. claude doesn't need this -- it picks up ~/.secfoo/config.toml
    automatically on every run. agy isn't supported (its CLI has no MCP
    configuration mechanism yet).
    """
    try:
        cfg = load_config()
    except ConfigError as exc:
        err_console.print(f"[red]Error in {CONFIG_PATH}:[/] {exc}")
        raise typer.Exit(code=1) from None

    if not cfg.mcp_servers:
        console.print(f"No MCP servers configured in {CONFIG_PATH} -- nothing to sync.")
        return

    if agent.value == "claude":
        console.print("[yellow]claude doesn't need syncing[/] -- it loads MCP servers automatically on every run.")
        return

    try:
        results = mcp_module.sync(agent.value, cfg.mcp_servers)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None

    any_failed = False
    for result in results:
        style = "green" if result.ok else "red"
        console.print(f"  [{style}]{'ok' if result.ok else 'failed'}[/] {result.server_name}: {result.message}")
        if not result.ok:
            any_failed = True
    if any_failed:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
