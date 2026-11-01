"""Presentation helpers for a single run: the step checklist on the run
page, the "Blocked" explanation for a run that didn't produce a report,
and per-agent facts the dashboard needs (install hint, whether the CLI
reports its own cost).

The runner doesn't emit progress events, so the steps are derived from
what a run has left behind so far -- prompt.md is written just before the
agent is invoked, stdout.log right after it returns, and report_path once
the report has been parsed. That's coarse (the agent's own work is one
step), but it is accurate: nothing here is guessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from secfoo.agents.api import KEY_VARS
from secfoo.agents.registry import ADAPTERS, get_adapter
from secfoo.config import run_dir
from secfoo.storage.models import RunRecord

ACTIVE_STATUSES = {"pending", "running"}

# Agents whose CLI reports token usage / cost back to secfoo. The others run
# on the user's own subscription and say nothing about spend, so the
# dashboard labels them instead of showing a bare "-".
COST_REPORTING_AGENTS = {"claude", "gemini", "api", "droid"}

AGENT_LABELS = {
    "claude": "Claude Code",
    "agent": "Cursor",
    "agy": "Antigravity",
    "gemini": "Gemini CLI",
    "codex": "Codex CLI",
    "copilot": "GitHub Copilot CLI",
    "droid": "Factory Droid",
    "devin": "Devin",
    "api": "API agent (LiteLLM)",
}

INSTALL_HINTS = {
    "claude": "npm install -g @anthropic-ai/claude-code",
    "agent": "curl https://cursor.com/install -fsS | bash",
    "gemini": "npm install -g @google/gemini-cli",
    "codex": "npm install -g @openai/codex",
    "copilot": "npm install -g @github/copilot",
    "api": f"Set one of {', '.join(KEY_VARS)} in your environment",
}


@dataclass(frozen=True)
class RunStep:
    label: str
    state: str  # "done" | "live" | "failed" | "todo"
    detail: str = ""


@dataclass(frozen=True)
class BlockedHint:
    title: str
    explanation: str
    fix: str | None = None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def elapsed_seconds(run: RunRecord) -> float | None:
    """Wall-clock seconds so far for a live run, or the recorded duration."""
    if run.duration_seconds is not None:
        return run.duration_seconds
    started = _parse_time(run.started_at)
    if started is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - started).total_seconds())


def run_steps(run: RunRecord) -> list[RunStep]:
    folder = run_dir(run.run_uuid)
    prompt_written = (folder / "prompt.md").exists() or bool(run.prompt_path)
    agent_returned = (folder / "stdout.log").exists() or run.status not in ACTIVE_STATUSES
    report_saved = bool(run.report_path) and run.status not in ACTIVE_STATUSES
    failed = run.status not in ACTIVE_STATUSES and run.status != "success"
    agent_label = AGENT_LABELS.get(run.agent_id, run.agent_id)

    steps = [RunStep("Run created", "done", run.started_at[:19].replace("T", " "))]
    # The runner writes prompt.md before invoking the agent, so any finished
    # run got past this step even if its prompt file has since been removed.
    prompt_done = prompt_written or run.status not in ACTIVE_STATUSES
    steps.append(RunStep("Prompt prepared from skill", "done" if prompt_done else "live"))

    if failed:
        agent_state = "failed"
    elif not prompt_written:
        agent_state = "todo"
    elif agent_returned:
        agent_state = "done"
    else:
        agent_state = "live"
    confluence = f" with {len(run.confluence_urls)} Confluence page(s)" if run.confluence_urls else ""
    steps.append(RunStep(f"{agent_label} reviewing the target{confluence}", agent_state))

    if failed:
        steps.append(RunStep("Report saved and findings counted", "todo", "skipped: the agent didn't finish"))
    else:
        steps.append(RunStep("Report saved and findings counted", "done" if report_saved else "todo"))
    return steps


def blocked_hint(run: RunRecord) -> BlockedHint | None:
    """Plain-language cause and fix for a run that ended without success."""
    agent_label = AGENT_LABELS.get(run.agent_id, run.agent_id)
    if run.status == "binary_not_found":
        if run.agent_id == "api":
            return BlockedHint(
                "No API key found for the api agent",
                "The api agent calls a model provider directly and needs a key in the environment "
                "of the process running secfoo.",
                INSTALL_HINTS["api"],
            )
        binary = ADAPTERS[run.agent_id].binary if run.agent_id in ADAPTERS else run.agent_id
        return BlockedHint(
            f"{agent_label} isn't installed",
            f"secfoo couldn't find the {binary!r} command on PATH, so the agent never started.",
            INSTALL_HINTS.get(run.agent_id),
        )
    if run.status == "timeout":
        return BlockedHint(
            "The agent ran out of time",
            "The run hit its timeout before the agent returned a report. Large repositories or "
            "standard depth can need longer.",
            "Re-run with --timeout set higher, or exclude vendored paths",
        )
    if run.status == "failed":
        exit_note = f" (exit code {run.exit_code})" if run.exit_code is not None else ""
        return BlockedHint(
            f"{agent_label} stopped with an error{exit_note}",
            "The agent exited before producing a usable report. The error output below usually "
            "says why: an expired sign-in, a rate limit, or a sandbox refusing to read the target.",
            None,
        )
    return None


def agent_health(runs_by_agent: dict[str, dict]) -> list[dict]:
    """One row per registered agent for the Agents page and dashboard card.

    `runs_by_agent` maps agent id -> {"runs": int, "last_run_at": str|None,
    "last_success_at": str|None}. "Ready" only means the CLI (or API key) is
    present -- secfoo can't tell whether a CLI is still signed in without
    launching it, so the page says so rather than implying more.
    """
    rows = []
    for agent_id in ADAPTERS:
        adapter = get_adapter(agent_id)
        available = adapter.is_available()
        stats = runs_by_agent.get(agent_id, {})
        rows.append(
            {
                "id": agent_id,
                "label": AGENT_LABELS.get(agent_id, agent_id),
                "binary": adapter.binary,
                "available": available,
                "reports_cost": agent_id in COST_REPORTING_AGENTS,
                "install_hint": None if available else INSTALL_HINTS.get(agent_id),
                "runs": stats.get("runs", 0),
                "last_run_at": stats.get("last_run_at"),
                "last_success_at": stats.get("last_success_at"),
                "last_status": stats.get("last_status"),
            }
        )
    return rows


BLOCKED_STATUSES = {"binary_not_found", "failed", "timeout"}


def assessment_pipeline(runs: list[RunRecord], skill_order: list) -> list[dict]:
    """One node per security activity, in review order, for the assessment
    page's pipeline view. Each node reflects the LATEST run of that skill
    on this assessment: done / blocked / running / not run, plus that run's
    finding counts. Skills with no run still appear, so coverage gaps are
    visible rather than silently missing."""
    latest: dict[str, RunRecord] = {}
    for run in sorted(runs, key=lambda r: r.started_at):
        latest[run.skill_id] = run
    nodes = []
    for skill in skill_order:
        run = latest.get(skill.id)
        if run is None:
            state = "todo"
        elif run.status in ACTIVE_STATUSES:
            state = "running"
        elif run.status in BLOCKED_STATUSES:
            state = "blocked"
        else:
            state = "done"
        nodes.append(
            {
                "id": skill.id,
                "label": skill.nav_label,
                "state": state,
                "run": run,
                "findings": (run.critical_count + run.high_count + run.medium_count + run.low_count) if run else 0,
                "severe": (run.critical_count + run.high_count) if run else 0,
            }
        )
    return nodes


def setup_steps(*, agents: list[dict], assessment_count: int, run_count: int, reviewed_count: int) -> list[dict]:
    """The dashboard's getting-started checklist, each step checked off from
    real state rather than a "dismiss" flag."""
    return [
        {"label": "Set up an agent", "detail": "Install a coding-agent CLI or set an API key.",
         "done": any(a["available"] for a in agents), "href": "/agents"},
        {"label": "Create an assessment", "detail": "Name the project and point at its code.",
         "done": assessment_count > 0, "href": "/assessments/new"},
        {"label": "Run your first activity", "detail": "Pick a starter template and start a run.",
         "done": run_count > 0, "href": "/assessments"},
        {"label": "Sign off a finding", "detail": "Confirm, dismiss or accept the risk on a SAST finding.",
         "done": reviewed_count > 0, "href": "/activities/sast/findings"},
    ]
