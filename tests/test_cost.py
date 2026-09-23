from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from secfoo.cli import app
from secfoo.cost import format_cost, format_tokens
from secfoo.runner import RunOutcome
from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app

runner = CliRunner()


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    return tmp_path


def _seed(*, agent_id: str, skill: str = "SAST", project: str = "org/repo", cost=None, tokens=None, status="success"):
    repo = RunRepository()
    project_id = repo.upsert_project(f"https://github.com/{project}", project, "github")
    run_uuid = repo.create_run(
        project_id=project_id,
        skill_id=skill.lower(),
        skill_name=skill,
        agent_id=agent_id,
        confluence_urls=[],
    )
    repo.complete_run(
        run_uuid,
        status=status,
        exit_code=0,
        duration_seconds=1.0,
        report_path=None,
        prompt_path=None,
        stderr_excerpt=None,
        input_tokens=tokens[0] if tokens else None,
        output_tokens=tokens[1] if tokens else None,
        cost_usd=cost,
    )
    repo.close()
    return run_uuid


def test_format_cost_and_tokens():
    assert format_cost(None) == "-"
    assert format_cost(0.0) == "$0.00"
    assert format_cost(0.004) == "<$0.01"
    assert format_cost(1234.5) == "$1,234.50"
    assert format_tokens(None) == "-"
    assert format_tokens(1234567) == "1,234,567"


def test_complete_run_stores_usage(db):
    run_uuid = _seed(agent_id="api", cost=0.25, tokens=(1000, 200))
    with RunRepository() as repo:
        run = repo.get_run(run_uuid)
    assert run.cost_usd == 0.25
    assert run.input_tokens == 1000
    assert run.output_tokens == 200


def test_cost_summary_groups_and_counts_unpriced_runs(db):
    _seed(agent_id="api", cost=0.25, tokens=(1000, 200))
    _seed(agent_id="api", skill="Threat Modeling", cost=0.75, tokens=(3000, 400))
    _seed(agent_id="agent")  # cursor: no usage reported
    _seed(agent_id="api", status="running", cost=9.0)  # in flight: excluded

    with RunRepository() as repo:
        rows = {r.label: r for r in repo.cost_summary(group_by="agent")}

    assert rows["api"].runs == 2
    assert rows["api"].cost_usd == pytest.approx(1.0)
    assert rows["api"].input_tokens == 4000
    assert rows["api"].unpriced_runs == 0
    assert rows["agent"].cost_usd == 0
    assert rows["agent"].unpriced_runs == 1


def test_cost_summary_since_filters_old_runs(db):
    _seed(agent_id="api", cost=0.5)
    with RunRepository() as repo:
        assert repo.cost_summary(group_by="skill", since="2999-01-01") == []
        assert len(repo.cost_summary(group_by="skill", since="2000-01-01")) == 1


def test_existing_db_without_cost_columns_migrates_cleanly(tmp_path):
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, run_uuid TEXT NOT NULL UNIQUE, "
        "project_id INTEGER NOT NULL, skill_id TEXT NOT NULL, skill_name TEXT NOT NULL, agent_id TEXT NOT NULL, "
        "confluence_urls TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL, exit_code INTEGER, "
        "started_at TEXT NOT NULL, finished_at TEXT, duration_seconds REAL, report_path TEXT, "
        "prompt_path TEXT, stderr_excerpt TEXT)"
    )
    conn.commit()
    conn.close()

    repo = RunRepository(db_path=db_path)
    columns = {row["name"] for row in repo._conn.execute("PRAGMA table_info(runs)").fetchall()}
    repo.close()
    assert {"input_tokens", "output_tokens", "cost_usd"} <= columns


def test_cost_command_shows_totals_and_unpriced_note(db):
    _seed(agent_id="api", cost=0.25, tokens=(1000, 200))
    _seed(agent_id="agent")

    result = runner.invoke(app, ["cost"])

    assert result.exit_code == 0
    assert "api" in result.stdout
    assert "$0.25" in result.stdout
    assert "1 run(s) have no cost recorded" in result.stdout


def test_cost_command_rejects_bad_since_date(db):
    result = runner.invoke(app, ["cost", "--since", "last week"])
    assert result.exit_code != 0


def test_cost_command_empty_store(db):
    result = runner.invoke(app, ["cost", "--by", "project"])
    assert result.exit_code == 0
    assert "No runs found" in result.stdout


def test_run_command_prints_cost_per_skill_and_total(monkeypatch):
    outcomes = [
        RunOutcome(
            run_uuid=f"u{i}",
            skill_id="sast",
            skill_name=f"Skill {i}",
            agent_id="api",
            status="success",
            exit_code=0,
            duration_seconds=1.0,
            report_path=None,
            cost_usd=cost,
        )
        for i, cost in enumerate([0.5, 1.25])
    ]
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kwargs: outcomes)

    result = runner.invoke(app, ["run", "--skill", "sast", "--agent", "api"])

    assert result.exit_code == 0
    assert "$1.25" in result.stdout
    assert "AI spend for this run: $1.75" in result.stdout


def test_dashboard_shows_run_cost_and_overview_spend(db):
    run_uuid = _seed(agent_id="api", cost=0.25, tokens=(1000, 200))
    client = TestClient(create_app())

    run_page = client.get(f"/runs/{run_uuid}")
    assert run_page.status_code == 200
    assert "AI cost" in run_page.text
    assert "$0.25" in run_page.text
    assert "1,000 / 200" in run_page.text

    overview = client.get("/")
    assert overview.status_code == 200
    assert "AI spend by agent" in overview.text
    assert "$0.25" in overview.text


def test_overview_spend_is_unknown_not_zero_when_no_run_has_a_cost(db):
    _seed(agent_id="agent")
    overview = TestClient(create_app()).get("/")
    assert "$0.00" not in overview.text
    assert "AI spend" in overview.text


def test_create_completed_run_keeps_usage_for_portal_ingestion(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project("id-1", "P1", "local")
    repo.create_completed_run(
        run_uuid="remote-1", project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="api",
        confluence_urls=[], status="success", exit_code=0, started_at="2026-09-21T00:00:00+00:00",
        finished_at=None, duration_seconds=1.0, report_path=None,
        input_tokens=1000, output_tokens=200, cost_usd=0.25,
    )
    run = repo.get_run("remote-1")
    repo.close()
    assert (run.input_tokens, run.output_tokens, run.cost_usd) == (1000, 200, 0.25)


def test_cost_command_filters_by_project(db):
    _seed(agent_id="api", project="acme/checkout", cost=0.25)
    _seed(agent_id="api", project="acme/billing", cost=5.0)

    result = runner.invoke(app, ["cost", "--project", "checkout"])

    assert result.exit_code == 0
    assert "$0.25" in result.stdout
    assert "$5.00" not in result.stdout


def test_cost_command_rejects_ambiguous_or_unknown_project(db):
    _seed(agent_id="api", project="acme/checkout", cost=0.25)
    _seed(agent_id="api", project="acme/billing", cost=5.0)

    assert runner.invoke(app, ["cost", "--project", "acme"]).exit_code == 1
    unknown = runner.invoke(app, ["cost", "--project", "nope"])
    assert "No project matches" in unknown.stdout
