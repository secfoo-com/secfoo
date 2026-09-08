from __future__ import annotations

from secfoo.storage.repository import RunRepository


def _repo(tmp_path):
    return RunRepository(db_path=tmp_path / "secfoo.db")


def test_upsert_project_is_idempotent(tmp_path):
    repo = _repo(tmp_path)
    id1 = repo.upsert_project("id-1", "Project One", "local")
    id2 = repo.upsert_project("id-1", "Project One", "local")
    assert id1 == id2
    assert len(repo.list_projects()) == 1
    repo.close()


def test_rename_project_overrides_display_name(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "auto-derived-name", "local")
    repo.rename_project(project_id, "Custom Friendly Name")
    assert repo.get_project(project_id).display_name == "Custom Friendly Name"
    repo.close()


def test_rename_then_upsert_again_does_not_revert_the_name(tmp_path):
    """A later plain run against the same target must not silently blow
    away a custom name set via the New Assessment form -- upsert_project's
    conflict branch never touches display_name.
    """
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "auto-derived-name", "local")
    repo.rename_project(project_id, "Custom Friendly Name")
    repo.upsert_project("id-1", "auto-derived-name", "local")
    assert repo.get_project(project_id).display_name == "Custom Friendly Name"
    repo.close()


def test_create_and_complete_run_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "Project One", "local")
    run_uuid = repo.create_run(
        project_id=project_id,
        skill_id="security-architecture-review",
        skill_name="Security Architecture Review",
        agent_id="claude",
        confluence_urls=["https://example.atlassian.net/wiki/x"],
    )

    run = repo.get_run(run_uuid)
    assert run is not None
    assert run.status == "running"
    assert run.confluence_urls == ["https://example.atlassian.net/wiki/x"]
    assert run.finished_at is None

    repo.complete_run(
        run_uuid,
        status="success",
        exit_code=0,
        duration_seconds=1.5,
        report_path="/tmp/r.md",
        prompt_path="/tmp/p.md",
        stderr_excerpt=None,
    )

    run = repo.get_run(run_uuid)
    assert run.status == "success"
    assert run.exit_code == 0
    assert run.report_path == "/tmp/r.md"
    assert run.finished_at is not None
    repo.close()


def test_get_run_missing_returns_none(tmp_path):
    repo = _repo(tmp_path)
    assert repo.get_run("does-not-exist") is None
    repo.close()


def test_list_runs_filters_by_project_and_status(tmp_path):
    repo = _repo(tmp_path)
    p1 = repo.upsert_project("id-1", "P1", "local")
    p2 = repo.upsert_project("id-2", "P2", "github")

    r1 = repo.create_run(project_id=p1, skill_id="s", skill_name="S", agent_id="a", confluence_urls=[])
    repo.complete_run(r1, status="success", exit_code=0, duration_seconds=1, report_path=None, prompt_path=None, stderr_excerpt=None)

    r2 = repo.create_run(project_id=p2, skill_id="s", skill_name="S", agent_id="a", confluence_urls=[])
    repo.complete_run(r2, status="failed", exit_code=1, duration_seconds=1, report_path=None, prompt_path=None, stderr_excerpt="boom")

    assert len(repo.list_runs()) == 2

    p1_runs = repo.list_runs(project_id=p1)
    assert [r.run_uuid for r in p1_runs] == [r1]

    failed_runs = repo.list_runs(status="failed")
    assert [r.run_uuid for r in failed_runs] == [r2]
    repo.close()


def test_list_projects_ordered_by_last_run_desc(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_project("id-1", "P1", "local")
    repo.upsert_project("id-2", "P2", "local")
    repo.upsert_project("id-1", "P1", "local")  # bump P1's last_run_at
    projects = repo.list_projects()
    assert projects[0].identifier == "id-1"
    repo.close()


def test_create_assessment_auto_generates_a_uuid(tmp_path):
    """The local autoincrement id only means something within this one
    SQLite file -- cloud sync needs a stable identity to correlate the
    same assessment across a push to a shared portal tenant DB.
    """
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal")
    assessment = repo.get_assessment(assessment_id)
    assert assessment.assessment_uuid is not None
    assert len(assessment.assessment_uuid) == 36  # well-formed UUID string
    repo.close()


def test_create_assessment_accepts_an_explicit_uuid(tmp_path):
    """The portal's ingest handler creates an assessment with a uuid it
    already received from the CLI, rather than minting a fresh one.
    """
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(
        project_id=project_id, assessment_type="internal", assessment_uuid="fixed-uuid-value"
    )
    assert repo.get_assessment(assessment_id).assessment_uuid == "fixed-uuid-value"
    repo.close()


def test_get_assessment_by_uuid_finds_it(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(
        project_id=project_id, assessment_type="internal", assessment_uuid="find-me"
    )
    found = repo.get_assessment_by_uuid("find-me")
    assert found is not None
    assert found.id == assessment_id
    assert repo.get_assessment_by_uuid("does-not-exist") is None
    repo.close()


def test_create_completed_run_attaches_to_an_assessment(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal")
    repo.create_completed_run(
        run_uuid="r1",
        project_id=project_id,
        skill_id="sast",
        skill_name="SAST",
        agent_id="claude",
        confluence_urls=[],
        status="success",
        exit_code=0,
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        duration_seconds=60.0,
        report_path=None,
        assessment_id=assessment_id,
    )
    assert repo.get_run("r1").assessment_id == assessment_id
    repo.close()


def test_existing_db_without_assessment_uuid_column_migrates_cleanly(tmp_path):
    """Simulates a pre-existing ~/.secfoo/secfoo.db (or live tenant DB)
    created before this column existed -- opening it with the new code
    must add the column instead of crashing, per the established
    _RUNS_MIGRATIONS pattern this mirrors.
    """
    import sqlite3

    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE assessments (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL, "
        "assessment_type TEXT NOT NULL, status TEXT NOT NULL, application_id TEXT, sar_number TEXT, "
        "reviewer TEXT, review_date TEXT, notes TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, identifier TEXT NOT NULL UNIQUE, "
        "display_name TEXT NOT NULL, kind TEXT NOT NULL, first_seen_at TEXT NOT NULL, last_run_at TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()

    repo = RunRepository(db_path=db_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal")
    assert repo.get_assessment(assessment_id).assessment_uuid is not None
    repo.close()
