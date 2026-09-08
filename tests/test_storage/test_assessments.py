from __future__ import annotations

import sqlite3

from secfoo.storage.repository import RunRepository


def _repo(tmp_path):
    return RunRepository(db_path=tmp_path / "secfoo.db")


def test_migration_adds_new_run_columns_to_pre_existing_db(tmp_path):
    """Simulates a real user's pre-upgrade ~/.secfoo/secfoo.db: only the
    original runs/projects tables exist, no assessments table, no new
    columns. RunRepository must add them without touching existing data.
    """
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_run_at TEXT NOT NULL
        );
        CREATE TABLE runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_uuid TEXT NOT NULL UNIQUE,
            project_id INTEGER NOT NULL,
            skill_id TEXT NOT NULL,
            skill_name TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            confluence_urls TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL,
            exit_code INTEGER,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            duration_seconds REAL,
            report_path TEXT,
            prompt_path TEXT,
            stderr_excerpt TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO projects (identifier, display_name, kind, first_seen_at, last_run_at) "
        "VALUES ('id-1', 'P1', 'local', 't', 't')"
    )
    conn.execute(
        "INSERT INTO runs (run_uuid, project_id, skill_id, skill_name, agent_id, status, started_at) "
        "VALUES ('u1', 1, 'threat-assessment', 'Security Architecture Review', 'claude', 'success', 't')"
    )
    conn.commit()
    conn.close()

    repo = RunRepository(db_path=db_path)
    run = repo.get_run("u1")
    assert run is not None
    assert run.assessment_id is None
    assert run.high_count == 0
    assert run.cloud_synced_at is None
    project = repo.get_project(1)
    assert project.display_name == "P1"
    repo.close()


def test_migration_widens_attachment_kind_check_for_vendor_doc(tmp_path):
    """Simulates a real pre-upgrade DB where assessment_attachments exists
    but its CHECK constraint predates 'vendor_doc' -- SQLite has no ALTER
    TABLE for a CHECK constraint, so RunRepository must rebuild the table
    (see _migrate_attachment_kind_check), preserving existing rows and
    allowing 'vendor_doc' inserts afterward.
    """
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_run_at TEXT NOT NULL
        );
        CREATE TABLE runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_uuid TEXT NOT NULL UNIQUE,
            project_id INTEGER NOT NULL,
            skill_id TEXT NOT NULL,
            skill_name TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            confluence_urls TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL,
            exit_code INTEGER,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            duration_seconds REAL,
            report_path TEXT,
            prompt_path TEXT,
            stderr_excerpt TEXT
        );
        CREATE TABLE assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            assessment_type TEXT NOT NULL,
            status TEXT NOT NULL,
            application_id TEXT,
            sar_number TEXT,
            reviewer TEXT,
            review_date TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE assessment_attachments (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id    INTEGER NOT NULL REFERENCES assessments(id),
            file_path        TEXT NOT NULL,
            original_name    TEXT NOT NULL,
            attachment_kind  TEXT NOT NULL CHECK (attachment_kind IN ('ai_bom','report','other')),
            uploaded_at      TEXT NOT NULL
        );
        """
    )
    conn.execute(
        "INSERT INTO projects (identifier, display_name, kind, first_seen_at, last_run_at) "
        "VALUES ('id-1', 'P1', 'local', 't', 't')"
    )
    conn.execute(
        "INSERT INTO assessments (project_id, assessment_type, status, created_at, updated_at) "
        "VALUES (1, 'third_party', 'ready', 't', 't')"
    )
    conn.execute(
        "INSERT INTO assessment_attachments (assessment_id, file_path, original_name, attachment_kind, uploaded_at) "
        "VALUES (1, '/tmp/x.pdf', 'x.pdf', 'other', 't')"
    )
    conn.commit()
    conn.close()

    repo = RunRepository(db_path=db_path)
    # The pre-existing row survived the table rebuild.
    attachments = repo.list_attachments(1)
    assert len(attachments) == 1
    assert attachments[0].original_name == "x.pdf"

    # 'vendor_doc' -- unavailable under the old CHECK constraint -- now inserts cleanly.
    new_id = repo.add_attachment(
        assessment_id=1, file_path="/tmp/vendor.pdf", original_name="vendor.pdf", attachment_kind="vendor_doc"
    )
    assert new_id is not None
    assert len(repo.list_attachments(1)) == 2
    repo.close()


def test_migration_attachment_kind_check_is_a_no_op_on_a_fresh_db(tmp_path):
    """A brand-new DB already has the widened constraint from schema.sql
    -- the migration must detect that and do nothing, not attempt to
    rebuild a table it just created.
    """
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="third_party", status="ready")
    attachment_id = repo.add_attachment(
        assessment_id=assessment_id, file_path="/tmp/vendor.pdf", original_name="vendor.pdf",
        attachment_kind="vendor_doc",
    )
    assert attachment_id is not None
    repo.close()


# ---------------------------------------------------------------------------
# Cloud sync (secfoo cloud) and multi-tenant db_path resolution
# ---------------------------------------------------------------------------


def test_mark_run_synced_sets_timestamp(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )
    assert repo.get_run(run_uuid).cloud_synced_at is None

    repo.mark_run_synced(run_uuid)
    assert repo.get_run(run_uuid).cloud_synced_at is not None
    repo.close()


def test_list_unsynced_runs_only_returns_successful_unsynced(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")

    synced_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        synced_uuid, status="success", exit_code=0, duration_seconds=1, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )
    repo.mark_run_synced(synced_uuid)

    unsynced_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        unsynced_uuid, status="success", exit_code=0, duration_seconds=1, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )

    failed_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        failed_uuid, status="failed", exit_code=1, duration_seconds=1, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )

    unsynced = repo.list_unsynced_runs()
    assert [r.run_uuid for r in unsynced] == [unsynced_uuid]
    repo.close()


def test_use_db_path_scopes_default_repository_construction(tmp_path):
    """The multi-tenant portal sets this once per request so every route's
    bare `RunRepository()` (no explicit db_path) resolves to that tenant's
    file -- proves the resolution actually works and cleans up afterward.
    """
    from secfoo.storage.repository import use_db_path

    tenant_a_path = tmp_path / "tenant-a.db"
    tenant_b_path = tmp_path / "tenant-b.db"

    with use_db_path(tenant_a_path):
        repo_a = RunRepository()
        assert repo_a.db_path == tenant_a_path
        repo_a.close()

    with use_db_path(tenant_b_path):
        repo_b = RunRepository()
        assert repo_b.db_path == tenant_b_path
        repo_b.close()

    # Outside any use_db_path() block, falls back to the process default.
    repo_default = RunRepository(db_path=tmp_path / "default.db")
    assert repo_default.db_path == tmp_path / "default.db"
    repo_default.close()


def test_create_and_get_assessment_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(
        project_id=project_id,
        assessment_type="internal",
        status="ready",
        application_id="APP-001",
        sar_number="SAR-2026-001",
        reviewer="Alex",
        review_date="2026-08-01",
        notes="first pass",
    )
    assessment = repo.get_assessment(assessment_id)
    assert assessment is not None
    assert assessment.application_id == "APP-001"
    assert assessment.sar_number == "SAR-2026-001"
    assert assessment.project_display_name == "P1"
    assert assessment.critical_count == 0
    repo.close()


def test_update_assessment_partial_fields(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    repo.update_assessment(assessment_id, status="completed", reviewer="Sam")
    assessment = repo.get_assessment(assessment_id)
    assert assessment.status == "completed"
    assert assessment.reviewer == "Sam"
    repo.close()


def test_update_assessment_rejects_unknown_field(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    try:
        repo.update_assessment(assessment_id, nonsense="x")
        assert False, "expected ValueError"
    except ValueError:
        pass
    repo.close()


def test_list_assessments_filters_by_type_status_search(tmp_path):
    repo = _repo(tmp_path)
    p1 = repo.upsert_project("id-1", "Acme App", "local")
    p2 = repo.upsert_project("id-2", "Vendor App", "github")
    a1 = repo.create_assessment(project_id=p1, assessment_type="internal", status="ready")
    a2 = repo.create_assessment(project_id=p2, assessment_type="third_party", status="completed")

    assert {a.id for a in repo.list_assessments()} == {a1, a2}
    assert [a.id for a in repo.list_assessments(assessment_type="third_party")] == [a2]
    assert [a.id for a in repo.list_assessments(status="completed")] == [a2]
    assert [a.id for a in repo.list_assessments(search="Acme")] == [a1]
    repo.close()


def test_delete_assessment_cascades_and_detaches_runs(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id,
        skill_id="security-architecture-review",
        skill_name="Security Architecture Review",
        agent_id="claude",
        confluence_urls=[],
        assessment_id=assessment_id,
    )

    attachment_file = tmp_path / "ai-bom.json"
    attachment_file.write_text("{}")
    attachment_id = repo.add_attachment(
        assessment_id=assessment_id,
        file_path=str(attachment_file),
        original_name="ai-bom.json",
        attachment_kind="ai_bom",
    )
    repo.add_ai_bom_items(attachment_id, [{"kind": "model", "name": "gemini"}])

    repo.delete_assessment(assessment_id)

    assert repo.get_assessment(assessment_id) is None
    assert repo.list_attachments(assessment_id) == []
    assert not attachment_file.exists()
    run = repo.get_run(run_uuid)
    assert run.assessment_id is None
    repo.close()


def test_severity_totals_sum_across_runs(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    r1 = repo.create_run(project_id=project_id, skill_id="s", skill_name="S", agent_id="a", confluence_urls=[])
    repo.complete_run(
        r1, status="success", exit_code=0, duration_seconds=1, report_path=None, prompt_path=None,
        stderr_excerpt=None, high_count=2, medium_count=1,
    )
    r2 = repo.create_run(project_id=project_id, skill_id="s", skill_name="S", agent_id="a", confluence_urls=[])
    repo.complete_run(
        r2, status="success", exit_code=0, duration_seconds=1, report_path=None, prompt_path=None,
        stderr_excerpt=None, high_count=1, low_count=3,
    )
    totals = repo.severity_totals()
    assert totals.high == 3
    assert totals.medium == 1
    assert totals.low == 3
    assert totals.total == 7
    repo.close()


def test_assessment_severity_totals_only_counts_attached_runs(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    a1 = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    a2 = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")

    r1 = repo.create_run(
        project_id=project_id, skill_id="s", skill_name="S", agent_id="a", confluence_urls=[], assessment_id=a1
    )
    repo.complete_run(
        r1, status="success", exit_code=0, duration_seconds=1, report_path=None, prompt_path=None,
        stderr_excerpt=None, high_count=5,
    )
    r2 = repo.create_run(
        project_id=project_id, skill_id="s", skill_name="S", agent_id="a", confluence_urls=[], assessment_id=a2
    )
    repo.complete_run(
        r2, status="success", exit_code=0, duration_seconds=1, report_path=None, prompt_path=None,
        stderr_excerpt=None, high_count=9,
    )

    assert repo.assessment_severity_totals(a1).high == 5
    assert repo.assessment_severity_totals(a2).high == 9
    repo.close()


def test_responsible_ai_risk_derived_from_attached_run_report(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="responsible-ai-compliance", skill_name="Responsible AI Compliance",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    report_path = tmp_path / "report.md"
    report_path.write_text("# Report\n\n## Summary\n**Overall risk rating:** High.\n")
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )

    assessment = repo.get_assessment(assessment_id)
    assert assessment.responsible_ai_risk == "high-risk"
    assert assessment.responsible_ai_status == "provisional"

    repo.update_assessment(assessment_id, status="completed")
    assessment = repo.get_assessment(assessment_id)
    assert assessment.responsible_ai_status == "confirmed"
    repo.close()


def test_skill_coverage_counts_distinct_projects_per_skill(tmp_path):
    repo = _repo(tmp_path)
    p1 = repo.upsert_project("id-1", "P1", "local")
    p2 = repo.upsert_project("id-2", "P2", "local")

    # Two runs against the same project count once; a second project counts
    # separately.
    for project_id in (p1, p1, p2):
        run_uuid = repo.create_run(
            project_id=project_id, skill_id="security-architecture-review", skill_name="Security Architecture Review",
            agent_id="claude", confluence_urls=[],
        )
        repo.complete_run(
            run_uuid, status="success", exit_code=0, duration_seconds=1, report_path=None,
            prompt_path=None, stderr_excerpt=None,
        )

    assert repo.skill_coverage()["security-architecture-review"] == 2
    repo.close()


def test_skill_coverage_counts_runs_with_no_assessment_attached(tmp_path):
    """Assessments are an optional wrapper -- a plain `secfoo run` still
    counts as coverage. Counting only assessment-attached runs made the
    dashboard report 0% for activities that had genuinely been run.
    """
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST",
        agent_id="claude", confluence_urls=[],  # no assessment_id
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )

    assert repo.skill_coverage()["sast"] == 1
    repo.close()


def test_skill_coverage_ignores_unsuccessful_runs(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    for status in ("failed", "timeout", "binary_not_found"):
        run_uuid = repo.create_run(
            project_id=project_id, skill_id="sast", skill_name="SAST",
            agent_id="claude", confluence_urls=[],
        )
        repo.complete_run(
            run_uuid, status=status, exit_code=1, duration_seconds=1, report_path=None,
            prompt_path=None, stderr_excerpt=None,
        )

    assert repo.skill_coverage().get("sast", 0) == 0
    repo.close()


def test_ai_bom_counts_aggregate_across_attachments(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    attachment_file = tmp_path / "ai-bom.json"
    attachment_file.write_text("{}")
    attachment_id = repo.add_attachment(
        assessment_id=assessment_id, file_path=str(attachment_file), original_name="ai-bom.json",
        attachment_kind="ai_bom",
    )
    repo.add_ai_bom_items(
        attachment_id,
        [
            {"kind": "model", "name": "gemini"},
            {"kind": "model", "name": "claude"},
            {"kind": "tool", "name": "langchain"},
        ],
    )
    models, tools = repo.ai_bom_counts(assessment_id)
    assert models == 2
    assert tools == 1
    assert repo.ai_bom_counts_total() == (2, 1)
    repo.close()


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


def test_create_and_get_exception_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    exception_id = repo.create_exception(
        project_id=project_id, title="Legacy auth exemption", justification="migration in progress",
        granted_by="Jane Doe", expires_at="2099-01-01", standard_or_control="IAM",
    )
    exception = repo.get_exception(exception_id)
    assert exception is not None
    assert exception.title == "Legacy auth exemption"
    assert exception.status == "active"
    assert exception.project_display_name == "P1"
    repo.close()


def test_update_exception_partial_fields(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    exception_id = repo.create_exception(
        project_id=project_id, title="x", justification="y", granted_by="z", expires_at="2099-01-01",
    )
    repo.update_exception(exception_id, status="revoked")
    assert repo.get_exception(exception_id).status == "revoked"
    repo.close()


def test_update_exception_rejects_unknown_field(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    exception_id = repo.create_exception(
        project_id=project_id, title="x", justification="y", granted_by="z", expires_at="2099-01-01",
    )
    try:
        repo.update_exception(exception_id, nonsense="x")
        assert False, "expected ValueError"
    except ValueError:
        pass
    repo.close()


def test_list_exceptions_filters_by_status(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    active_id = repo.create_exception(
        project_id=project_id, title="active one", justification="j", granted_by="g", expires_at="2099-01-01",
    )
    revoked_id = repo.create_exception(
        project_id=project_id, title="revoked one", justification="j", granted_by="g", expires_at="2099-01-01",
    )
    repo.update_exception(revoked_id, status="revoked")

    assert [e.id for e in repo.list_exceptions(status="active")] == [active_id]
    assert [e.id for e in repo.list_exceptions(status="revoked")] == [revoked_id]
    assert {e.id for e in repo.list_exceptions()} == {active_id, revoked_id}
    repo.close()


def test_delete_exception(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    exception_id = repo.create_exception(
        project_id=project_id, title="x", justification="y", granted_by="z", expires_at="2099-01-01",
    )
    repo.delete_exception(exception_id)
    assert repo.get_exception(exception_id) is None
    repo.close()


def test_exceptions_past_expiry_count(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    repo.create_exception(
        project_id=project_id, title="expired", justification="j", granted_by="g", expires_at="2020-01-01",
    )
    repo.create_exception(
        project_id=project_id, title="future", justification="j", granted_by="g", expires_at="2099-01-01",
    )
    assert repo.exceptions_past_expiry_count() == 1
    repo.close()


def test_exceptions_past_expiry_count_ignores_revoked(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    exception_id = repo.create_exception(
        project_id=project_id, title="expired but revoked", justification="j", granted_by="g",
        expires_at="2020-01-01",
    )
    repo.update_exception(exception_id, status="revoked")
    assert repo.exceptions_past_expiry_count() == 0
    repo.close()


def test_exceptions_aging_buckets(tmp_path):
    import datetime as dt

    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    now = dt.datetime.now(dt.timezone.utc)

    def _at(days: int) -> str:
        return (now + dt.timedelta(days=days)).isoformat()

    repo.create_exception(project_id=project_id, title="past", justification="j", granted_by="g", expires_at=_at(-5))
    repo.create_exception(project_id=project_id, title="due15", justification="j", granted_by="g", expires_at=_at(15))
    repo.create_exception(project_id=project_id, title="due45", justification="j", granted_by="g", expires_at=_at(45))
    repo.create_exception(project_id=project_id, title="due75", justification="j", granted_by="g", expires_at=_at(75))
    repo.create_exception(project_id=project_id, title="due200", justification="j", granted_by="g", expires_at=_at(200))

    buckets = repo.exceptions_aging_buckets()
    assert buckets == {"past_expiry": 1, "due_0_30": 1, "due_31_60": 1, "due_61_90": 1}
    repo.close()


# ---------------------------------------------------------------------------
# Cross-project dashboard queries
# ---------------------------------------------------------------------------


def test_assessment_cycle_times_days_only_counts_completed(tmp_path):
    import datetime as dt

    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")

    created = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5)
    aid = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    repo._conn.execute("UPDATE assessments SET created_at = ? WHERE id = ?", (created.isoformat(), aid))
    repo._conn.commit()
    repo.update_assessment(aid, status="completed")

    # A still-open assessment must not count.
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="in_progress")

    durations = repo.assessment_cycle_times_days()
    assert len(durations) == 1
    assert durations[0] > 4.9
    repo.close()


def test_architecture_coverage_in_scope_requires_an_assessment(tmp_path):
    repo = _repo(tmp_path)
    reviewed_project = repo.upsert_project("id-1", "Reviewed", "local")
    unreviewed_project = repo.upsert_project("id-2", "Unreviewed", "local")
    no_assessment_project = repo.upsert_project("id-3", "NoAssessment", "local")

    repo.create_assessment(project_id=reviewed_project, assessment_type="internal", status="ready")
    repo.create_assessment(project_id=unreviewed_project, assessment_type="internal", status="ready")
    # no_assessment_project deliberately has no assessment -- out of scope.

    run_uuid = repo.create_run(
        project_id=reviewed_project, skill_id="security-architecture-review", skill_name="x",
        agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )

    reviewed, in_scope = repo.architecture_coverage("security-architecture-review")
    assert reviewed == 1
    assert in_scope == 2  # reviewed_project + unreviewed_project, not no_assessment_project
    repo.close()


def test_unreviewed_and_stale_projects_flags_never_reviewed(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "Never Reviewed", "local")
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")

    results = repo.unreviewed_and_stale_projects("security-architecture-review")
    assert len(results) == 1
    assert results[0]["state"] == "never_reviewed"
    assert results[0]["project_display_name"] == "Never Reviewed"
    repo.close()


def test_unreviewed_and_stale_projects_flags_old_reviews(tmp_path):
    import datetime as dt

    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "Stale App", "local")
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")

    run_uuid = repo.create_run(
        project_id=project_id, skill_id="security-architecture-review", skill_name="x",
        agent_id="claude", confluence_urls=[],
    )
    old_date = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=400)).isoformat()
    repo._conn.execute("UPDATE runs SET started_at = ? WHERE run_uuid = ?", (old_date, run_uuid))
    repo._conn.commit()
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )

    results = repo.unreviewed_and_stale_projects("security-architecture-review", stale_days=365)
    assert len(results) == 1
    assert results[0]["state"] == "stale"
    assert results[0]["days_since_review"] >= 399
    repo.close()


def test_unreviewed_and_stale_projects_excludes_recently_reviewed(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "Fresh App", "local")
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="security-architecture-review", skill_name="x",
        agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )
    assert repo.unreviewed_and_stale_projects("security-architecture-review", stale_days=365) == []
    repo.close()


# ---------------------------------------------------------------------------
# Post-build findings (threats a model missed)
# ---------------------------------------------------------------------------


def test_create_and_get_post_build_finding_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    finding_id = repo.create_post_build_finding(
        project_id=project_id, title="SSRF via webhook URL", discovered_at="2026-08-01",
        description="found in pen test", discovered_by="Pen test Q3",
    )
    finding = repo.get_post_build_finding(finding_id)
    assert finding is not None
    assert finding.title == "SSRF via webhook URL"
    assert finding.discovered_by == "Pen test Q3"
    assert finding.project_display_name == "P1"
    assert finding.run_id is None
    repo.close()


def test_create_post_build_finding_links_to_run(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="threat-modeling", skill_name="Threat Modeling",
        agent_id="claude", confluence_urls=[],
    )
    run = repo.get_run(run_uuid)
    finding_id = repo.create_post_build_finding(
        project_id=project_id, title="Missed threat", discovered_at="2026-08-01", run_id=run.id,
    )
    finding = repo.get_post_build_finding(finding_id)
    assert finding.run_id == run.id
    repo.close()


def test_list_post_build_findings_filters_by_project_and_orders_recent_first(tmp_path):
    repo = _repo(tmp_path)
    p1 = repo.upsert_project("id-1", "P1", "local")
    p2 = repo.upsert_project("id-2", "P2", "local")
    repo.create_post_build_finding(project_id=p1, title="older", discovered_at="2026-01-01")
    newer_id = repo.create_post_build_finding(project_id=p1, title="newer", discovered_at="2026-08-10")
    repo.create_post_build_finding(project_id=p2, title="other project", discovered_at="2026-08-01")

    all_findings = repo.list_post_build_findings()
    assert len(all_findings) == 3
    assert all_findings[0].id == newer_id  # most recent first

    p1_findings = repo.list_post_build_findings(project_id=p1)
    assert len(p1_findings) == 2
    repo.close()


def test_delete_post_build_finding(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    finding_id = repo.create_post_build_finding(project_id=project_id, title="x", discovered_at="2026-08-01")
    repo.delete_post_build_finding(finding_id)
    assert repo.get_post_build_finding(finding_id) is None
    repo.close()


def test_post_build_findings_count_total_and_since_days(tmp_path):
    import datetime as dt

    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    now = dt.datetime.now(dt.timezone.utc)
    repo.create_post_build_finding(
        project_id=project_id, title="recent", discovered_at=now.isoformat(),
    )
    repo.create_post_build_finding(
        project_id=project_id, title="old", discovered_at=(now - dt.timedelta(days=200)).isoformat(),
    )

    assert repo.post_build_findings_count() == 2
    assert repo.post_build_findings_count(since_days=90) == 1
    repo.close()


# ---------------------------------------------------------------------------
# Threat acceptances (the human loop-back on a threat's disposition)
# ---------------------------------------------------------------------------


def test_create_and_get_threat_acceptance_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    acceptance_id = repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T4", title="Risk accepted for legacy endpoint",
        justification="Endpoint is being decommissioned next quarter", accepted_by="Jane Doe",
        expires_at="2099-01-01",
    )
    acceptance = repo.get_threat_acceptance(acceptance_id)
    assert acceptance is not None
    assert acceptance.threat_ref == "T4"
    assert acceptance.accepted_by == "Jane Doe"
    assert acceptance.status == "active"
    assert acceptance.project_display_name == "P1"
    repo.close()


def test_create_threat_acceptance_links_to_run(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="threat-modeling", skill_name="Threat Modeling",
        agent_id="claude", confluence_urls=[],
    )
    run = repo.get_run(run_uuid)
    acceptance_id = repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T1", title="x", justification="y", accepted_by="z", run_id=run.id,
    )
    acceptance = repo.get_threat_acceptance(acceptance_id)
    assert acceptance.run_id == run.id
    repo.close()


def test_update_threat_acceptance_partial_fields(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    acceptance_id = repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T1", title="x", justification="y", accepted_by="z",
    )
    repo.update_threat_acceptance(acceptance_id, status="revoked")
    assert repo.get_threat_acceptance(acceptance_id).status == "revoked"
    repo.close()


def test_update_threat_acceptance_rejects_unknown_field(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    acceptance_id = repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T1", title="x", justification="y", accepted_by="z",
    )
    try:
        repo.update_threat_acceptance(acceptance_id, nonsense="x")
        assert False, "expected ValueError"
    except ValueError:
        pass
    repo.close()


def test_list_threat_acceptances_filters_by_status(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    active_id = repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T1", title="active one", justification="j", accepted_by="a",
    )
    revoked_id = repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T2", title="revoked one", justification="j", accepted_by="a",
    )
    repo.update_threat_acceptance(revoked_id, status="revoked")

    assert [a.id for a in repo.list_threat_acceptances(status="active")] == [active_id]
    assert [a.id for a in repo.list_threat_acceptances(status="revoked")] == [revoked_id]
    assert {a.id for a in repo.list_threat_acceptances()} == {active_id, revoked_id}
    repo.close()


def test_delete_threat_acceptance(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    acceptance_id = repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T1", title="x", justification="y", accepted_by="z",
    )
    repo.delete_threat_acceptance(acceptance_id)
    assert repo.get_threat_acceptance(acceptance_id) is None
    repo.close()


def test_list_runs_filters_by_skill_id(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    repo.create_run(project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[])
    repo.create_run(
        project_id=project_id, skill_id="security-architecture-review", skill_name="x",
        agent_id="claude", confluence_urls=[],
    )
    runs = repo.list_runs(skill_id="security-architecture-review")
    assert len(runs) == 1
    assert runs[0].skill_id == "security-architecture-review"
    repo.close()


# ---------------------------------------------------------------------------
# OSV.dev vulnerability lookup cache
# ---------------------------------------------------------------------------


def test_upsert_osv_lookup_and_read_back_via_map(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_osv_lookup(
        ecosystem="PyPI", package="aiohttp", version="3.8.0",
        vulns=[{"id": "CVE-2022-33124", "summary": "Invalid IPv6 URL DoS"}],
    )
    lookup_map = repo.osv_lookup_map()
    record = lookup_map[("PyPI", "aiohttp", "3.8.0")]
    assert record.vulns == [{"id": "CVE-2022-33124", "summary": "Invalid IPv6 URL DoS"}]
    assert record.queried_at
    repo.close()


def test_upsert_osv_lookup_caches_empty_result_as_clean_not_missing(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_osv_lookup(ecosystem="npm", package="left-pad", version="1.3.0", vulns=[])
    lookup_map = repo.osv_lookup_map()
    assert ("npm", "left-pad", "1.3.0") in lookup_map
    assert lookup_map[("npm", "left-pad", "1.3.0")].vulns == []
    repo.close()


def test_upsert_osv_lookup_refreshes_existing_entry(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_osv_lookup(ecosystem="PyPI", package="aiohttp", version="3.8.0", vulns=[])
    repo.upsert_osv_lookup(
        ecosystem="PyPI", package="aiohttp", version="3.8.0",
        vulns=[{"id": "CVE-2022-33124"}],
    )
    lookup_map = repo.osv_lookup_map()
    assert len(lookup_map) == 1  # updated in place, not duplicated
    assert lookup_map[("PyPI", "aiohttp", "3.8.0")].vulns == [{"id": "CVE-2022-33124"}]
    repo.close()


def test_osv_lookup_map_empty_when_nothing_cached(tmp_path):
    repo = _repo(tmp_path)
    assert repo.osv_lookup_map() == {}


# ---------------------------------------------------------------------------
# SAST findings (persistent per-finding open/closed lifecycle)
# ---------------------------------------------------------------------------


def _sast_run_id(repo, project_id: int) -> int:
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[]
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )
    return repo.get_run(run_uuid).id


def _upsert(repo, *, project_id, run_id, fingerprint="fp-1", **overrides):
    fields = {
        "current_ref": "F1",
        "title": "SQL Injection in query builder",
        "severity": "High",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "verdict": "Confirmed",
        "location_file": "app/db.py",
        "location_line": "42",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.4,
    }
    fields.update(overrides)
    repo.upsert_sast_finding(project_id=project_id, fingerprint=fingerprint, run_id=run_id, **fields)


def test_upsert_sast_finding_inserts_as_open_with_first_and_last_seen_set(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_id = _sast_run_id(repo, project_id)
    _upsert(repo, project_id=project_id, run_id=run_id)

    findings = repo.list_sast_findings(project_id=project_id)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == "open"
    assert finding.first_seen_run_id == run_id
    assert finding.last_seen_run_id == run_id
    assert finding.closed_in_run_id is None
    assert finding.cvss_score == 9.4
    repo.close()


def test_upsert_sast_finding_seen_again_updates_last_seen_not_first_seen(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_1 = _sast_run_id(repo, project_id)
    _upsert(repo, project_id=project_id, run_id=run_1)
    first_seen_at = repo.list_sast_findings(project_id=project_id)[0].first_seen_at

    run_2 = _sast_run_id(repo, project_id)
    _upsert(repo, project_id=project_id, run_id=run_2, current_ref="F3", severity="Medium")

    findings = repo.list_sast_findings(project_id=project_id)
    assert len(findings) == 1  # same fingerprint, updated in place -- not duplicated
    finding = findings[0]
    assert finding.first_seen_run_id == run_1
    assert finding.first_seen_at == first_seen_at
    assert finding.last_seen_run_id == run_2
    assert finding.current_ref == "F3"
    assert finding.severity == "Medium"
    repo.close()


def test_close_stale_sast_findings_closes_unseen_and_keeps_seen_open(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_1 = _sast_run_id(repo, project_id)
    _upsert(repo, project_id=project_id, run_id=run_1, fingerprint="fp-stays-open")
    _upsert(repo, project_id=project_id, run_id=run_1, fingerprint="fp-gets-fixed")

    run_2 = _sast_run_id(repo, project_id)
    _upsert(repo, project_id=project_id, run_id=run_2, fingerprint="fp-stays-open")
    repo.close_stale_sast_findings(
        project_id=project_id, run_id=run_2, seen_fingerprints=["fp-stays-open"], closed_at="2026-08-22T00:00:00Z"
    )

    open_findings = {f.fingerprint for f in repo.list_sast_findings(project_id=project_id, status="open")}
    closed_findings = {f.fingerprint for f in repo.list_sast_findings(project_id=project_id, status="closed")}
    assert open_findings == {"fp-stays-open"}
    assert closed_findings == {"fp-gets-fixed"}
    closed = repo.list_sast_findings(project_id=project_id, status="closed")[0]
    assert closed.closed_in_run_id == run_2
    assert closed.closed_at == "2026-08-22T00:00:00Z"
    repo.close()


def test_reopened_finding_restores_original_first_seen_and_clears_closed_fields(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_1 = _sast_run_id(repo, project_id)
    _upsert(repo, project_id=project_id, run_id=run_1, fingerprint="fp-1")
    first_seen_at = repo.list_sast_findings(project_id=project_id)[0].first_seen_at

    run_2 = _sast_run_id(repo, project_id)
    repo.close_stale_sast_findings(
        project_id=project_id, run_id=run_2, seen_fingerprints=[], closed_at="2026-08-22T00:00:00Z"
    )
    assert repo.list_sast_findings(project_id=project_id, status="closed")[0].fingerprint == "fp-1"

    run_3 = _sast_run_id(repo, project_id)
    _upsert(repo, project_id=project_id, run_id=run_3, fingerprint="fp-1")

    reopened = repo.list_sast_findings(project_id=project_id, status="open")[0]
    assert reopened.first_seen_run_id == run_1
    assert reopened.first_seen_at == first_seen_at
    assert reopened.closed_in_run_id is None
    assert reopened.closed_at is None
    repo.close()


def test_list_sast_findings_filters_by_status_and_search(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_id = _sast_run_id(repo, project_id)
    _upsert(repo, project_id=project_id, run_id=run_id, fingerprint="fp-sqli", title="SQL Injection", cwe="CWE-89")
    _upsert(repo, project_id=project_id, run_id=run_id, fingerprint="fp-xss", title="Reflected XSS", cwe="CWE-79")

    assert {f.fingerprint for f in repo.list_sast_findings(project_id=project_id, search="Injection")} == {"fp-sqli"}
    assert {f.fingerprint for f in repo.list_sast_findings(project_id=project_id, search="CWE-79")} == {"fp-xss"}
    assert len(repo.list_sast_findings(project_id=project_id, status="open")) == 2
    assert len(repo.list_sast_findings(project_id=project_id, status="closed")) == 0
    repo.close()


def test_list_sast_findings_scoped_by_project(tmp_path):
    repo = _repo(tmp_path)
    project_a = repo.upsert_project("id-a", "A", "local")
    project_b = repo.upsert_project("id-b", "B", "local")
    run_a = _sast_run_id(repo, project_a)
    run_b = _sast_run_id(repo, project_b)
    _upsert(repo, project_id=project_a, run_id=run_a, fingerprint="fp-1")
    _upsert(repo, project_id=project_b, run_id=run_b, fingerprint="fp-1")  # same fingerprint, different project

    assert len(repo.list_sast_findings(project_id=project_a)) == 1
    assert len(repo.list_sast_findings(project_id=project_b)) == 1
    assert len(repo.list_sast_findings()) == 2
    repo.close()
    repo.close()
