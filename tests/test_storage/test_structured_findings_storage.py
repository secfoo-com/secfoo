from __future__ import annotations

import sqlite3

from secfoo.storage.repository import RunRepository


def _project_and_run(repo: RunRepository) -> tuple[int, int]:
    project_id = repo.upsert_project(identifier="/tmp/x", display_name="x", kind="local")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sca-reachability", skill_name="SCA", agent_id="claude", confluence_urls=[]
    )
    return project_id, repo.get_run(run_uuid).id


def test_sca_finding_lifecycle_open_refresh_close(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _project_and_run(repo)

    repo.upsert_sca_finding(
        project_id=project_id, fingerprint="fp1", run_id=run_id, current_ref="D1", package="PyYAML",
        version="5.3", severity="High", ecosystem="PyPI", language="python", construct="unsafe yaml load",
    )
    repo.upsert_sca_finding(
        project_id=project_id, fingerprint="fp1", run_id=run_id, current_ref="D4", package="PyYAML",
        version="5.3.1", severity="High", ecosystem="PyPI", language="python", construct="unsafe yaml load",
    )
    open_rows = repo.list_sca_findings(status="open")
    assert len(open_rows) == 1
    assert open_rows[0].current_ref == "D4"
    assert open_rows[0].version == "5.3.1"
    assert open_rows[0].project_display_name == "x"

    repo.close_stale_findings(
        "sca-reachability", project_id=project_id, run_id=run_id, seen_fingerprints=[], closed_at="2026-10-09"
    )
    assert repo.list_sca_findings(status="open") == []
    closed = repo.list_sca_findings(status="closed")
    assert closed[0].closed_at == "2026-10-09"
    repo.close()


def test_secret_finding_reopens_and_keeps_first_seen(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _project_and_run(repo)
    kwargs = dict(
        project_id=project_id, fingerprint="s1", run_id=run_id, current_ref="S1", secret_type="API token",
        location_file="deploy/ci.yml", severity="High", evidence="TOKENJ4F...",
    )
    repo.upsert_secret_finding(**kwargs)
    first_seen = repo.list_secret_findings()[0].first_seen_at
    repo.close_stale_findings(
        "secret-scanning", project_id=project_id, run_id=run_id, seen_fingerprints=[], closed_at="t"
    )
    repo.upsert_secret_finding(**kwargs)

    row = repo.list_secret_findings()[0]
    assert row.status == "open"
    assert row.closed_at is None
    assert row.first_seen_at == first_seen
    repo.close()


def test_list_structured_findings_spans_every_table_and_filters(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _project_and_run(repo)
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint="a", current_ref="F1", title="SQLi", severity="High", cwe="CWE-89",
        owasp=None, verdict=None, location_file="app/db.py", location_line="4", cvss_vector=None,
        cvss_score=None, run_id=run_id, language="python", framework="django", construct="raw sql",
    )
    repo.upsert_sca_finding(
        project_id=project_id, fingerprint="b", run_id=run_id, current_ref="D1", package="p", severity="Low"
    )

    everything = repo.list_structured_findings()
    assert sorted(skill for skill, _row in everything) == ["sast", "sca-reachability"]
    sast_only = repo.list_structured_findings(skill_ids=["sast"])
    assert len(sast_only) == 1
    assert sast_only[0][1]["construct"] == "raw sql"
    assert sast_only[0][1]["framework"] == "django"
    assert repo.list_structured_findings(status="closed") == []
    repo.close()


def test_pre_existing_sast_table_gains_stack_columns(tmp_path):
    db_path = tmp_path / "db.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        "CREATE TABLE sast_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL, "
        "fingerprint TEXT NOT NULL, current_ref TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, "
        "cwe TEXT, owasp TEXT, verdict TEXT, location_file TEXT NOT NULL, location_line TEXT, "
        "cvss_vector TEXT, cvss_score REAL, description TEXT, recommendation TEXT, status TEXT NOT NULL, "
        "first_seen_run_id INTEGER NOT NULL, first_seen_at TEXT NOT NULL, last_seen_run_id INTEGER NOT NULL, "
        "last_seen_at TEXT NOT NULL, closed_in_run_id INTEGER, closed_at TEXT, UNIQUE (project_id, fingerprint));"
    )
    conn.close()

    repo = RunRepository(db_path=db_path)
    columns = {row["name"] for row in repo._conn.execute("PRAGMA table_info(sast_findings)")}
    run_columns = {row["name"] for row in repo._conn.execute("PRAGMA table_info(runs)")}
    repo.close()
    assert {"language", "framework", "construct", "code_region_hash"} <= columns
    assert "memory_enabled" in run_columns


def test_complete_run_records_memory_flag(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project(identifier="/tmp/x", display_name="x", kind="local")
    on = repo.create_run(project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[])
    off = repo.create_run(project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[])
    untouched = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[]
    )
    common = dict(status="success", exit_code=0, duration_seconds=1.0, report_path=None, prompt_path=None,
                  stderr_excerpt=None)
    repo.complete_run(on, memory_enabled=True, **common)
    repo.complete_run(off, memory_enabled=False, **common)
    repo.complete_run(untouched, **common)
    assert repo.get_run(on).memory_enabled == 1
    assert repo.get_run(off).memory_enabled == 0
    assert repo.get_run(untouched).memory_enabled is None
    repo.close()
