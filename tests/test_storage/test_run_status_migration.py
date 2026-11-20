"""runs.status must accept every status an adapter can return (agents.base.Status)."""
from __future__ import annotations

import sqlite3
import threading
import typing

import pytest

from secfoo.agents.api import KEY_VARS, ApiAdapter
from secfoo.agents.base import Status
from secfoo.runner import execute_runs
from secfoo.storage.repository import RunRepository

# The runs table as created before 'not_configured' existed, plus a column a
# later _RUNS_MIGRATIONS entry appended (so column order differs from schema.sql).
_OLD_RUNS = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT, identifier TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('local','github')), first_seen_at TEXT NOT NULL, last_run_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uuid          TEXT NOT NULL UNIQUE,
    project_id        INTEGER NOT NULL REFERENCES projects(id),
    skill_id          TEXT NOT NULL,
    skill_name        TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    confluence_urls   TEXT NOT NULL DEFAULT '[]',
    status            TEXT NOT NULL CHECK (status IN
                          ('pending','running','success','failed','timeout','binary_not_found')),
    exit_code         INTEGER,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    duration_seconds  REAL,
    report_path       TEXT,
    prompt_path       TEXT,
    stderr_excerpt    TEXT
);
ALTER TABLE runs ADD COLUMN cost_usd REAL;
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    title TEXT NOT NULL
);
"""


def _old_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(_OLD_RUNS)
    conn.execute("INSERT INTO projects (identifier, display_name, kind, first_seen_at, last_run_at) "
                 "VALUES ('/p', 'p', 'local', 't', 't')")
    conn.execute("INSERT INTO runs (run_uuid, project_id, skill_id, skill_name, agent_id, status, started_at, cost_usd) "
                 "VALUES ('old-run', 1, 'sast', 'SAST', 'claude', 'success', 't', 0.25)")
    conn.execute("INSERT INTO findings (run_id, title) VALUES (1, 'kept')")
    conn.commit()
    conn.close()


def _runs_sql(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT sql FROM sqlite_master WHERE name = 'runs'").fetchone()[0]
    finally:
        conn.close()


def test_every_adapter_status_is_allowed_by_a_fresh_schema(tmp_path):
    with RunRepository(db_path=tmp_path / "secfoo.db") as repo:
        project = repo.upsert_project("/p", "p", "local")
        for status in typing.get_args(Status):
            run_uuid = repo.create_run(project_id=project, skill_id="sast", skill_name="SAST",
                                       agent_id="api", confluence_urls=[])
            repo.complete_run(run_uuid, status=status, exit_code=None, duration_seconds=0.0,
                              report_path=None, prompt_path=None, stderr_excerpt=None)
            assert repo.get_run(run_uuid).status == status


def test_api_agent_without_a_key_is_saved_as_not_configured(tmp_path, monkeypatch):
    """Was an IntegrityError traceback: the first thing a user without an agent CLI sees."""
    for var in KEY_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("secfoo.runner.run_dir", lambda run_uuid: tmp_path / "reports" / run_uuid)
    monkeypatch.setattr("secfoo.runner.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: ApiAdapter())
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('hi')\n")
    with RunRepository(db_path=tmp_path / "secfoo.db") as repo:
        [outcome] = execute_runs(skill_ids=["sast"], target=str(target), confluence_urls=[], agent_id="api", repo=repo)
        run = repo.get_run(outcome.run_uuid)
    assert outcome.status == "not_configured"
    assert run.status == "not_configured"
    assert "No API key set" in (run.stderr_excerpt or "")


def test_migration_widens_runs_status_check_and_keeps_rows_and_references(tmp_path):
    db = tmp_path / "old.db"
    _old_db(db)
    with RunRepository(db_path=db) as repo:
        old = repo.get_run("old-run")
        assert old.status == "success" and old.cost_usd == 0.25
        new = repo.create_run(project_id=1, skill_id="sast", skill_name="SAST", agent_id="api",
                              confluence_urls=[])
        repo.complete_run(new, status="not_configured", exit_code=None, duration_seconds=0.0,
                          report_path=None, prompt_path=None, stderr_excerpt=None)
        assert repo.get_run(new).status == "not_configured"
        conn = repo._conn
        assert conn.execute("SELECT title FROM findings WHERE run_id = 1").fetchone()[0] == "kept"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='runs'")}
        assert "idx_runs_project_id" in indexes
        with pytest.raises(sqlite3.IntegrityError):  # the CHECK itself survived, only widened
            conn.execute("UPDATE runs SET status = 'bogus' WHERE run_uuid = ?", (new,))
        with pytest.raises(sqlite3.IntegrityError):  # and foreign keys still bind to the rebuilt table
            conn.execute("DELETE FROM runs WHERE id = 1")
    assert "runs_new" not in _runs_sql(db) and "'not_configured'" in _runs_sql(db)


def test_runs_status_migration_is_idempotent_and_safe_under_concurrent_opens(tmp_path):
    """Skills run in parallel threads with their own connections, so the first
    run after an upgrade opens an old database several times at once."""
    db = tmp_path / "old.db"
    _old_db(db)
    errors = []

    def open_repo():
        try:
            RunRepository(db_path=db).close()
        except Exception as exc:  # noqa: BLE001 -- surfaced by the assert below
            errors.append(exc)

    threads = [threading.Thread(target=open_repo) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    sql = _runs_sql(db)
    assert sql.count("'not_configured'") == 1
    RunRepository(db_path=db).close()
    assert _runs_sql(db) == sql


def test_runs_without_any_status_check_are_left_alone(tmp_path):
    """The oldest databases had no CHECK on status at all; nothing to widen."""
    db = tmp_path / "oldest.db"
    conn = sqlite3.connect(db)
    conn.executescript(_OLD_RUNS.replace(
        "CHECK (status IN\n                          ('pending','running','success','failed','timeout','binary_not_found'))", ""))
    conn.close()
    RunRepository(db_path=db).close()
    assert "CHECK (status" not in _runs_sql(db)
