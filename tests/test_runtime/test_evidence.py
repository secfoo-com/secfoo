"""#53: runtime evidence format, storage and `secfoo runtime ingest`."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secfoo.cli import app
from secfoo.runtime import evidence
from secfoo.runtime.evidence import (
    EvidenceError,
    ingest_events,
    ingest_file,
    validate_event,
)
from secfoo.storage.repository import RunRepository

FP = "sca:pypi:pyyaml:GHSA-xxxx"
OTHER_FP = "sca:npm:lodash:GHSA-yyyy"
SESSION = "8f8a1c2e-0000-4000-8000-000000000001"

SESSION_LINE = {
    "type": "session", "id": SESSION, "language": "python", "runtime": "3.12.4", "source": "sensor",
    "started_at": "2026-11-08T10:00:00Z", "ended_at": "2026-11-08T16:00:00Z", "app": "payments-api",
    "env": "prod", "instance": "pod-1", "sensor_version": "0.4.0",
    "app_functions_total": 1840, "app_functions_executed": 1362,
}
LOAD_LINE = {
    "type": "load", "session": SESSION, "ecosystem": "PyPI", "package": "pyyaml", "version": "5.3",
    "path": "/app/.venv/lib/python3.12/site-packages/yaml", "first_seen": "2026-11-08T10:00:01Z",
}
HIT_LINE = {
    "type": "hit", "session": SESSION, "finding_fingerprint": FP, "symbol": "yaml.load", "route": "POST /upload",
    "auth": "anonymous", "count": 312, "first_seen": "2026-11-08T10:05:00Z", "last_seen": "2026-11-08T15:59:00Z",
    "entry_frame": "app/routes/upload.py:42", "stack_sample": ["app/routes/upload.py:42", "app/services/parse.py:17"],
}


def _lines(*events) -> list[str]:
    return [json.dumps(e) for e in events]


@pytest.fixture
def repo(tmp_path):
    with RunRepository(db_path=tmp_path / "db.sqlite") as repo:
        yield repo


@pytest.fixture
def project_id(repo):
    pid = repo.upsert_project("https://github.com/acme/payments", "payments", "github")
    run_uuid = repo.create_run(
        project_id=pid, skill_id="sca-reachability", skill_name="SCA", agent_id="claude", confluence_urls=[]
    )
    run_id = repo.get_run(run_uuid).id
    repo.upsert_sca_finding(project_id=pid, fingerprint=FP, run_id=run_id, current_ref="D1", package="pyyaml",
                            severity="high", version="5.3", ecosystem="PyPI", reachability="Not reachable")
    return pid


def _rows(repo, table):
    return [dict(r) for r in repo.connection.execute(f"SELECT * FROM {table}").fetchall()]  # nosec B608 -- test


# ---------- a valid file ----------


def test_valid_file_stores_session_load_and_hit(repo, project_id):
    report = ingest_events(repo.connection, project_id, _lines(SESSION_LINE, LOAD_LINE, HIT_LINE))

    assert (report.sessions, report.loads, report.hits, report.skipped) == (1, 1, 1, [])
    [session] = _rows(repo, "runtime_sessions")
    assert session["session_uuid"] == SESSION and session["source"] == "sensor"
    assert (session["app_functions_total"], session["app_functions_executed"]) == (1840, 1362)
    [package] = _rows(repo, "runtime_packages")
    assert (package["ecosystem"], package["package"], package["version"]) == ("PyPI", "pyyaml", "5.3")
    [hit] = _rows(repo, "runtime_evidence")
    assert hit["finding_fingerprint"] == FP and hit["route"] == "POST /upload" and hit["count"] == 312
    assert json.loads(hit["stack_sample"]) == HIT_LINE["stack_sample"]


def test_optional_fields_can_be_left_out(repo, project_id):
    minimal = _lines(
        {"type": "session", "id": "s1", "language": "node", "source": "coverage", "started_at": "2026-11-08T10:00:00"},
        {"type": "hit", "session": "s1", "finding_fingerprint": FP, "symbol": "pyyaml", "count": 1},
    )
    report = ingest_events(repo.connection, project_id, minimal)
    assert report.skipped == [] and report.hits == 1
    assert _rows(repo, "runtime_evidence")[0]["route"] == ""  # no request context


# ---------- malformed lines: skip and report, never abort ----------


def test_malformed_lines_are_skipped_and_reported_but_the_rest_is_stored(repo, project_id):
    lines = [
        json.dumps(SESSION_LINE),
        "{not json",
        json.dumps({**HIT_LINE, "count": 0}),
        json.dumps({"type": "bogus"}),
        "",  # blank lines are ignored, not errors
        json.dumps(LOAD_LINE),
        json.dumps(HIT_LINE),
    ]
    report = ingest_events(repo.connection, project_id, lines)

    assert (report.sessions, report.loads, report.hits) == (1, 1, 1)
    assert [n for n, _ in report.skipped] == [2, 3, 4]
    reasons = dict(report.skipped)
    assert "not valid JSON" in reasons[2]
    assert "'count'" in reasons[3]
    assert "'type'" in reasons[4]


def test_hit_for_an_unknown_fingerprint_is_skipped_with_a_warning(repo, project_id):
    report = ingest_events(
        repo.connection, project_id, _lines(SESSION_LINE, {**HIT_LINE, "finding_fingerprint": OTHER_FP})
    )
    assert report.hits == 0 and report.unknown_fingerprints == {OTHER_FP}
    assert "not an SCA finding of this project" in report.skipped[0][1]


def test_hit_before_any_session_line_is_skipped(repo, project_id):
    report = ingest_events(repo.connection, project_id, _lines(HIT_LINE))
    assert report.hits == 0 and "unknown session" in report.skipped[0][1]


def test_findings_of_another_project_do_not_count(repo, project_id):
    other = repo.upsert_project("/elsewhere", "elsewhere", "local")
    report = ingest_events(repo.connection, other, _lines({**SESSION_LINE}, HIT_LINE))
    assert report.hits == 0 and report.unknown_fingerprints == {FP}


# ---------- idempotent re-ingest ----------


def test_reingesting_the_same_file_does_not_double_count(repo, project_id):
    lines = _lines(SESSION_LINE, LOAD_LINE, HIT_LINE)
    ingest_events(repo.connection, project_id, lines)
    ingest_events(repo.connection, project_id, lines)

    assert len(_rows(repo, "runtime_sessions")) == 1
    assert len(_rows(repo, "runtime_packages")) == 1
    [hit] = _rows(repo, "runtime_evidence")
    assert hit["count"] == 312


def test_a_later_flush_of_the_same_session_replaces_the_running_total(repo, project_id):
    ingest_events(repo.connection, project_id, _lines(SESSION_LINE, HIT_LINE))
    later = {**HIT_LINE, "count": 400, "last_seen": "2026-11-08T17:00:00Z", "first_seen": "2026-11-08T11:00:00Z"}
    # The session line isn't repeated: hits attach to a session stored earlier.
    ingest_events(repo.connection, project_id, _lines(later))

    [hit] = _rows(repo, "runtime_evidence")
    assert hit["count"] == 400
    assert hit["first_seen"] == "2026-11-08T10:05:00Z"  # earliest kept
    assert hit["last_seen"] == "2026-11-08T17:00:00Z"  # latest kept


def test_each_route_is_its_own_row(repo, project_id):
    ingest_events(repo.connection, project_id, _lines(SESSION_LINE, HIT_LINE, {**HIT_LINE, "route": "GET /export"}))
    assert sorted(r["route"] for r in _rows(repo, "runtime_evidence")) == ["GET /export", "POST /upload"]


# ---------- privacy (#51 rule 3) ----------


@pytest.mark.parametrize("route", ["https://shop.example/upload", "POST /upload?token=abc", "GET /a#frag"])
def test_concrete_urls_are_rejected_as_routes(route):
    with pytest.raises(EvidenceError, match="template"):
        validate_event({**HIT_LINE, "route": route})


@pytest.mark.parametrize("stack", [["password=hunter2"], [{"frame": "a.py:1"}], ["a.py:1"] * 51, "a.py:1"])
def test_stack_samples_must_be_file_line_frames(stack):
    with pytest.raises(EvidenceError, match="stack_sample"):
        validate_event({**HIT_LINE, "stack_sample": stack})


def test_unknown_fields_are_never_stored(repo, project_id):
    sneaky = {**HIT_LINE, "args": ["s3cr3t"], "request_body": "card=4111"}
    ingest_events(repo.connection, project_id, _lines(SESSION_LINE, sneaky))
    dumped = json.dumps(_rows(repo, "runtime_evidence"))
    assert "s3cr3t" not in dumped and "4111" not in dumped


@pytest.mark.parametrize(
    "event, field",
    [
        ({**SESSION_LINE, "language": "cobol"}, "language"),
        ({**SESSION_LINE, "source": "guess"}, "source"),
        ({**SESSION_LINE, "started_at": "yesterday"}, "started_at"),
        ({**SESSION_LINE, "app_functions_executed": 2000}, "app_functions_executed"),
        ({**HIT_LINE, "auth": "admin"}, "auth"),
        ({**HIT_LINE, "count": True}, "count"),
        ({k: v for k, v in LOAD_LINE.items() if k != "version"}, "version"),
    ],
)
def test_invalid_fields_name_the_field(event, field):
    with pytest.raises(EvidenceError, match=field):
        validate_event(event)


# ---------- the JSON Schema says the same thing as the validator ----------


def test_json_schema_agrees_with_the_validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((Path(evidence.__file__).parent / "evidence.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for good in (SESSION_LINE, LOAD_LINE, HIT_LINE):
        validate_event(good)
        assert validator.is_valid(good), list(validator.iter_errors(good))
    for bad in (
        {**HIT_LINE, "route": "POST /upload?x=1"},
        {**HIT_LINE, "count": 0},
        {**HIT_LINE, "stack_sample": ["no-line-number"]},
        {**SESSION_LINE, "language": "cobol"},
        {"type": "load", "session": SESSION},
    ):
        assert not validator.is_valid(bad)
        with pytest.raises(EvidenceError):
            validate_event(bad)


# ---------- migration: works on an existing database ----------


def test_tables_are_added_to_a_database_created_before_they_existed(tmp_path):
    db = tmp_path / "old.sqlite"
    with RunRepository(db_path=db):
        pass
    conn = sqlite3.connect(db)
    for table in ("runtime_evidence", "runtime_packages", "runtime_sessions"):
        conn.execute(f"DROP TABLE {table}")  # simulate a store from before #53
    conn.commit()
    conn.close()

    with RunRepository(db_path=db) as repo:
        tables = {r[0] for r in repo.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"runtime_sessions", "runtime_evidence", "runtime_packages"} <= tables


# ---------- CLI ----------


def test_cli_ingest_reports_counts_and_skipped_lines(tmp_path, monkeypatch):
    db = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda: RunRepository(db_path=db))
    with RunRepository(db_path=db) as repo:
        pid = repo.upsert_project("https://github.com/acme/payments", "payments", "github")
        run_id = repo.get_run(repo.create_run(
            project_id=pid, skill_id="sca-reachability", skill_name="SCA", agent_id="claude", confluence_urls=[]
        )).id
        repo.upsert_sca_finding(project_id=pid, fingerprint=FP, run_id=run_id, current_ref="D1",
                                package="pyyaml", severity="high")
    events = tmp_path / "events.ndjson"
    events.write_text("\n".join(_lines(SESSION_LINE, LOAD_LINE, HIT_LINE)) + "\n{broken\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["runtime", "ingest", str(events), "--project", "payments"])

    assert result.exit_code == 1  # one line was skipped
    assert "Stored 1 session(s), 1 package load(s), 1 hit(s)" in result.output
    assert "line 4: not valid JSON" in result.output

    clean = tmp_path / "clean.ndjson"
    clean.write_text("\n".join(_lines(SESSION_LINE, HIT_LINE)), encoding="utf-8")
    again = CliRunner().invoke(app, ["runtime", "ingest", str(clean), "--project", str(pid)])
    assert again.exit_code == 0, again.output
    with RunRepository(db_path=db) as repo:
        assert repo.connection.execute("SELECT count FROM runtime_evidence").fetchone()[0] == 312


def test_cli_ingest_unknown_project(tmp_path, monkeypatch):
    db = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda: RunRepository(db_path=db))
    events = tmp_path / "events.ndjson"
    events.write_text(json.dumps(SESSION_LINE), encoding="utf-8")
    result = CliRunner().invoke(app, ["runtime", "ingest", str(events), "--project", "nope"])
    assert result.exit_code == 1
    assert "no single project matches 'nope'" in result.output


def test_ingest_file_reads_a_path(repo, project_id, tmp_path):
    path = tmp_path / "e.ndjson"
    path.write_text("\n".join(_lines(SESSION_LINE, HIT_LINE)), encoding="utf-8")
    assert ingest_file(repo.connection, project_id, path).hits == 1
