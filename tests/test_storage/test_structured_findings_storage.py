from __future__ import annotations

import sqlite3

from secfoo.report.sast import fingerprint_for_row as sast_fp
from secfoo.report.secret_scanning import fingerprint_for_row as sec_fp
from secfoo.runner import update_sast_findings
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
    kwargs = {
        "project_id": project_id, "fingerprint": "s1", "run_id": run_id, "current_ref": "S1", "secret_type": "API token",
        "location_file": "deploy/ci.yml", "severity": "High", "evidence": "TOKENJ4F...",
    }
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
    secret_columns = {row["name"] for row in repo._conn.execute("PRAGMA table_info(secret_findings)")}
    run_columns = {row["name"] for row in repo._conn.execute("PRAGMA table_info(runs)")}
    repo.close()
    assert {"language", "framework", "construct", "code_region_hash", "locations"} <= columns
    assert "locations" in secret_columns
    assert "memory_enabled" in run_columns


def test_migration_re_derives_locations_for_existing_sast_and_secret_rows(tmp_path):
    db_path = tmp_path / "legacy.sqlite"
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
        CREATE TABLE sast_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            current_ref TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cwe TEXT,
            owasp TEXT,
            verdict TEXT,
            location_file TEXT NOT NULL,
            location_line TEXT,
            code_region_hash TEXT,
            language TEXT,
            framework TEXT,
            construct TEXT,
            cvss_vector TEXT,
            cvss_score REAL,
            description TEXT,
            recommendation TEXT,
            status TEXT NOT NULL,
            first_seen_run_id INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_run_id INTEGER NOT NULL,
            last_seen_at TEXT NOT NULL,
            closed_in_run_id INTEGER,
            closed_at TEXT,
            UNIQUE (project_id, fingerprint)
        );
        CREATE TABLE secret_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            current_ref TEXT NOT NULL,
            secret_type TEXT NOT NULL,
            location_file TEXT NOT NULL,
            location_line TEXT,
            code_region_hash TEXT,
            source TEXT,
            validity TEXT,
            severity TEXT NOT NULL,
            evidence TEXT,
            exposure TEXT,
            remediation TEXT,
            language TEXT,
            framework TEXT,
            construct TEXT,
            status TEXT NOT NULL,
            first_seen_run_id INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_run_id INTEGER NOT NULL,
            last_seen_at TEXT NOT NULL,
            closed_in_run_id INTEGER,
            closed_at TEXT,
            UNIQUE (project_id, fingerprint)
        );
        INSERT INTO projects VALUES (1, '/tmp/nodegoat', 'NodeGoat', 'local', '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z');
        INSERT INTO runs (id, run_uuid, project_id, skill_id, skill_name, agent_id, status, started_at)
        VALUES (1, 'run-1', 1, 'sast', 'SAST', 'claude', 'success', '2026-11-14T00:00:00Z');
        INSERT INTO sast_findings (
            project_id, fingerprint, current_ref, title, severity, cwe, location_file, location_line,
            status, first_seen_run_id, first_seen_at, last_seen_run_id, last_seen_at
        ) VALUES
            (1, 'fp-f7', 'F7', 'Plaintext passwords', 'Medium', 'CWE-256',
             'app/data/user-dao.js:25, :61', NULL, 'open', 1, '2026-11-14T00:00:00Z', 1, '2026-11-14T00:00:00Z'),
            (1, 'fp-f6', 'F6', 'Autoescape off', 'High', 'CWE-79',
             'server.js:135-137, app/views/layout.html:75', NULL, 'open', 1, '2026-11-14T00:00:00Z', 1, '2026-11-14T00:00:00Z'),
            (1, 'fp-single', 'F1', 'SQLi', 'High', 'CWE-89',
             'app/db.py', '42', 'open', 1, '2026-11-14T00:00:00Z', 1, '2026-11-14T00:00:00Z');
        INSERT INTO secret_findings (
            project_id, fingerprint, current_ref, secret_type, location_file, location_line,
            source, validity, severity, status, first_seen_run_id, first_seen_at, last_seen_run_id, last_seen_at
        ) VALUES
            (1, 'fp-s5', 'S5', 'Seeded passwords',
             'artifacts/db-reset.js:18,27,35; test/e2e/fixtures/users/*.json; test/security/profile-test.js:37',
             NULL, 'code', 'Looks live', 'Medium', 'open', 1, '2026-11-14T00:00:00Z', 1, '2026-11-14T00:00:00Z');
        """
    )
    conn.close()

    with RunRepository(db_path=db_path) as repo:
        sast_by_ref = {r.current_ref: r for r in repo.list_sast_findings()}
        secret_by_ref = {r.current_ref: r for r in repo.list_secret_findings()}
        exported = {(skill, row["current_ref"]): row for skill, row in repo.list_structured_findings()}

    assert sast_by_ref["F7"].location_file == "app/data/user-dao.js"
    assert sast_by_ref["F7"].location_line == "25"
    assert sast_by_ref["F7"].locations == [
        {"path": "app/data/user-dao.js", "start_line": 25, "end_line": None},
        {"path": "app/data/user-dao.js", "start_line": 61, "end_line": None},
    ]
    assert sast_by_ref["F6"].location_file == "server.js"
    assert sast_by_ref["F6"].location_line == "135"
    assert sast_by_ref["F6"].locations == [
        {"path": "server.js", "start_line": 135, "end_line": 137},
        {"path": "app/views/layout.html", "start_line": 75, "end_line": None},
    ]
    assert sast_by_ref["F1"].location_file == "app/db.py"
    assert sast_by_ref["F1"].location_line == "42"
    assert sast_by_ref["F1"].locations == [
        {"path": "app/db.py", "start_line": 42, "end_line": None},
    ]
    assert secret_by_ref["S5"].location_file == "artifacts/db-reset.js"
    assert secret_by_ref["S5"].location_line == "18"
    assert secret_by_ref["S5"].locations == [
        {"path": "artifacts/db-reset.js", "start_line": 18, "end_line": None},
        {"path": "artifacts/db-reset.js", "start_line": 27, "end_line": None},
        {"path": "artifacts/db-reset.js", "start_line": 35, "end_line": None},
        {"path": "test/e2e/fixtures/users/*.json", "start_line": None, "end_line": None},
        {"path": "test/security/profile-test.js", "start_line": 37, "end_line": None},
    ]
    assert isinstance(exported[("sast", "F6")]["locations"], list)
    assert isinstance(exported[("secret-scanning", "S5")]["locations"], list)
    assert sast_by_ref["F7"].fingerprint == sast_fp({"cwe": "CWE-256", "location": "app/data/user-dao.js:25, :61"})
    assert sast_by_ref["F6"].fingerprint == sast_fp({"cwe": "CWE-79", "location": "server.js:135-137, app/views/layout.html:75"})
    assert secret_by_ref["S5"].fingerprint == sec_fp({"secret_type": "Seeded passwords"}, file_path="artifacts/db-reset.js")


def test_migration_collapses_duplicate_findings_preserving_review(tmp_path):
    db_path = tmp_path / "legacy.sqlite"
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
        CREATE TABLE sast_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            current_ref TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cwe TEXT,
            owasp TEXT,
            verdict TEXT,
            location_file TEXT NOT NULL,
            location_line TEXT,
            code_region_hash TEXT,
            language TEXT,
            framework TEXT,
            construct TEXT,
            cvss_vector TEXT,
            cvss_score REAL,
            description TEXT,
            recommendation TEXT,
            status TEXT NOT NULL,
            first_seen_run_id INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_run_id INTEGER NOT NULL,
            last_seen_at TEXT NOT NULL,
            closed_in_run_id INTEGER,
            closed_at TEXT,
            review_status TEXT,
            review_note TEXT,
            reviewed_by TEXT,
            reviewed_at TEXT,
            UNIQUE (project_id, fingerprint)
        );
        INSERT INTO projects VALUES (1, '/tmp/nodegoat', 'NodeGoat', 'local', '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z');
        INSERT INTO runs (id, run_uuid, project_id, skill_id, skill_name, agent_id, status, started_at)
        VALUES (1, 'run-1', 1, 'sast', 'SAST', 'claude', 'success', '2026-11-14T00:00:00Z');
        INSERT INTO sast_findings (
            project_id, fingerprint, current_ref, title, severity, cwe, location_file, location_line,
            status, first_seen_run_id, first_seen_at, last_seen_run_id, last_seen_at,
            review_status, review_note, reviewed_by, reviewed_at
        ) VALUES
            (1, 'old-fp-1', 'F1', 'Missing HttpOnly', 'Medium', 'CWE-1004',
             'server.js:78-102', NULL, 'open', 1, '2026-11-14T00:00:00Z', 1, '2026-11-14T00:00:00Z',
             NULL, NULL, NULL, NULL),
            (1, 'old-fp-2', 'F2', 'Missing HttpOnly cookie flag', 'Medium', 'CWE-1004',
             'server.js:104-113', NULL, 'open', 1, '2026-11-14T01:00:00Z', 1, '2026-11-14T01:00:00Z',
             'confirmed', 'Cookie flag verified missing', 'secops', '2026-11-15T10:00:00Z');
        """
    )
    conn.close()

    with RunRepository(db_path=db_path) as repo:
        open_findings = repo.list_sast_findings(status="open")
        closed_findings = repo.list_sast_findings(status="closed")

    assert len(open_findings) == 1
    assert open_findings[0].review_status == "confirmed"
    assert open_findings[0].review_note == "Cookie flag verified missing"
    assert open_findings[0].reviewed_by == "secops"
    assert open_findings[0].reviewed_at == "2026-11-15T10:00:00Z"
    assert open_findings[0].location_file == "server.js"
    assert open_findings[0].locations == [{"path": "server.js", "start_line": 104, "end_line": 113}]

    assert len(closed_findings) == 1
    assert ":merged:" in closed_findings[0].fingerprint
    assert closed_findings[0].status == "closed"


def test_migration_rescan_causes_no_churn(tmp_path):
    db_path = tmp_path / "rescan.sqlite"
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
        CREATE TABLE sast_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            current_ref TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cwe TEXT,
            owasp TEXT,
            verdict TEXT,
            location_file TEXT NOT NULL,
            location_line TEXT,
            code_region_hash TEXT,
            language TEXT,
            framework TEXT,
            construct TEXT,
            cvss_vector TEXT,
            cvss_score REAL,
            description TEXT,
            recommendation TEXT,
            status TEXT NOT NULL,
            first_seen_run_id INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_run_id INTEGER NOT NULL,
            last_seen_at TEXT NOT NULL,
            closed_in_run_id INTEGER,
            closed_at TEXT,
            review_status TEXT,
            review_note TEXT,
            reviewed_by TEXT,
            reviewed_at TEXT,
            UNIQUE (project_id, fingerprint)
        );
        INSERT INTO projects VALUES (1, '/tmp/nodegoat', 'NodeGoat', 'local', '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z');
        INSERT INTO runs (id, run_uuid, project_id, skill_id, skill_name, agent_id, status, started_at)
        VALUES (1, 'run-1', 1, 'sast', 'SAST', 'claude', 'success', '2026-11-14T00:00:00Z');
        INSERT INTO sast_findings (
            project_id, fingerprint, current_ref, title, severity, cwe, location_file, location_line,
            status, first_seen_run_id, first_seen_at, last_seen_run_id, last_seen_at,
            review_status, review_note, reviewed_by, reviewed_at
        ) VALUES
            (1, 'old-fp-1', 'F1', 'Missing HttpOnly', 'Medium', 'CWE-1004',
             'server.js:78-102', NULL, 'open', 1, '2026-11-14T00:00:00Z', 1, '2026-11-14T00:00:00Z',
             'confirmed', 'Reviewed and accepted', 'secops', '2026-11-15T10:00:00Z');
        """
    )
    conn.close()

    # Step 1: Migration runs automatically when RunRepository opens
    with RunRepository(db_path=db_path) as repo:
        migrated = repo.list_sast_findings(status="open")
        assert len(migrated) == 1
        assert migrated[0].review_status == "confirmed"

        # Step 2: Next run scans the project and finds the vulnerability with new range/multi-site format
        run_uuid = repo.create_run(
            project_id=1, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[]
        )
        run_id = repo.get_run(run_uuid).id
        report_text = """# SAST Report
## Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | Missing HttpOnly cookie flag | Medium | CWE-1004 | A05:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | `server.js:78-102, :104-113` | Confirmed |
"""
        update_sast_findings(repo, project_id=1, run_id=run_id, report_text=report_text)

        after_scan_open = repo.list_sast_findings(status="open")
        after_scan_closed = repo.list_sast_findings(status="closed")

    assert len(after_scan_open) == 1
    assert len(after_scan_closed) == 0
    assert after_scan_open[0].review_status == "confirmed"
    assert after_scan_open[0].review_note == "Reviewed and accepted"
    assert after_scan_open[0].reviewed_by == "secops"
    assert after_scan_open[0].last_seen_run_id == run_id


def test_complete_run_records_memory_flag(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project(identifier="/tmp/x", display_name="x", kind="local")
    on = repo.create_run(project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[])
    off = repo.create_run(project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[])
    untouched = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[]
    )
    common = {
        "status": "success", "exit_code": 0, "duration_seconds": 1.0, "report_path": None, "prompt_path": None,
        "stderr_excerpt": None,
    }
    repo.complete_run(on, memory_enabled=True, **common)
    repo.complete_run(off, memory_enabled=False, **common)
    repo.complete_run(untouched, **common)
    assert repo.get_run(on).memory_enabled == 1
    assert repo.get_run(off).memory_enabled == 0
    assert repo.get_run(untouched).memory_enabled is None
    repo.close()
