"""#112: ranged and multi-site Location cells become real paths.

Before #112, parse_location() only understood `file:line`, so
"server.js:78-102, app/routes/session.js:116" was stored whole as the
file name: SARIF got a percent-encoded URI GitHub cannot attach to a file,
and the fingerprint changed whenever an agent wrote `all.js:8` instead of
`all.js:8-9`.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema import Draft7Validator, FormatChecker

from secfoo.report import sast, secret_scanning
from secfoo.report.sarif import findings_to_sarif
from secfoo.report.sast import (
    SourceLocation,
    fingerprint_for_row,
    parse_location,
    parse_locations,
)
from secfoo.runner import update_sast_findings, update_secret_findings
from secfoo.storage.repository import RunRepository

ROOT = Path(__file__).parents[2]
SAMPLE = ROOT / "examples" / "sample-output" / "nodegoat"
SCHEMA = json.loads((Path(__file__).parents[1] / "fixtures" / "sarif-schema-2.1.0.json").read_text())
VALIDATOR = Draft7Validator(SCHEMA, format_checker=FormatChecker())


# --- The four strings from the issue -------------------------------------

@pytest.mark.parametrize(
    ("cell", "expected"),
    [
        ("config/env/all.js:8-9", [("config/env/all.js", "8", "9")]),
        (
            "server.js:78-102, app/routes/session.js:116, …",
            [("server.js", "78", "102"), ("app/routes/session.js", "116", None)],
        ),
        ("app/data/user-dao.js:25, :61", [("app/data/user-dao.js", "25", None), ("app/data/user-dao.js", "61", None)]),
        (
            "`server.js:135-137`, `app/views/layout.html:75`",
            [("server.js", "135", "137"), ("app/views/layout.html", "75", None)],
        ),
    ],
)
def test_issue_examples_parse_into_every_site(cell, expected):
    assert parse_locations(cell) == [SourceLocation(*site) for site in expected]
    assert parse_location(cell) == (expected[0][0], expected[0][1])


@pytest.mark.parametrize(
    ("cell", "expected"),
    [
        ("`app/db.py:42`", [("app/db.py", "42", None)]),
        ("app/db.py", [("app/db.py", None, None)]),
        ("a.py:10–12", [("a.py", "10", "12")]),  # en dash
        ("a.py:10 - 12", [("a.py", "10", "12")]),
        ("a.py:12:5", [("a.py", "12", None)]),  # line:column
        ("a.py:9-3", [("a.py", "9", None)]),  # reversed range is its start line
        ("a.py:7-7", [("a.py", "7", None)]),
        ("a.py:25,61", [("a.py", "25", None), ("a.py", "61", None)]),
        ("a.py:1; b.py:2", [("a.py", "1", None), ("b.py", "2", None)]),
        ("a.py:5, 80-90", [("a.py", "5", None), ("a.py", "80", "90")]),
        ("a.py:0042", [("a.py", "42", None)]),
        (r"C:\src\app.py:12", [(r"C:\src\app.py", "12", None)]),
        ("", []),
        ("…", []),
        (":61", []),  # a bare line with no path before it
    ],
)
def test_other_location_shapes(cell, expected):
    assert parse_locations(cell) == [SourceLocation(*site) for site in expected]


def test_a_cell_with_no_site_degrades_to_its_text():
    assert parse_location("  `…`  ") == ("…", None)


# --- Properties ----------------------------------------------------------

_TRAILING_RANGE = re.compile(r":\s*\d+(\s*[-\u2013\u2014]\s*\d+)?\s*$")
_PATH = st.from_regex(r"[A-Za-z0-9_./-]{1,20}", fullmatch=True).filter(lambda p: any(c.isalnum() for c in p))
_LINE = st.integers(min_value=1, max_value=99_999).map(str)


@settings(max_examples=300)
@given(st.text(alphabet=st.characters(codec="utf-8"), max_size=120))
def test_parse_locations_never_leaves_separators_or_ranges_in_a_path(cell):
    for site in parse_locations(cell):
        assert site.path and site.path == site.path.strip()
        assert not set(site.path) & {",", ";", "`"}
        assert not _TRAILING_RANGE.search(site.path)
        assert site.start_line is None or site.start_line.isdigit()
        if site.end_line is not None:
            assert (len(site.end_line), site.end_line) > (len(site.start_line), site.start_line)
    path, _line = parse_location(cell)
    assert "`" not in path


@settings(max_examples=200)
@given(st.lists(st.tuples(_PATH, _LINE, st.one_of(st.none(), _LINE)), min_size=1, max_size=5), st.booleans())
def test_written_lists_round_trip(sites, backticks):
    tick = "`" if backticks else ""
    cell = ", ".join(f"{tick}{p}:{a}{'-' + b if b else ''}{tick}" for p, a, b in sites)
    parsed = parse_locations(cell)
    assert [(s.path, s.start_line) for s in parsed] == [(p, a) for p, a, _b in sites]
    for site, (_p, a, b) in zip(parsed, sites):
        assert site.end_line == (b if b is not None and int(b) > int(a) else None)


def test_fingerprint_is_the_same_for_a_range_and_its_first_line():
    """all.js:8-9 one run and all.js:8 the next is the same finding."""
    ranged = fingerprint_for_row({"cwe": "CWE-798", "location": "`config/env/all.js:8-9`"})
    single = fingerprint_for_row({"cwe": "CWE-798", "location": "`config/env/all.js:8`"})
    multi = fingerprint_for_row({"cwe": "CWE-798", "location": "`config/env/all.js:8`, `db-reset.js:15-18`"})
    assert ranged == single == multi


# --- The NodeGoat sample -------------------------------------------------

def _sample_records() -> list[dict]:
    records = []
    for skill, module, report in (
        ("sast", sast, "sast-report.md"),
        ("secret-scanning", secret_scanning, "secret-scanning-report.md"),
    ):
        for row in module.findings_with_fingerprints((SAMPLE / report).read_text(encoding="utf-8")):
            records.append({**row, "skill_id": skill})
    return records


def test_nodegoat_sample_sarif_validates_and_every_result_has_a_real_uri():
    records = _sample_records()
    assert len(records) == 18
    document = findings_to_sarif(records)
    VALIDATOR.validate(document)
    for result in document["runs"][0]["results"]:
        assert result["locations"]
        for location in result["locations"]:
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
            # No encoded comma, colon, semicolon, space or backtick: one file per URI.
            assert not re.search(r"%(2C|3A|3B|20|60)", uri, re.IGNORECASE), uri
            region = location["physicalLocation"].get("region")
            if region and "endLine" in region:
                assert region["endLine"] > region["startLine"]


def test_nodegoat_multi_site_finding_gets_one_sarif_location_per_site():
    records = {r["id"]: r for r in _sample_records() if r["skill_id"] == "sast"}
    xss = next(r for r in records.values() if "server.js:135-137" in r["location"])
    result = findings_to_sarif([xss])["runs"][0]["results"][0]
    assert [loc["physicalLocation"] for loc in result["locations"]] == [
        {"artifactLocation": {"uri": "server.js"}, "region": {"startLine": 135, "endLine": 137}},
        {"artifactLocation": {"uri": "app/views/layout.html"}, "region": {"startLine": 75}},
    ]


def test_sarif_without_locations_falls_back_to_location_file():
    result = findings_to_sarif([{"skill_id": "sast", "location_file": "a.py", "location_line": "3"}])
    assert result["runs"][0]["results"][0]["locations"] == [
        {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 3}}}
    ]


# --- Storage, migration and lifecycle ------------------------------------

_REPORT = """# SAST

## Findings Register

| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | Hard-coded secret | High | CWE-798 | A07:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | `config/env/all.js:8-9`, `artifacts/db-reset.js:15-18` | Confirmed |
"""

_SECRET_REPORT = (SAMPLE / "secret-scanning-report.md").read_text(encoding="utf-8")


def _project_and_run(repo: RunRepository) -> tuple[int, int]:
    project_id = repo.upsert_project(identifier="/tmp/x", display_name="x", kind="local")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[]
    )
    return project_id, repo.get_run(run_uuid).id


def test_sast_rows_store_every_site(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _project_and_run(repo)
    update_sast_findings(repo, project_id=project_id, run_id=run_id, report_text=_REPORT)
    (row,) = repo.list_sast_findings()
    assert (row.location_file, row.location_line) == ("config/env/all.js", "8")
    assert row.sites() == [
        {"path": "config/env/all.js", "start_line": "8", "end_line": "9"},
        {"path": "artifacts/db-reset.js", "start_line": "15", "end_line": "18"},
    ]
    repo.close()


def _store_as_before_112(repo: RunRepository, table: str) -> None:
    """Drop the #112 column, as on a store created before it existed."""
    repo._conn.execute(f"ALTER TABLE {table} DROP COLUMN locations")
    repo._conn.commit()


def test_migration_re_derives_locations_for_rows_stored_before_112(tmp_path):
    db_path = tmp_path / "db.sqlite"
    repo = RunRepository(db_path=db_path)
    project_id, run_id = _project_and_run(repo)
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint="old", current_ref="F12", title="XSS", severity="High",
        cwe="CWE-79", owasp=None, verdict=None,
        location_file="server.js:78-102, app/routes/session.js:116, …", location_line=None,
        cvss_vector=None, cvss_score=None, run_id=run_id,
    )
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint="plain", current_ref="F1", title="SQLi", severity="High",
        cwe="CWE-89", owasp=None, verdict=None, location_file="app/db.py", location_line="42",
        cvss_vector=None, cvss_score=None, run_id=run_id,
    )
    repo.upsert_secret_finding(
        project_id=project_id, fingerprint="s-old", run_id=run_id, current_ref="S1", secret_type="Password",
        location_file="config/env/all.js:8-9", severity="High",
    )
    _store_as_before_112(repo, "sast_findings")
    _store_as_before_112(repo, "secret_findings")
    repo.close()

    repo = RunRepository(db_path=db_path)
    rows = {r.fingerprint: r for r in repo.list_sast_findings()}
    assert (rows["old"].location_file, rows["old"].location_line) == ("server.js", "78")
    assert json.loads(rows["old"].locations) == [
        {"path": "server.js", "start_line": "78", "end_line": "102"},
        {"path": "app/routes/session.js", "start_line": "116", "end_line": None},
    ]
    assert (rows["plain"].location_file, rows["plain"].location_line) == ("app/db.py", "42")
    assert json.loads(rows["plain"].locations) == [{"path": "app/db.py", "start_line": "42", "end_line": None}]
    (secret,) = repo.list_secret_findings()
    assert (secret.location_file, secret.location_line) == ("config/env/all.js", "8")
    assert json.loads(secret.locations) == [{"path": "config/env/all.js", "start_line": "8", "end_line": "9"}]
    repo.close()

    # Opening again is a no-op: nothing is NULL any more.
    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM sast_findings WHERE locations IS NULL").fetchone() == (0,)
    conn.close()


def test_a_finding_stored_before_112_stays_open_when_seen_again(tmp_path):
    """The upgrade must not show every multi-site finding as closed + new."""
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _project_and_run(repo)
    row = sast.extract_findings_register_rows(_REPORT)[0]
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint=sast.pre_112_fingerprint(row), current_ref="F1",
        title="Hard-coded secret", severity="High", cwe="CWE-798", owasp=None, verdict=None,
        location_file=row["location"].replace("`", ""), location_line=None,
        cvss_vector=None, cvss_score=None, run_id=run_id,
    )
    (before,) = repo.list_sast_findings()

    update_sast_findings(repo, project_id=project_id, run_id=run_id, report_text=_REPORT)

    (after,) = repo.list_sast_findings()
    assert after.id == before.id
    assert after.status == "open"
    assert after.fingerprint == fingerprint_for_row(row)
    assert after.first_seen_at == before.first_seen_at
    repo.close()


def test_a_secret_stored_before_112_stays_open_when_seen_again(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _project_and_run(repo)
    rows = secret_scanning.findings_with_fingerprints(_SECRET_REPORT)
    ranged = [r for r in rows if r["pre_112_fingerprint"]]
    assert ranged, "the sample should contain at least one ranged secret location"
    for row in rows:
        repo.upsert_secret_finding(
            project_id=project_id, fingerprint=row["pre_112_fingerprint"] or row["fingerprint"], run_id=run_id,
            current_ref=row["id"], secret_type=row["secret_type"], location_file=row["location"],
            severity=row["severity"],
        )
    ids_before = {r.id for r in repo.list_secret_findings()}

    update_secret_findings(repo, project_id=project_id, run_id=run_id, report_text=_SECRET_REPORT)

    after = repo.list_secret_findings()
    assert {r.id for r in after} == ids_before
    assert all(r.status == "open" for r in after)
    repo.close()


@pytest.mark.parametrize(
    ("cell", "old_path"),
    [
        # The old regex matched these, but read the whole list as one file.
        ("app/db.py, app/cli.py", "app/db.py, app/cli.py"),
        ("app/db.py; app/cli.py", "app/db.py; app/cli.py"),
        ("app/db.py, app/cli.py:12", "app/db.py, app/cli.py"),
    ],
)
def test_an_unbackticked_list_the_old_parser_matched_is_still_rekeyed(cell, old_path):
    assert sast.pre_112_path(cell) == old_path
    # The key a stored row got: skill | cwe | whole path (no line, no region hash).
    old_sast = hashlib.sha256(f"{sast.SKILL_ID}|cwe-89|{old_path}".encode()).hexdigest()
    assert sast.pre_112_fingerprint({"cwe": "CWE-89", "location": cell}) == old_sast
    old_secret = secret_scanning.fingerprint_for_row({"secret_type": "x"}, file_path=old_path)
    assert secret_scanning.pre_112_fingerprint({"secret_type": "x", "location": cell}) == old_secret


def test_rekey_is_a_no_op_for_a_single_site_cell():
    assert sast.pre_112_fingerprint({"cwe": "CWE-89", "location": "`app/db.py:42`"}) is None
    assert secret_scanning.pre_112_fingerprint({"secret_type": "x", "location": "`a.env:3`"}) is None


def test_jsonl_export_carries_locations_as_a_list():
    from secfoo.cli import _decoded_locations

    assert _decoded_locations('[{"path": "a.py", "start_line": "1", "end_line": null}]') == [
        {"path": "a.py", "start_line": "1", "end_line": None}
    ]
    assert _decoded_locations(None) is None
    assert _decoded_locations("not json") is None
    assert _decoded_locations('{"path": "a.py"}') is None
