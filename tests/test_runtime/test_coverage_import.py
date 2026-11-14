"""#54: coverage files as runtime evidence -- end to end with committed fixtures."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secfoo.cli import app
from secfoo.runtime.coverage_import import CoverageImportError, load_coverage, to_events
from secfoo.storage.repository import RunRepository

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "coverage"
PY_COVERAGE = FIXTURES / "python-coverage.json"
V8_DIR = FIXTURES / "v8"
runner = CliRunner(env={"COLUMNS": "250"})


def _watchlist(path: Path) -> Path:
    path.write_text(json.dumps({"version": 1, "generated_at": "x", "entries": [
        {"finding_fingerprint": "fp-py", "advisory": None, "ecosystem": "PyPI", "package": "vulnpkg", "version": "1",
         "granularity": "symbol", "symbols": ["vulnpkg.load", "vulnpkg.safe_load", "vulnpkg.Loader.construct",
                                              "vulnpkg.missing"], "source": "osv"},
        {"finding_fingerprint": "fp-npm", "advisory": None, "ecosystem": "npm", "package": "lodash", "version": "4",
         "granularity": "symbol", "symbols": ["lodash#template", "lodash#escape"], "source": "osv"},
        {"finding_fingerprint": "fp-babel", "advisory": None, "ecosystem": "npm", "package": "@babel/core",
         "version": "7", "granularity": "symbol", "symbols": ["@babel/core#transform"], "source": "osv"},
    ]}), encoding="utf-8")
    return path


def _hits(events):
    return {e["symbol"]: e for e in events if e["type"] == "hit"}


# ---------- Python ----------


def test_python_coverage_hits_and_app_coverage(tmp_path):
    events, notes = to_events(load_coverage(PY_COVERAGE), json.loads(_watchlist(tmp_path / "w.json").read_text()))
    session = events[0]
    assert session["source"] == "coverage" and session["language"] == "python"
    assert (session["app_functions_total"], session["app_functions_executed"]) == (2, 1)  # handle ran, unused didn't
    hits = _hits(events)
    assert set(hits) == {"vulnpkg.load", "vulnpkg.Loader.construct"}  # safe_load never ran
    assert all("stack_sample" not in h and "entry_frame" not in h for h in hits.values())
    assert any("weren't in the coverage report" in n for n in notes)  # vulnpkg.missing


def test_python_coverage_without_dependencies_explains_how_to_collect_them(tmp_path):
    report = json.loads(PY_COVERAGE.read_text())
    report["files"] = {k: v for k, v in report["files"].items() if "site-packages" not in k}
    path = tmp_path / "app-only.json"
    path.write_text(json.dumps(report))
    with pytest.raises(CoverageImportError, match=r"omits site-packages by default.*--source"):
        load_coverage(path)


def test_old_coverage_without_function_data_is_explained(tmp_path):
    report = json.loads(PY_COVERAGE.read_text())
    for entry in report["files"].values():
        entry.pop("functions")
    path = tmp_path / "old.json"
    path.write_text(json.dumps(report))
    with pytest.raises(CoverageImportError, match="coverage >= 7.5"):
        load_coverage(path)


# ---------- Node / V8 ----------


def test_v8_coverage_directory(tmp_path):
    events, _ = to_events(load_coverage(V8_DIR), json.loads(_watchlist(tmp_path / "w.json").read_text()))
    session = events[0]
    assert session["language"] == "node"
    assert (session["app_functions_total"], session["app_functions_executed"]) == (2, 1)
    hits = _hits(events)
    assert set(hits) == {"lodash#template"}  # escape and @babel/core#transform had count 0
    assert hits["lodash#template"]["count"] == 4


def test_a_single_v8_file_works_too(tmp_path):
    [file] = V8_DIR.glob("*.json")
    events, _ = to_events(load_coverage(file), json.loads(_watchlist(tmp_path / "w.json").read_text()))
    assert set(_hits(events)) == {"lodash#template"}


def test_unrecognised_files_are_rejected(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text('{"hello": 1}')
    with pytest.raises(CoverageImportError, match="not a coverage.py JSON report or a V8"):
        load_coverage(bad)


# ---------- end to end: import -> ingest -> evidence rows ----------


@pytest.mark.parametrize("source, fingerprint, symbol, count", [
    (PY_COVERAGE, "fp-py", "vulnpkg.load", 1),
    (V8_DIR, "fp-npm", "lodash#template", 4),
])
def test_end_to_end_import_ingest_evidence(tmp_path, monkeypatch, source, fingerprint, symbol, count):
    db = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda: RunRepository(db_path=db))
    with RunRepository(db_path=db) as repo:
        pid = repo.upsert_project("https://github.com/acme/app", "app", "github")
        run_id = repo.get_run(repo.create_run(project_id=pid, skill_id="sca-reachability", skill_name="SCA",
                                              agent_id="claude", confluence_urls=[])).id
        for fp in ("fp-py", "fp-npm", "fp-babel"):
            repo.upsert_sca_finding(project_id=pid, fingerprint=fp, run_id=run_id, current_ref="D1", package=fp,
                                    severity="High")
    out = tmp_path / "events.ndjson"
    imported = runner.invoke(app, ["runtime", "import-coverage", str(source), "--watchlist",
                                   str(_watchlist(tmp_path / "w.json")), "-o", str(out)])
    assert imported.exit_code == 0, imported.output
    ingested = runner.invoke(app, ["runtime", "ingest", str(out), "--project", "app"])
    assert ingested.exit_code == 0, ingested.output
    again = runner.invoke(app, ["runtime", "ingest", str(out), "--project", "app"])  # idempotent
    assert again.exit_code == 0
    with RunRepository(db_path=db) as repo:
        rows = [tuple(r) for r in repo.connection.execute(
            "SELECT e.finding_fingerprint, e.symbol, e.count, s.source FROM runtime_evidence e "
            "JOIN runtime_sessions s ON s.id = e.session_id WHERE e.finding_fingerprint = ?", (fingerprint,))]
    assert (fingerprint, symbol, count, "coverage") in rows
    assert len([r for r in rows if r[1] == symbol]) == 1


def test_cli_reports_missing_dependencies_clearly(tmp_path):
    report = json.loads(PY_COVERAGE.read_text())
    report["files"] = {k: v for k, v in report["files"].items() if "site-packages" not in k}
    path = tmp_path / "app-only.json"
    path.write_text(json.dumps(report))
    result = runner.invoke(app, ["runtime", "import-coverage", str(path), "--watchlist",
                                 str(_watchlist(tmp_path / "w.json"))])
    assert result.exit_code == 1 and "site-packages" in " ".join(result.output.split())
