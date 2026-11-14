"""#80: runtime evidence in the CLI, SARIF and the CI gate."""
from __future__ import annotations

import json
import urllib.error

import pytest
from typer.testing import CliRunner

from secfoo.cli import EXIT_RUNTIME_REACHED, _runtime_summary_line, app
from secfoo.cloud import CloudConfig
from secfoo.report.sarif import findings_to_sarif
from secfoo.runtime.developer import RuntimeLookup, parse_gate
from secfoo.runtime.evidence import ingest_events
from secfoo.storage.repository import RunRepository

runner = CliRunner(env={"COLUMNS": "250"})
PROJECT = "https://github.com/acme/payments"
# fingerprint -> (package, severity, static reachability, fixed_in)
FINDINGS = {
    "fp-reached": ("pyyaml", "High", "Not reachable", "5.4"),
    "fp-executed": ("jinja2", "High", "Reachable", "2.10.1"),
    "fp-loaded": ("requests", "High", "Reachable", "2.31.0"),
    "fp-quiet": ("lxml", "High", "Not reachable", "4.6.3"),
    "fp-low": ("pillow", "Low", "Reachable", "8.1.1"),
}


def _events():
    s = {"type": "session", "id": "s-1", "language": "python", "source": "sensor",
         "started_at": "2026-11-12T00:00:00Z", "ended_at": "2026-11-12T06:00:00Z",
         "app_functions_total": 100, "app_functions_executed": 74}
    return [
        s,
        {"type": "load", "session": "s-1", "ecosystem": "PyPI", "package": "requests", "version": "2.31.0"},
        {"type": "hit", "session": "s-1", "finding_fingerprint": "fp-reached", "symbol": "yaml.load",
         "route": "POST /upload", "auth": "anonymous", "count": 312, "last_seen": "2026-11-12T05:00:00Z"},
        {"type": "hit", "session": "s-1", "finding_fingerprint": "fp-executed", "symbol": "jinja2.Template.render",
         "route": "startup", "count": 2},
        {"type": "hit", "session": "s-1", "finding_fingerprint": "fp-low", "symbol": "PIL.Image.open",
         "route": "GET /avatar", "count": 5},
    ]


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.cloud.load_cloud_config", lambda *a, **k: None)  # no key unless a test adds one
    with RunRepository() as repo:
        pid = repo.upsert_project(PROJECT, "payments", "github")
        run_id = repo.get_run(repo.create_run(project_id=pid, skill_id="sca-reachability", skill_name="SCA",
                                              agent_id="claude", confluence_urls=[])).id
        for i, (fp, (package, severity, reach, fixed)) in enumerate(FINDINGS.items(), start=1):
            repo.upsert_sca_finding(project_id=pid, fingerprint=fp, run_id=run_id, current_ref=f"D{i}",
                                    package=package, severity=severity, version="1.0", ecosystem="PyPI",
                                    reachability=reach, fixed_in=fixed, issue=f"{package} issue")
    return pid


def _ingest(pid):
    with RunRepository() as repo:
        assert ingest_events(repo.connection, pid, [json.dumps(e) for e in _events()]).skipped == []


def _states(**kwargs):
    with RunRepository() as repo:
        lookup = RuntimeLookup(repo, **kwargs)
        return {row["fingerprint"]: lookup.for_finding(skill, row)
                for skill, row in repo.list_structured_findings(skill_ids=["sca-reachability"])}


# ---------- every runtime state ----------


def test_every_state_from_local_evidence(store):
    _ingest(store)
    states = _states()
    assert states["fp-reached"].state == "reached"
    assert states["fp-reached"].summary == "Reached · POST /upload (anonymous) · 312"
    assert states["fp-executed"].state == "executed"
    assert states["fp-loaded"].state == "loaded" and states["fp-loaded"].version_drift  # scanned 1.0, running 2.31.0
    assert states["fp-quiet"].state == "not_loaded"
    assert "74% coverage" in states["fp-quiet"].summary  # never "not reachable" without its coverage


def test_no_sensor_means_no_runtime_data_and_no_errors(store):
    assert {s.state for s in _states().values()} == {"none"}
    assert all(s.summary == "No runtime data" for s in _states().values())


def test_no_key_means_no_network_call(store):
    calls = []
    states = _states(fetch=lambda url, key: calls.append(url) or {})
    assert calls == [] and {s.state for s in states.values()} == {"none"}


def test_no_runtime_skips_everything(store):
    _ingest(store)
    calls = []
    states = _states(enabled=False, fetch=lambda u, k: calls.append(u) or {},
                     cloud_config=CloudConfig(api_key="sfk_x", portal_url="https://s"))
    assert calls == [] and {s.state for s in states.values()} == {"none"}


# ---------- server + offline cache ----------


SERVER = {"findings": [{"finding_fingerprint": "fp-quiet", "runtime_state": "reached",
                        "runtime_summary": "Reached · GET /export (authenticated) · 9", "hits": 9,
                        "routes": [{"route": "GET /export", "auth": "authenticated", "count": 9}]}]}


def test_server_evidence_is_fetched_with_the_key_and_cached_for_offline(store):
    config = CloudConfig(api_key="sfk_secret", portal_url="https://secfoo.internal")
    seen = []

    def online(url, key):
        seen.append((url, key))
        return SERVER

    states = _states(fetch=online, cloud_config=config)
    assert states["fp-quiet"].state == "reached" and states["fp-quiet"].source == "server"
    assert seen == [("https://secfoo.internal/api/runtime/v1/evidence?project=https%3A%2F%2Fgithub.com%2Facme%2Fpayments",
                     "sfk_secret")]

    def offline(url, key):
        raise urllib.error.URLError("no route to host")

    with RunRepository() as repo:
        lookup = RuntimeLookup(repo, fetch=offline, cloud_config=config)
        rows = {row["fingerprint"]: row for _, row in repo.list_structured_findings(skill_ids=["sca-reachability"])}
        cached = lookup.for_finding("sca-reachability", rows["fp-quiet"])
    assert cached.state == "reached" and cached.source == "cache"
    assert any("cache" in note for note in lookup.notes)


def test_stronger_of_local_and_server_wins(store):
    _ingest(store)
    weaker = {"findings": [{"finding_fingerprint": "fp-reached", "runtime_state": "loaded", "runtime_summary": "Loaded"}]}
    states = _states(fetch=lambda u, k: weaker, cloud_config=CloudConfig(api_key="k", portal_url="https://s"))
    assert states["fp-reached"].state == "reached"


# ---------- CLI: list / show ----------


def test_findings_list_shows_runtime_and_sorts_within_severity(store):
    _ingest(store)
    result = runner.invoke(app, ["findings", "list"])
    assert result.exit_code == 0, result.output
    # Order by position in the output: rich may wrap cells on a narrow CI terminal.
    order = sorted(FINDINGS, key=lambda fp: result.output.index(fp[:10]))
    assert order == ["fp-reached", "fp-executed", "fp-loaded", "fp-quiet", "fp-low"]  # High by runtime, then Low
    flat = " ".join(result.output.split())
    assert "pyyaml" in flat and "Not loaded" in flat


def test_findings_list_no_runtime(store):
    _ingest(store)
    result = runner.invoke(app, ["findings", "list", "--no-runtime"])
    assert result.exit_code == 0 and "Reached" not in result.output


def test_findings_show_gives_the_remediation_hint(store):
    _ingest(store)
    result = runner.invoke(app, ["findings", "show", "fp-reached"])
    assert result.exit_code == 0, result.output
    flat = " ".join(result.output.split())  # rich wraps long lines on narrow CI terminals
    assert "Fix first: upgrade pyyaml to 5.4; this protects live route(s): POST /upload (anonymous)" in flat


# ---------- SARIF ----------


def test_sarif_carries_runtime_properties_and_priority(store):
    _ingest(store)
    result = runner.invoke(app, ["findings", "export", "--format", "sarif", "--skill", "sca-reachability",
                                 "--runtime-priority"])
    assert result.exit_code == 0, result.output
    results = json.loads(result.stdout)["runs"][0]["results"]
    by_state = {r["properties"]["secfoo"]["runtime"]["state"]: r for r in results}
    reached = by_state["reached"]
    assert reached["properties"]["secfoo"]["runtime"]["routes"][0]["route"] == "POST /upload"
    assert "Reached in production via POST /upload" in reached["message"]["text"]
    assert reached["level"] == "error"
    assert {"reached", "executed", "loaded", "not_loaded"} <= set(by_state)


def test_runtime_priority_only_raises_reached_findings():
    records = [{"skill_id": "sca-reachability", "severity": "Low", "issue": "x", "runtime": {"state": "reached", "routes": []}},
               {"skill_id": "sca-reachability", "severity": "Low", "issue": "y", "runtime": {"state": "loaded"}}]
    levels = [r["level"] for r in findings_to_sarif(records, runtime_priority=True)["runs"][0]["results"]]
    assert levels == ["error", "note"]
    assert [r["level"] for r in findings_to_sarif(records)["runs"][0]["results"]] == ["note", "note"]


# ---------- CI gate ----------


def test_gate_trips_with_its_own_exit_code(store):
    _ingest(store)
    result = runner.invoke(app, ["findings", "check", "--fail-on", "reached:high"])
    assert result.exit_code == EXIT_RUNTIME_REACHED == 4
    assert "pyyaml" in result.output and "pillow" not in result.output  # Low is below the threshold


def test_gate_executed_level_and_severity(store):
    _ingest(store)
    assert runner.invoke(app, ["findings", "check", "--fail-on", "reached:critical"]).exit_code == 0
    tripped = runner.invoke(app, ["findings", "check", "--fail-on", "executed:high"])
    assert tripped.exit_code == 4 and "jinja2" in tripped.output
    assert runner.invoke(app, ["findings", "check", "--fail-on", "reached"]).exit_code == 4  # any severity


def test_gate_passes_without_runtime_data(store):
    assert runner.invoke(app, ["findings", "check", "--fail-on", "reached"]).exit_code == 0


@pytest.mark.parametrize("spec", ["loaded", "reached:urgent", ""])
def test_gate_spec_is_validated(spec):
    with pytest.raises(ValueError):
        parse_gate(spec)


# ---------- after secfoo run ----------


def test_run_summary_line(store):
    _ingest(store)

    class Outcome:
        def __init__(self, uuid):
            self.run_uuid = uuid

    with RunRepository() as repo:
        uuid = repo.connection.execute("SELECT run_uuid FROM runs").fetchone()[0]
    line = _runtime_summary_line([Outcome(uuid)])
    assert "2 of 5 findings are reached in production" in line and "D1 (POST /upload, anonymous)" in line


def test_run_summary_is_silent_without_runtime_data(store):
    with RunRepository() as repo:
        uuid = repo.connection.execute("SELECT run_uuid FROM runs").fetchone()[0]

    class Outcome:
        run_uuid = uuid

    assert _runtime_summary_line([Outcome()]) is None
