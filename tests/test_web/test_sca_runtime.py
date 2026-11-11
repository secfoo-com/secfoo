"""#57: runtime evidence in the SCA dashboard -- every runtime state and the conflict highlight."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from secfoo.report.sca import findings_with_fingerprints
from secfoo.runtime.evidence import ingest_events
from secfoo.storage.repository import RunRepository
from secfoo.web import sca_dashboard, sca_runtime
from secfoo.web.app import create_app

REPORT = """\
# SCA Report — Reachability & Upgrade Triage

## 1. Executive Summary
Test summary. **Overall risk rating:** High

## 2. Dependency Inventory

| Package | Version | Direct/Transitive | Ecosystem | Source manifest |
|---------|---------|--------------------|-----------|------------------|
| pyyaml | 5.3 | Direct | Python | requirements.txt |

## 4. Risk Register

| ID | Package | Version | Issue | Severity | Reachability | Fixed in |
|----|---------|---------|-------|----------|---------------|----------|
| D1 | pyyaml | 5.3 | Arbitrary code execution in full_load | High | {reachability} | 5.4 |

## 5. Detailed Findings

### [HIGH] D1: pyyaml@5.3 — code execution
- **Package / version:** pyyaml 5.3, **CVE:** unverified, **Severity:** High
- **Reachability:** {reachability}
- **Recommendation:** upgrade to 5.4
"""

SESSION = {"type": "session", "id": "s-1", "language": "python", "source": "sensor",
           "started_at": "2026-11-08T10:00:00Z", "ended_at": "2026-11-08T16:00:00Z",
           "app": "payments-api", "env": "prod", "app_functions_total": 1000, "app_functions_executed": 740}


@pytest.fixture
def store(tmp_path, monkeypatch):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.web.sca_dashboard.osv.enrich_lookups", lambda repo, keys, **kw: False)
    return tmp_path


def _seed(tmp_path, *, reachability="Not reachable", events=()):
    """One project, one SCA finding (persisted the way the runner does it),
    and optional runtime events ingested through #53's real code path."""
    text = REPORT.format(reachability=reachability)
    with RunRepository() as repo:
        pid = repo.upsert_project("https://github.com/acme/payments", "payments", "github")
        aid = repo.create_assessment(project_id=pid, assessment_type="internal", status="ready")
        run_uuid = repo.create_run(project_id=pid, skill_id="sca-reachability", skill_name="SCA",
                                   agent_id="claude", confluence_urls=[], assessment_id=aid)
        path = tmp_path / f"{run_uuid}.md"
        path.write_text(text, encoding="utf-8")
        repo.complete_run(run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(path),
                          prompt_path=None, stderr_excerpt=None, high_count=1)
        [row] = findings_with_fingerprints(text)
        repo.upsert_sca_finding(project_id=pid, fingerprint=row["fingerprint"], run_id=repo.get_run(run_uuid).id,
                                current_ref="D1", package="pyyaml", severity="High", version="5.3",
                                ecosystem="PyPI", reachability=reachability)
        if events:
            lines = [json.dumps({**e, "finding_fingerprint": row["fingerprint"]} if e["type"] == "hit" else e)
                     for e in events]
            report = ingest_events(repo.connection, pid, lines)
            assert report.skipped == [], report.skipped
    return row["fingerprint"]


def _hit(**overrides):
    return {"type": "hit", "session": "s-1", "symbol": "yaml.full_load", "count": 312,
            "last_seen": "2026-11-08T15:59:00Z", **overrides}


def _vuln():
    with RunRepository() as repo:
        [vuln] = sca_dashboard.build(repo).vulnerabilities
    return vuln


# ---------- each state of the evidence ladder ----------


def test_no_runtime_data(store):
    _seed(store)
    vuln = _vuln()
    assert vuln.runtime.state == "none" and vuln.runtime.label == "No runtime data"
    assert not vuln.runtime_conflict


def test_reached_from_traffic_shows_route_auth_and_count(store):
    _seed(store, events=[SESSION, _hit(route="POST /upload", auth="anonymous")])
    rt = _vuln().runtime
    assert rt.state == "reached"
    assert rt.summary == "Reached · POST /upload (anonymous) · 312"


def test_hits_without_request_context_are_executed(store):
    _seed(store, events=[SESSION, _hit(route="startup", count=4), _hit(route="job:nightly-import", count=9)])
    rt = _vuln().runtime
    assert rt.state == "executed" and rt.hits == 13
    assert rt.summary.startswith("Executed · 13 hits · last 2026-11-08")


def test_loaded_package_with_no_watched_call_and_version_drift(store):
    _seed(store, events=[SESSION, {"type": "load", "session": "s-1", "ecosystem": "PyPI",
                                   "package": "PyYAML", "version": "5.4.1"}])
    rt = _vuln().runtime
    assert rt.state == "loaded" and rt.loaded_versions == ["5.4.1"]
    assert rt.version_drift  # production runs 5.4.1, the scan saw 5.3


def test_not_loaded_when_the_inventory_lacks_the_package_shows_coverage(store):
    _seed(store, events=[SESSION, {"type": "load", "session": "s-1", "ecosystem": "PyPI",
                                   "package": "requests", "version": "2.31.0"}])
    rt = _vuln().runtime
    assert rt.state == "not_loaded"
    assert rt.summary == "Not loaded · 74% coverage · 6h"  # never shown without its coverage


def test_not_observed_when_sessions_have_no_inventory(store):
    _seed(store, events=[SESSION])
    rt = _vuln().runtime
    assert rt.state == "not_observed" and rt.summary == "Not observed · 74% coverage · 6h"


def test_strongest_state_wins_across_projects():
    reached, loaded = sca_runtime.RuntimeStatus(state="reached"), sca_runtime.RuntimeStatus(state="loaded")
    assert sca_runtime.strongest([loaded, reached]) is reached
    assert sca_runtime.strongest([]).state == "none"


# ---------- the conflict highlight ----------


@pytest.mark.parametrize("route", ["POST /upload", "startup"])
def test_not_reachable_but_ran_is_a_conflict(store, route):
    _seed(store, reachability="Not reachable", events=[SESSION, _hit(route=route)])
    assert _vuln().runtime_conflict


def test_reachable_and_ran_is_not_a_conflict(store):
    _seed(store, reachability="Reachable", events=[SESSION, _hit(route="POST /upload")])
    assert not _vuln().runtime_conflict


def test_not_reachable_and_only_loaded_is_not_a_conflict(store):
    _seed(store, reachability="Not reachable", events=[SESSION, {"type": "load", "session": "s-1",
                                                                  "ecosystem": "PyPI", "package": "pyyaml", "version": "5.3"}])
    assert not _vuln().runtime_conflict


# ---------- rendered pages ----------


def test_list_page_shows_runtime_column_and_highlights_the_conflict(store):
    _seed(store, events=[SESSION, _hit(route="POST /upload", auth="anonymous")])
    html = TestClient(create_app()).get("/activities/sca-reachability/vulnerabilities").text
    assert "<th>Runtime</th>" in html
    assert 'data-runtime-state="reached"' in html
    assert "Reached · POST /upload (anonymous) · 312" in html
    assert 'class="run-row runtime-conflict"' in html
    assert "Conflicts with static verdict" in html


def test_list_page_without_runtime_data_says_so_and_has_no_highlight(store):
    _seed(store)
    html = TestClient(create_app()).get("/activities/sca-reachability/vulnerabilities").text
    assert 'data-runtime-state="none"' in html and "No runtime data" in html
    assert "runtime-conflict" not in html


def test_detail_page_shows_sessions_routes_frames_and_the_conflict(store):
    _seed(store, events=[SESSION, _hit(route="POST /upload", auth="anonymous", entry_frame="app/routes/upload.py:42",
                                       stack_sample=["app/routes/upload.py:42", "app/services/parse.py:17"])])
    client = TestClient(create_app())
    key = _vuln().key
    html = client.get(f"/activities/sca-reachability/vulnerabilities/{key}").text
    assert "Runtime evidence contradicts the static verdict" in html
    assert "<code>yaml.full_load</code>" in html and "POST /upload" in html and "anonymous" in html
    assert "payments-api / prod" in html
    assert "<code>app/routes/upload.py:42</code>" in html and "app/services/parse.py:17" in html
    assert "Source: sensor" in html


def test_detail_page_not_observed_never_claims_unreachable(store):
    _seed(store, events=[SESSION])
    key = _vuln().key
    html = TestClient(create_app()).get(f"/activities/sca-reachability/vulnerabilities/{key}").text
    assert "This is not proof the code is unreachable" in html and "74%" in html


def test_overview_counts_runtime_confirmed_only_when_there_is_runtime_data(store):
    _seed(store)
    client = TestClient(create_app())
    assert 'id="runtime-confirmed"' not in client.get("/activities/sca-reachability").text

    with RunRepository() as repo:
        [finding] = repo.list_sca_findings()
        ingest_events(repo.connection, finding.project_id, [
            json.dumps(SESSION), json.dumps({**_hit(route="POST /upload"), "finding_fingerprint": finding.fingerprint}),
        ])
    html = client.get("/activities/sca-reachability").text
    assert 'id="runtime-confirmed"' in html
    assert "1 reached from traffic, 0 executed" in html
    assert '1 contradicts a static "Not reachable"' in html
