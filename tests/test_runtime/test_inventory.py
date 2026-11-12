"""#68: runtime package inventory -- drift, unscanned dependencies, never loaded, real-time advisories."""
from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from secfoo.cli import app
from secfoo.report.sca import findings_with_fingerprints
from secfoo.runtime.evidence import ingest_events
from secfoo.runtime.inventory import analyze, cyclonedx, recheck
from secfoo.storage.repository import RunRepository
from secfoo.web import sca_runtime

REPORT = """\
# SCA Report — Reachability & Upgrade Triage

## 1. Executive Summary
Test. **Overall risk rating:** High

## 2. Dependency Inventory

| Package | Version | Direct/Transitive | Ecosystem | Source manifest |
|---------|---------|--------------------|-----------|------------------|
| pyyaml | 5.3 | Direct | Python | requirements.txt |
| requests | 2.19.0 | Direct | Python | requirements.txt |
| lxml | 4.6.2 | Direct | Python | requirements.txt |

## 4. Risk Register

| ID | Package | Version | Issue | Severity | Reachability | Fixed in |
|----|---------|---------|-------|----------|---------------|----------|
| D1 | pyyaml | 5.3 | Code execution in full_load | High | Not reachable | 5.4 |
| D2 | lxml | 4.6.2 | XSS in clean | Medium | Reachable | 4.6.3 |

## 5. Detailed Findings

### [HIGH] D1: pyyaml
- **Package / version:** pyyaml 5.3, **CVE:** GHSA-8q59-q68h-6hv4, **Severity:** High
### [MEDIUM] D2: lxml
- **Package / version:** lxml 4.6.2, **CVE:** unverified, **Severity:** Medium
"""

EVENTS = [
    {"type": "session", "id": "s-1", "language": "python", "source": "sensor", "app": "payments-api", "env": "prod",
     "started_at": "2026-11-10T00:00:00Z", "ended_at": "2026-11-12T00:00:00Z"},
    {"type": "load", "session": "s-1", "ecosystem": "PyPI", "package": "pyyaml", "version": "5.3",
     "first_seen": "2026-11-10T00:00:01Z"},                       # case 1: scanned version
    {"type": "load", "session": "s-1", "ecosystem": "PyPI", "package": "requests", "version": "2.31.0",
     "first_seen": "2026-11-10T00:00:01Z"},                       # case 2: drift
    {"type": "load", "session": "s-1", "ecosystem": "PyPI", "package": "left-pad-py", "version": "1.0",
     "first_seen": "2026-11-11T06:00:00Z"},                       # case 3: unscanned, and new after the 24h baseline
]
# Fixture OSV responses (already in the cache, as the dashboard/runner would leave them).
OSV = {
    ("PyPI", "pyyaml", "5.3"): [{"id": "GHSA-8q59-q68h-6hv4"}],
    ("PyPI", "requests", "2.31.0"): [{"id": "PYSEC-2024-1", "aliases": ["GHSA-drft-0000-0000"]}],
    ("PyPI", "left-pad-py", "1.0"): [{"id": "GHSA-unsc-0000-0000"}],
}


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    with RunRepository() as repo:
        pid = repo.upsert_project("https://github.com/acme/payments", "payments", "github")
        aid = repo.create_assessment(project_id=pid, assessment_type="internal", status="ready")
        uuid = repo.create_run(project_id=pid, skill_id="sca-reachability", skill_name="SCA", agent_id="claude",
                               confluence_urls=[], assessment_id=aid)
        path = tmp_path / "sca.md"
        path.write_text(REPORT, encoding="utf-8")
        repo.complete_run(uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(path),
                          prompt_path=None, stderr_excerpt=None, high_count=1)
        run_id = repo.get_run(uuid).id
        for row in findings_with_fingerprints(REPORT):
            repo.upsert_sca_finding(project_id=pid, fingerprint=row["fingerprint"], run_id=run_id,
                                    current_ref=row["id"], package=row["package"], severity=row["severity"],
                                    version=row["version"], ecosystem="PyPI", reachability=row["reachability"],
                                    cve=row["cve"])
        for (eco, pkg, ver), vulns in OSV.items():
            repo.upsert_osv_lookup(ecosystem=eco, package=pkg, version=ver, vulns=vulns)
        assert ingest_events(repo.connection, pid, [json.dumps(e) for e in EVENTS]).skipped == []
    return pid


def _by_name(report):
    return {p.package: p for p in report.packages}


def test_case_1_vulnerable_package_loaded_at_the_scanned_version(project):
    with RunRepository() as repo:
        report = analyze(repo, project)
        pyyaml = _by_name(report)["pyyaml"]
        assert pyyaml.status == "scanned" and not pyyaml.new
        # The SCA finding shows Loaded, and its known advisory raises nothing new.
        finding = next(f for f in repo.list_sca_findings(project_id=project) if f.package == "pyyaml")
        status = sca_runtime.status_for(repo.connection, project_id=project, fingerprint=finding.fingerprint,
                                        package="pyyaml", ecosystem="PyPI", scanned_version="5.3")
    assert status.state == "loaded" and not status.version_drift
    assert not [r for r in report.raised if r["package"] == "pyyaml"]


def test_case_2_version_drift_is_checked_against_osv(project):
    with RunRepository() as repo:
        report = analyze(repo, project)
    requests = _by_name(report)["requests"]
    assert requests.status == "drift" and requests.scanned_versions == ["2.19.0"]
    assert requests.advisories == ["GHSA-drft-0000-0000"]  # GHSA alias preferred
    [raised] = [r for r in report.raised if r["package"] == "requests"]
    assert raised["kind"] == "drift" and raised["apps"] == ["payments-api/prod"]


def test_case_3_unscanned_dependency_raises_a_runtime_finding(project):
    with RunRepository() as repo:
        report = analyze(repo, project)
        rows = [tuple(r) for r in repo.connection.execute(
            "SELECT kind, package, version, advisory FROM runtime_findings ORDER BY kind")]
    leftpad = _by_name(report)["left-pad-py"]
    assert leftpad.status == "unscanned" and leftpad.new  # first seen 30h in, after the 24h baseline
    assert ("unscanned", "left-pad-py", "1.0", "GHSA-unsc-0000-0000") in rows


def test_case_4_vulnerable_package_never_loaded_shows_the_window(project):
    with RunRepository() as repo:
        report = analyze(repo, project)
    assert [f["package"] for f in report.not_loaded] == ["lxml"]
    assert report.observed_hours == 48


def test_analysis_is_idempotent(project):
    with RunRepository() as repo:
        analyze(repo, project)
        analyze(repo, project)
        assert repo.connection.execute("SELECT COUNT(*) FROM runtime_findings").fetchone()[0] == 2


def test_recheck_finds_a_newly_published_advisory_against_a_running_version(project):
    def query_batch(keys):
        published = {("PyPI", "pyyaml", "5.3"): [{"id": "GHSA-8q59-q68h-6hv4"}, {"id": "GHSA-new0-0000-0000"}]}
        return [published.get(k, OSV.get(k, [])) for k in keys]

    with RunRepository() as repo:
        raised = recheck(repo, project_id=project, query_batch=query_batch)
        cached = repo.osv_lookup_map()[("PyPI", "pyyaml", "5.3")].vulns
    new = [r for r in raised if r["kind"] == "new_advisory"]
    assert [(r["package"], r["advisory"]) for r in new] == [("pyyaml", "GHSA-new0-0000-0000")]
    assert {"id": "GHSA-new0-0000-0000"} in cached


def test_recheck_without_runtime_data_makes_no_request(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    with RunRepository() as repo:
        assert recheck(repo, query_batch=lambda keys: pytest.fail("no runtime data, no OSV call")) == []


def test_cyclonedx_runtime_sbom(project):
    with RunRepository() as repo:
        bom = cyclonedx(analyze(repo, project, app="payments-api", env="prod"),
                        project="https://github.com/acme/payments", app="payments-api", env="prod")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    purls = {c["purl"] for c in bom["components"]}
    assert {"pkg:pypi/pyyaml@5.3", "pkg:pypi/requests@2.31.0", "pkg:pypi/left-pad-py@1.0"} == purls
    statuses = {c["name"]: c["properties"][0]["value"] for c in bom["components"]}
    assert statuses == {"pyyaml": "scanned", "requests": "drift", "left-pad-py": "unscanned"}


def test_cli_inventory_table_json_and_cyclonedx(project, tmp_path):
    runner = CliRunner(env={"COLUMNS": "250"})
    table = runner.invoke(app, ["runtime", "inventory", "--project", "payments"])
    assert table.exit_code == 0, table.output
    flat = " ".join(table.output.split())
    assert "drift" in flat and "2.19.0" in flat and "unscanned" in flat and "Not loaded" in flat
    as_json = json.loads(runner.invoke(app, ["runtime", "inventory", "--project", "payments", "--format", "json"]).stdout)
    assert {p["package"]: p["status"] for p in as_json["packages"]}["requests"] == "drift"
    out = tmp_path / "sbom.json"
    sbom = runner.invoke(app, ["runtime", "inventory", "--project", "payments", "--format", "cyclonedx", "-o", str(out)])
    assert sbom.exit_code == 0 and json.loads(out.read_text())["bomFormat"] == "CycloneDX"
