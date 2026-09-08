from __future__ import annotations

from secfoo.storage.repository import RunRepository
from secfoo.web import sca_dashboard


def _repo(tmp_path):
    return RunRepository(db_path=tmp_path / "db.sqlite")


def _report(*, rows: str, inventory: str = "") -> str:
    default_inventory = (
        "| aiohttp | 3.8.0 | Direct | Python | requirements.txt |\n"
        "| @babel/core | 7.0.0 | Direct | Node.js | package.json |\n"
        "| some-alpine-pkg | 1.0.0 | Direct | Alpine | Dockerfile |\n"
    )
    return f"""\
# SCA Report — Reachability & Upgrade Triage

## 1. Executive Summary
Test summary. **Overall risk rating:** High

## 2. Dependency Inventory

| Package | Version | Direct/Transitive | Ecosystem | Source manifest |
|---------|---------|--------------------|-----------|------------------|
{inventory or default_inventory}
## 4. Risk Register

| ID | Package | Version | Issue | Severity | Reachability | Fixed in |
|----|---------|---------|-------|----------|---------------|----------|
{rows}
## 5. Detailed Findings

### [HIGH] D1: placeholder
- **Package / version:** x, **CVE:** unverified, **Severity:** High
"""


def _seed(tmp_path, repo, *, project_name, report_text, skill_id="sca-reachability"):
    project_id = repo.upsert_project(f"https://github.com/{project_name}", project_name, "github")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id=skill_id, skill_name=skill_id,
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    report_path = tmp_path / f"{run_uuid}.md"
    report_path.write_text(report_text)
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None, high_count=1,
    )
    return project_id, run_uuid


def _no_op_enrich(monkeypatch, *, returns=False):
    """Prevents real network calls in unit tests -- the OSV client itself
    is already covered by tests/test_osv.py's mocked-HTTP tests.
    """
    calls = []

    def _fake(repo, keys, **kwargs):
        calls.append(list(keys))
        return returns

    monkeypatch.setattr("secfoo.web.sca_dashboard.osv.enrich_lookups", _fake)
    return calls


def test_build_empty_state(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch)
    repo = _repo(tmp_path)
    dash = sca_dashboard.build(repo)
    assert dash.coverage_in_scope == 0
    assert dash.vulnerabilities == []
    assert dash.severity_counts == {"high": 0, "medium": 0, "low": 0}
    repo.close()


def test_build_llm_only_finding_when_no_osv_match(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch)  # cache stays empty -- no OSV match possible
    repo = _repo(tmp_path)
    report = _report(rows="| D1 | aiohttp | 3.8.0 | Invalid IPv6 URL DoS class issue | High | Reachable | 3.8.1 |\n")
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = sca_dashboard.build(repo)
    assert len(dash.vulnerabilities) == 1
    vuln = dash.vulnerabilities[0]
    assert vuln.cve_id is None
    assert vuln.is_llm_reported is True
    assert vuln.package == "aiohttp"
    assert vuln.ecosystem_raw == "Python"
    assert vuln.ecosystem_osv == "PyPI"
    assert len(vuln.affected_projects) == 1
    repo.close()


def test_build_dedupes_same_cve_across_two_projects(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch)
    repo = _repo(tmp_path)
    repo.upsert_osv_lookup(
        ecosystem="PyPI", package="aiohttp", version="3.8.0",
        vulns=[{"id": "CVE-2022-33124", "summary": "Invalid IPv6 URL DoS", "published": "2022-06-23"}],
    )
    report = _report(rows="| D1 | aiohttp | 3.8.0 | Invalid IPv6 URL DoS class issue | Medium | Conditionally reachable | 3.8.1 |\n")
    _seed(tmp_path, repo, project_name="acme/app-a", report_text=report)
    _seed(tmp_path, repo, project_name="acme/app-b", report_text=report)

    dash = sca_dashboard.build(repo)
    assert len(dash.vulnerabilities) == 1
    vuln = dash.vulnerabilities[0]
    assert vuln.cve_id == "CVE-2022-33124"
    assert vuln.osv_summary == "Invalid IPv6 URL DoS"
    assert vuln.osv_published == "2022-06-23"
    assert vuln.is_llm_reported is False
    assert {p["project_display_name"] for p in vuln.affected_projects} == {"acme/app-a", "acme/app-b"}
    repo.close()


def test_build_aggregates_worst_case_severity_and_reachability(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch)
    repo = _repo(tmp_path)
    repo.upsert_osv_lookup(
        ecosystem="PyPI", package="aiohttp", version="3.8.0", vulns=[{"id": "CVE-2022-33124"}],
    )
    low_report = _report(rows="| D1 | aiohttp | 3.8.0 | issue | Low | Not reachable | 3.8.1 |\n")
    high_report = _report(rows="| D1 | aiohttp | 3.8.0 | issue | High | Reachable | 3.8.1 |\n")
    _seed(tmp_path, repo, project_name="acme/quiet-app", report_text=low_report)
    _seed(tmp_path, repo, project_name="acme/exposed-app", report_text=high_report)

    dash = sca_dashboard.build(repo)
    assert len(dash.vulnerabilities) == 1
    vuln = dash.vulnerabilities[0]
    # Row-level aggregate is the WORST observed, not the last-seen.
    assert vuln.severity == "High"
    assert vuln.reachability == "Reachable"
    # But the true per-project truth is preserved.
    by_project = {p["project_display_name"]: p for p in vuln.affected_projects}
    assert by_project["acme/quiet-app"]["severity"] == "Low"
    assert by_project["acme/exposed-app"]["severity"] == "High"
    repo.close()


def test_build_unmapped_ecosystem_never_triggers_a_lookup(tmp_path, monkeypatch):
    calls = _no_op_enrich(monkeypatch)
    repo = _repo(tmp_path)
    report = _report(rows="| D1 | some-alpine-pkg | 1.0.0 | issue | Medium | Reachable | unknown |\n")
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = sca_dashboard.build(repo)
    assert dash.unmapped_ecosystem_count == 1
    assert dash.vulnerabilities[0].ecosystem_osv is None
    assert dash.vulnerabilities[0].cve_id is None
    # "Alpine" never normalizes -- must never be handed to enrich_lookups.
    assert all(("Alpine", "some-alpine-pkg", "1.0.0") not in call for call in calls)
    repo.close()


def test_build_row_whose_package_is_missing_from_inventory_has_unknown_ecosystem(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch)
    repo = _repo(tmp_path)
    report = _report(
        rows="| D1 | ghost-package | 9.9.9 | issue not in inventory | Low | Not reachable | unknown |\n",
        inventory="| aiohttp | 3.8.0 | Direct | Python | requirements.txt |\n",
    )
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = sca_dashboard.build(repo)
    assert dash.unmapped_ecosystem_count == 1
    assert dash.vulnerabilities[0].ecosystem_raw is None
    repo.close()


def test_build_surfaces_osv_unreachable_flag(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch, returns=True)
    repo = _repo(tmp_path)
    report = _report(rows="| D1 | aiohttp | 3.8.0 | issue | High | Reachable | 3.8.1 |\n")
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = sca_dashboard.build(repo)
    assert dash.osv_unreachable is True
    repo.close()


def test_build_severity_reachability_and_ecosystem_counts(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch)
    repo = _repo(tmp_path)
    report = _report(
        rows=(
            "| D1 | aiohttp | 3.8.0 | issue a | High | Reachable | 3.8.1 |\n"
            "| D2 | @babel/core | 7.0.0 | issue b | Medium | Conditionally reachable | 7.0.1 |\n"
        )
    )
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = sca_dashboard.build(repo)
    assert dash.severity_counts == {"high": 1, "medium": 1, "low": 0}
    assert dash.reachability_counts["reachable"] == 1
    assert dash.reachability_counts["conditionally_reachable"] == 1
    ecosystems = dict(dash.ecosystem_counts)
    assert ecosystems["Python"] == 1
    assert ecosystems["Node.js"] == 1
    repo.close()


def test_build_computes_coverage(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch)
    repo = _repo(tmp_path)
    unreviewed = repo.upsert_project("https://github.com/acme/other", "acme/other", "github")
    repo.create_assessment(project_id=unreviewed, assessment_type="internal", status="ready")

    report = _report(rows="| D1 | aiohttp | 3.8.0 | issue | High | Reachable | 3.8.1 |\n")
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = sca_dashboard.build(repo)
    assert dash.coverage_reviewed == 1
    assert dash.coverage_in_scope == 2
    assert dash.coverage_pct == 50.0
    repo.close()


def test_build_vulnerabilities_by_key_matches_the_list(tmp_path, monkeypatch):
    _no_op_enrich(monkeypatch)
    repo = _repo(tmp_path)
    report = _report(rows="| D1 | aiohttp | 3.8.0 | issue | High | Reachable | 3.8.1 |\n")
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = sca_dashboard.build(repo)
    assert len(dash.vulnerabilities) == 1
    vuln = dash.vulnerabilities[0]
    assert dash.vulnerabilities_by_key[vuln.key] is vuln
    repo.close()
