from __future__ import annotations

from secfoo.storage.repository import RunRepository
from secfoo.web import sast_dashboard


def _repo(tmp_path):
    return RunRepository(db_path=tmp_path / "db.sqlite")


def _seed_run(repo, project_id):
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[]
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )
    return repo.get_run(run_uuid).id


def _seed_finding(repo, *, project_id, run_id, fingerprint, **overrides):
    fields = {
        "current_ref": "F1",
        "title": "SQL Injection",
        "severity": "High",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "verdict": "Confirmed",
        "location_file": "app/db.py",
        "location_line": "42",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.1,
    }
    fields.update(overrides)
    repo.upsert_sast_finding(project_id=project_id, fingerprint=fingerprint, run_id=run_id, **fields)


def test_build_empty_state(tmp_path):
    repo = _repo(tmp_path)
    dash = sast_dashboard.build(repo)
    assert dash.open_findings == []
    assert dash.closed_findings == []
    assert dash.funnel == {"findings": 0, "exploitable": 0, "verified": 0, "severe": 0}
    assert dash.cvss_band_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    repo.close()


def test_build_only_counts_open_findings_in_the_funnel(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_id = _seed_run(repo, project_id)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-open")
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-closed")
    repo.close_stale_sast_findings(
        project_id=project_id, run_id=run_id, seen_fingerprints=["fp-open"], closed_at="2026-08-22T00:00:00Z"
    )

    dash = sast_dashboard.build(repo)
    assert dash.funnel["findings"] == 1
    assert len(dash.open_findings) == 1
    assert len(dash.closed_findings) == 1
    assert dash.open_findings[0].fingerprint == "fp-open"
    assert dash.closed_findings[0].fingerprint == "fp-closed"
    repo.close()


def test_build_verified_maps_to_confirmed_verdict(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_id = _seed_run(repo, project_id)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-1", verdict="Confirmed")
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-2", verdict="Conditional")

    dash = sast_dashboard.build(repo)
    assert dash.funnel["findings"] == 2
    assert dash.funnel["verified"] == 1


def test_build_exploitable_excludes_latent_verdicts(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_id = _seed_run(repo, project_id)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-1", verdict="Confirmed")
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-2", verdict="Latent")

    dash = sast_dashboard.build(repo)
    assert dash.funnel["exploitable"] == 1


def test_build_severe_counts_high_and_critical_cvss_bands(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_id = _seed_run(repo, project_id)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-critical", cvss_score=9.8)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-high", cvss_score=7.5)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-medium", cvss_score=5.0)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-low", cvss_score=2.0)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-none", cvss_score=None)

    dash = sast_dashboard.build(repo)
    assert dash.funnel["severe"] == 2
    assert dash.cvss_band_counts == {"critical": 1, "high": 1, "medium": 1, "low": 1, "none": 1}


def test_build_top_cwe_counts_excludes_unverified(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_id = _seed_run(repo, project_id)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-1", cwe="CWE-89")
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-2", cwe="CWE-89")
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-3", cwe="CWE-79")
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-4", cwe="unverified")

    dash = sast_dashboard.build(repo)
    assert dash.top_cwe_counts == [("CWE-89", 2), ("CWE-79", 1)]


def test_build_open_findings_by_key_matches_the_list(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("id-1", "P1", "local")
    run_id = _seed_run(repo, project_id)
    _seed_finding(repo, project_id=project_id, run_id=run_id, fingerprint="fp-1")

    dash = sast_dashboard.build(repo)
    assert len(dash.open_findings) == 1
    finding = dash.open_findings[0]
    assert dash.open_findings_by_key[finding.fingerprint] is finding
