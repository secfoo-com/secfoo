from __future__ import annotations

from secfoo.storage.repository import RunRepository
from secfoo.web.top_findings import build_top_findings

_THIRD_PARTY_REPORT = """\
# Third-Party Risk Assessment Report

## 4. Findings
| ID | Finding | Severity | CCM Domain | Evidence |
|----|---------|----------|------------|----------|
| V1 | No vulnerability testing evidence | High | TVM | none provided |
| V2 | Minor documentation gap | Low | HRS | none provided |
"""

_THREAT_MODEL_REPORT = """\
# Threat Model Report

## 6. Threat Register
| ID | Threat | Archetype | Asset Class | Boundary | STRIDE | Severity | Disposition | Test Reference |
|----|--------|-----------|-------------|----------|--------|----------|--------------|-----------------|
| T1 | Unauthenticated internal call | Unauthenticated internal service call | Process | B1 | E | High | Gap | none |
| T2 | Mitigated spoofing risk | Spoofed identity | Process | B2 | S | High | Mitigated | test-1 |
| T3 | Low severity gap | Info disclosure | Data | B3 | I | Low | Gap | none |
"""


def _repo(tmp_path):
    return RunRepository(db_path=tmp_path / "db.sqlite")


def test_build_top_findings_empty_state(tmp_path):
    repo = _repo(tmp_path)
    assert build_top_findings(repo) == []
    repo.close()


def test_build_top_findings_includes_third_party_high_severity_only(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("https://github.com/acme/vendor", "acme/vendor", "github")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="third_party", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="third-party-risk-assessment", skill_name="Third-Party Risk Assessment",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    report_path = tmp_path / "report.md"
    report_path.write_text(_THIRD_PARTY_REPORT)
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )

    findings = build_top_findings(repo)
    assert len(findings) == 1
    assert findings[0].source == "Third-Party"
    assert findings[0].title == "No vulnerability testing evidence"
    assert findings[0].severity == "high"
    assert findings[0].url == f"/assessments/{assessment_id}"
    repo.close()


def test_build_top_findings_includes_threat_modeling_gaps_only(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="threat-modeling", skill_name="Threat Modeling",
        agent_id="claude", confluence_urls=[],
    )
    report_path = tmp_path / "tm-report.md"
    report_path.write_text(_THREAT_MODEL_REPORT)
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )

    findings = build_top_findings(repo)
    # T1 (High/Gap) included; T2 (High but Mitigated) excluded; T3 (Gap but Low) excluded.
    assert len(findings) == 1
    assert findings[0].source == "Threat Modeling"
    assert findings[0].title == "Unauthenticated internal call"
    assert findings[0].url == f"/runs/{run_uuid}"
    repo.close()


def test_build_top_findings_includes_secret_scanning_high_severity_only(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="secret-scanning", skill_name="Secret Scanning",
        agent_id="claude", confluence_urls=[],
    )
    report_path = tmp_path / "secrets-report.md"
    report_path.write_text(
        "# Secret Scanning Report\n\n## 3. Findings Register\n"
        "| ID | Secret type | Location | Source | Validity | Severity |\n"
        "|----|-------------|----------|--------|----------|----------|\n"
        "| S1 | AWS access key | `a.yml:1` | config | Looks live | High |\n"
        "| S2 | Old placeholder | `b.py:1` | code | Placeholder | Low |\n"
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )

    findings = build_top_findings(repo)
    assert len(findings) == 1
    assert findings[0].source == "Secret Scanning"
    assert findings[0].title == "AWS access key in a.yml:1"
    assert findings[0].detail == "Looks live"
    repo.close()


def test_build_top_findings_includes_past_due_exceptions_only(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    repo.create_exception(
        project_id=project_id, title="Legacy TLS 1.0 allowed", justification="vendor constraint",
        granted_by="secops", expires_at="2000-01-01T00:00:00+00:00",
    )
    repo.create_exception(
        project_id=project_id, title="Still valid waiver", justification="x",
        granted_by="secops", expires_at="2099-01-01T00:00:00+00:00",
    )

    findings = build_top_findings(repo)
    assert len(findings) == 1
    assert findings[0].source == "Architecture"
    assert "Legacy TLS 1.0 allowed" in findings[0].title
    assert findings[0].url == f"/projects/{project_id}"
    repo.close()


def test_build_top_findings_sorts_critical_before_high(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    run_id = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        run_id, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )
    numeric_run_id = repo.get_run(run_id).id
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint="fp-high", run_id=numeric_run_id, current_ref="F1",
        title="High severity finding", severity="High", cwe="CWE-89", owasp="A03:2021", verdict="Confirmed",
        location_file="app.py", location_line="1", cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=7.5,
    )
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint="fp-critical", run_id=numeric_run_id, current_ref="F2",
        title="Critical severity finding", severity="High", cwe="CWE-89", owasp="A03:2021", verdict="Confirmed",
        location_file="app.py", location_line="2", cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
    )

    findings = build_top_findings(repo)
    assert [f.severity for f in findings] == ["critical", "high"]
    assert findings[0].title == "Critical severity finding"
    repo.close()


def test_build_top_findings_respects_limit(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    for i in range(20):
        repo.create_exception(
            project_id=project_id, title=f"Waiver {i}", justification="x",
            granted_by="secops", expires_at="2000-01-01T00:00:00+00:00",
        )

    findings = build_top_findings(repo, limit=5)
    assert len(findings) == 5
    repo.close()
