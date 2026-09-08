from __future__ import annotations

from secfoo.storage.repository import RunRepository
from secfoo.web import third_party_dashboard

_REPORT_WITH_CCM = """\
# Third-Party Risk Assessment Report

## 1. Executive Summary
Test summary. **Overall risk rating:** Medium

## 3. CCM Domain Conformance
| Domain | Code | Conformance | Evidence |
|--------|------|--------------|----------|
| Audit & Assurance | A&A | Conformant | soc2.pdf section 3 |
| Application & Interface Security | AIS | Partial | soc2.pdf section 5 |
| Identity & Access Management | IAM | Not Assessed (no evidence provided) | -- |
"""


def _repo(tmp_path):
    return RunRepository(db_path=tmp_path / "db.sqlite")


def _seed(tmp_path, repo, *, project_name, report_text, status="success"):
    project_id = repo.upsert_project(f"https://github.com/{project_name}", project_name, "github")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="third_party", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id=third_party_dashboard.SKILL_ID, skill_name="Third-Party Risk Assessment",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    report_path = tmp_path / f"{run_uuid}.md"
    report_path.write_text(report_text)
    repo.complete_run(
        run_uuid, status=status, exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )
    return assessment_id


def test_build_empty_state(tmp_path):
    repo = _repo(tmp_path)
    dash = third_party_dashboard.build(repo)
    assert dash.assessed_vendor_count == 0
    assert len(dash.ccm_rows) == 17
    assert all(row["hatched"] for row in dash.ccm_rows)
    assert len(dash.uncovered_ccm_domains) == 17
    repo.close()


def test_build_aggregates_ccm_conformance_from_a_real_run(tmp_path):
    repo = _repo(tmp_path)
    _seed(tmp_path, repo, project_name="acme/vendor-a", report_text=_REPORT_WITH_CCM)

    dash = third_party_dashboard.build(repo)
    assert dash.assessed_vendor_count == 1
    by_code = {row["code"]: row for row in dash.ccm_rows}
    assert by_code["A&A"]["score"] == 100
    assert by_code["A&A"]["hatched"] is False
    assert by_code["AIS"]["score"] == 50
    # "Not Assessed" contributes no score -- IAM stays hatched.
    assert by_code["IAM"]["hatched"] is True
    # A domain no vendor assessment mentioned at all also stays hatched.
    assert by_code["BCR"]["hatched"] is True
    assert "Identity & Access Management" in dash.uncovered_ccm_domains
    assert "Audit & Assurance" not in dash.uncovered_ccm_domains
    repo.close()


def test_build_averages_across_multiple_vendors(tmp_path):
    repo = _repo(tmp_path)
    strong_report = _REPORT_WITH_CCM.replace("A&A | Conformant", "A&A | Conformant")
    weak_report = _REPORT_WITH_CCM.replace(
        "| Audit & Assurance | A&A | Conformant | soc2.pdf section 3 |",
        "| Audit & Assurance | A&A | Non-conformant | pentest.pdf finding 2 |",
    )
    _seed(tmp_path, repo, project_name="acme/vendor-a", report_text=strong_report)
    _seed(tmp_path, repo, project_name="acme/vendor-b", report_text=weak_report)

    dash = third_party_dashboard.build(repo)
    assert dash.assessed_vendor_count == 2
    by_code = {row["code"]: row for row in dash.ccm_rows}
    # Conformant (100) averaged with Non-conformant (0) -> 50.
    assert by_code["A&A"]["score"] == 50
    repo.close()


def test_build_ignores_assessments_with_no_successful_run(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("https://github.com/acme/pending", "acme/pending", "github")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="third_party", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id=third_party_dashboard.SKILL_ID, skill_name="Third-Party Risk Assessment",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    repo.complete_run(
        run_uuid, status="failed", exit_code=1, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt="boom",
    )

    dash = third_party_dashboard.build(repo)
    assert dash.assessed_vendor_count == 0
    repo.close()


def test_build_ignores_internal_assessments(tmp_path):
    repo = _repo(tmp_path)
    project_id = repo.upsert_project("https://github.com/acme/internal-app", "acme/internal-app", "github")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id=third_party_dashboard.SKILL_ID, skill_name="Third-Party Risk Assessment",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    report_path = tmp_path / "r.md"
    report_path.write_text(_REPORT_WITH_CCM)
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )

    dash = third_party_dashboard.build(repo)
    assert dash.assessed_vendor_count == 0
    repo.close()
