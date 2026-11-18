"""End-to-end tests for the Responsible AI chain, driven by real-shaped reports.

The chain a user hits: `secfoo run --skill responsible-ai-compliance`
auto-creates an assessment, the agent's report is parsed, and the rating
reaches the dashboard, the assessment pages, the CLI and the `--json`
document. The older unit tests used a four-line report that said "High",
which is how a Low rating rendering as "moderate" went unnoticed.

The fixtures under tests/fixtures/reports/ have the shape the output
contract requires (summary with rating, findings register, `### [Sev] Fn:`
headings, coverage notes), one per rating tier.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from secfoo.cli import app
from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app
from typer.testing import CliRunner

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "reports"
SKILL_ID = "responsible-ai-compliance"

# fixture file, report rating, risk tier, risk badge class, severity counts
TIERS = {
    "low": ("responsible-ai-compliance.md", "low-risk", "badge--success", (0, 0, 0, 6, 0)),
    "medium": ("responsible-ai-compliance-medium.md", "moderate", "badge--warning", (0, 0, 2, 4, 0)),
    "high": ("responsible-ai-compliance-high.md", "high-risk", "badge--error", (0, 2, 2, 2, 0)),
    "critical": ("responsible-ai-compliance-critical.md", "high-risk", "badge--error", (1, 2, 2, 1, 0)),
}

cli_runner = CliRunner()


def _report(tier: str) -> str:
    return (FIXTURE_DIR / TIERS[tier][0]).read_text(encoding="utf-8")


@pytest.fixture
def target_dir(tmp_path, monkeypatch) -> Path:
    """An isolated store plus a local directory to run the skill against."""
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.runner.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.runner.run_dir", lambda run_uuid: tmp_path / "reports" / run_uuid)
    monkeypatch.setattr("secfoo.config.ATTACHMENTS_DIR", tmp_path / "attachments")
    # Never sync a developer's real portal login from inside a test.
    monkeypatch.setattr("secfoo.runner._try_cloud_sync", lambda repo, run_uuid: None)
    target = tmp_path / "openai-quickstart-python"
    target.mkdir()
    return target


@pytest.fixture
def client(target_dir) -> TestClient:
    return TestClient(create_app())


def _run_skill(fake_popen, target_dir: Path, *, tier: str | None = None, extra: list[str] | None = None, **popen):
    """`secfoo run --skill responsible-ai-compliance --json`, with the
    agent's stdout replaced by a fixture report (or a failure)."""
    if tier is not None:
        popen = {"returncode": 0, "stdout": _report(tier)}
    fake_popen(**popen)
    args = ["run", "--skill", SKILL_ID, "--agent", "claude", "--target", str(target_dir), "--json", *(extra or [])]
    return cli_runner.invoke(app, args)


def _all_assessments() -> list:
    with RunRepository() as repo:
        return repo.list_assessments(limit=500)


def _show(assessment_id: int) -> str:
    result = cli_runner.invoke(app, ["assessment", "show", str(assessment_id)])
    assert result.exit_code == 0, result.output
    return " ".join(result.stdout.split())


def _stat(html: str, label: str) -> str:
    """The number printed on the stat card with this label."""
    stripped = re.sub(r'<details class="info-tip\b.*?</details>', "", html, flags=re.DOTALL)
    match = re.search(
        rf'stat-card__value[^"]*">\s*([^<\s]+)\s*</span>\s*<span class="stat-card__label[^"]*">\s*{re.escape(label)}\s*<',
        stripped,
        re.DOTALL,
    )
    assert match, f"no stat card labelled {label!r}"
    return match.group(1)


def _create_assessment_for(target_dir: Path) -> int:
    result = cli_runner.invoke(
        app, ["assessment", "create", "--project", str(target_dir), "--type", "internal"]
    )
    assert result.exit_code == 0, result.output
    return _all_assessments()[0].id


# ---------- the CLI chain ----------


@pytest.mark.parametrize("tier", list(TIERS))
def test_run_auto_creates_an_assessment_with_the_right_rating(fake_popen, target_dir, tier):
    _, risk, _, (critical, high, medium, low, info) = TIERS[tier]

    result = _run_skill(fake_popen, target_dir, tier=tier)

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    [run] = document["runs"]
    assert run["skill_id"] == SKILL_ID
    assert run["status"] == "success"
    assert run["severity"] == {"critical": critical, "high": high, "medium": medium, "low": low, "info": info}

    [assessment] = _all_assessments()
    assert assessment.responsible_ai_risk == risk
    assert assessment.responsible_ai_status == "provisional"
    assert (assessment.critical_count, assessment.high_count, assessment.medium_count, assessment.low_count) == (
        critical, high, medium, low,
    )
    assert f"Responsible AI: {risk} (provisional)" in _show(assessment.id)


def test_each_rating_gets_its_own_tier(fake_popen, target_dir):
    """The regression behind this suite: a mapping that collapses the
    ratings to one tier must fail here, not in a manual run."""
    seen = {}
    for tier in TIERS:
        # A fresh target per tier so each run auto-creates its own assessment.
        tier_target = target_dir / tier
        tier_target.mkdir()
        assert _run_skill(fake_popen, tier_target, tier=tier).exit_code == 0
    for assessment in _all_assessments():
        seen[assessment.project_display_name] = assessment.responsible_ai_risk

    assert seen == {tier: TIERS[tier][1] for tier in TIERS}
    assert len(set(seen.values())) == 3


def test_overall_rating_is_independent_of_worst_finding(fake_popen, target_dir):
    """Tier must come from `**Overall risk rating:**`, not from the worst finding."""
    stdout = (FIXTURE_DIR / "responsible-ai-compliance-medium-with-high-finding.md").read_text(encoding="utf-8")
    result = _run_skill(fake_popen, target_dir, returncode=0, stdout=stdout)

    assert result.exit_code == 0, result.output
    [run] = json.loads(result.stdout)["runs"]
    assert run["severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 4, "info": 0}

    [assessment] = _all_assessments()
    assert assessment.high_count == 1
    assert assessment.responsible_ai_risk == "moderate"
    assert "Responsible AI: moderate (provisional)" in _show(assessment.id)


def test_assessment_list_shows_the_auto_created_case_file_with_its_findings(fake_popen, target_dir):
    assert _run_skill(fake_popen, target_dir, tier="low").exit_code == 0
    unrated_target = target_dir / "unrated-app"
    unrated_target.mkdir()
    _create_assessment_for(unrated_target)

    # Wide enough that rich does not wrap the table cells.
    result = cli_runner.invoke(app, ["assessment", "list"], env={"COLUMNS": "240"})

    assert result.exit_code == 0, result.output
    flat = " ".join(result.stdout.split())
    assert "Responsible AI" in flat
    assert "openai-quickstart-python" in flat
    assert "0C 0H 0M 6L 0I" in flat
    assert "low-risk (provisional)" in flat
    assert re.search(r"unrated-app\s+│\s+internal\s+│\s+ready\s+│\s+-\s+│\s+-\s+│\s+0C 0H 0M 0L 0I\s+│\s+-", flat)


# ---------- the dashboard on the same store ----------


@pytest.fixture
def low_rated_assessment(fake_popen, target_dir) -> int:
    assert _run_skill(fake_popen, target_dir, tier="low").exit_code == 0
    [assessment] = _all_assessments()
    return assessment.id


@pytest.mark.parametrize("tier", list(TIERS))
def test_responsible_ai_page_shows_the_tier_badge_and_counts(fake_popen, target_dir, client, tier):
    _, risk, badge_class, _ = TIERS[tier]
    assert _run_skill(fake_popen, target_dir, tier=tier).exit_code == 0

    html = client.get("/responsible-ai").text

    assert f'badge {badge_class}">{risk}<' in html
    assert 'badge badge--neutral">provisional<' in html
    assert _stat(html, "Assessments with a risk rating") == "1"
    assert _stat(html, "High-risk") == ("1" if risk == "high-risk" else "0")
    assert _stat(html, "Provisional") == "1"


@pytest.mark.parametrize("tier", list(TIERS))
def test_assessment_pages_show_the_tier_badge(fake_popen, target_dir, client, tier):
    _, risk, badge_class, _ = TIERS[tier]
    assert _run_skill(fake_popen, target_dir, tier=tier).exit_code == 0
    [assessment] = _all_assessments()

    detail = client.get(f"/assessments/{assessment.id}").text
    listing = client.get("/assessments").text

    expected_badge = f'badge {badge_class}">{risk}<'
    all_badges = {
        'badge badge--success">low-risk<',
        'badge badge--warning">moderate<',
        'badge badge--error">high-risk<',
    }
    for html in (detail, listing):
        assert expected_badge in html
        for other_badge in all_badges - {expected_badge}:
            assert other_badge not in html


def test_overview_counts_the_rated_assessment(client, low_rated_assessment):
    assert _stat(client.get("/").text, "Responsible AI coverage") == "1"


def test_activity_page_shows_one_project_one_run_six_findings(client, low_rated_assessment):
    html = client.get(f"/activities/{SKILL_ID}").text

    assert _stat(html, "Projects covered") == "1"
    assert _stat(html, "Runs") == "1"
    assert _stat(html, "Total findings") == "6"


def test_bulk_status_form_confirms_the_rating(client, low_rated_assessment):
    resp = client.post(
        "/assessments/bulk-status",
        data={"ids": [str(low_rated_assessment)], "new_status": "completed"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    html = client.get("/responsible-ai").text
    assert 'badge badge--success">confirmed<' in html
    assert 'badge badge--neutral">provisional<' not in html
    assert _stat(html, "Provisional") == "0"
    # Confirming signs the rating off; it does not change the tier.
    assert 'badge--success">low-risk<' in html
    assert "Responsible AI: low-risk (confirmed)" in _show(low_rated_assessment)


def test_cli_status_update_confirms_the_rating(low_rated_assessment):
    result = cli_runner.invoke(app, ["assessment", "update", str(low_rated_assessment), "--status", "completed"])
    assert result.exit_code == 0, result.output

    assert "Responsible AI: low-risk (confirmed)" in _show(low_rated_assessment)


def test_reopening_a_completed_assessment_makes_the_rating_provisional_again(client, low_rated_assessment):
    confirm_resp = client.post(
        "/assessments/bulk-status",
        data={"ids": [str(low_rated_assessment)], "new_status": "completed"},
        follow_redirects=False,
    )
    assert confirm_resp.status_code == 303
    assert "Responsible AI: low-risk (confirmed)" in _show(low_rated_assessment)

    reopen_resp = client.post(
        "/assessments/bulk-status",
        data={"ids": [str(low_rated_assessment)], "new_status": "in_progress"},
        follow_redirects=False,
    )
    assert reopen_resp.status_code == 303
    assert "Responsible AI: low-risk (provisional)" in _show(low_rated_assessment)


def test_deleting_the_assessment_removes_it_from_the_page_and_the_count(client, low_rated_assessment):
    assert client.post(f"/assessments/{low_rated_assessment}/delete").json() == {"ok": True}

    page = client.get("/responsible-ai").text
    assert "No assessments have a Responsible AI risk rating yet" in page
    assert _stat(page, "Assessments with a risk rating") == "0"
    assert _stat(client.get("/").text, "Responsible AI coverage") == "0"


# ---------- most-recent-run semantics ----------


@pytest.mark.parametrize(
    "first, second, expected",
    [("low", "high", "high-risk"), ("high", "low", "low-risk"), ("high", "medium", "moderate")],
)
def test_the_badge_follows_the_newest_successful_run(fake_popen, target_dir, first, second, expected):
    assert _run_skill(fake_popen, target_dir, tier=first).exit_code == 0
    [assessment] = _all_assessments()

    result = _run_skill(fake_popen, target_dir, tier=second, extra=["--assessment", str(assessment.id)])

    assert result.exit_code == 0, result.output
    [assessment] = _all_assessments()
    assert assessment.responsible_ai_risk == expected


def test_the_badge_breaks_equal_timestamp_ties_in_favor_of_the_latest_run(fake_popen, target_dir, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository._now", lambda: "2026-11-15T12:00:00+00:00")
    assert _run_skill(fake_popen, target_dir, tier="low").exit_code == 0
    [assessment] = _all_assessments()
    assert assessment.responsible_ai_risk == "low-risk"

    result = _run_skill(fake_popen, target_dir, tier="high", extra=["--assessment", str(assessment.id)])

    assert result.exit_code == 0, result.output
    [assessment] = _all_assessments()
    assert assessment.responsible_ai_risk == "high-risk"


def test_a_failed_newer_run_does_not_change_the_badge(fake_popen, target_dir):
    assert _run_skill(fake_popen, target_dir, tier="low").exit_code == 0
    [assessment] = _all_assessments()

    failed = _run_skill(
        fake_popen, target_dir, extra=["--assessment", str(assessment.id)], returncode=1, stdout=_report("high")
    )

    assert failed.exit_code == 1
    assert json.loads(failed.stdout)["runs"][0]["status"] != "success"
    [assessment] = _all_assessments()
    assert assessment.responsible_ai_risk == "low-risk"
    assert "Responsible AI: low-risk (provisional)" in _show(assessment.id)


# ---------- attached runs ----------


def test_run_attaches_to_an_existing_assessment_and_updates_its_badge(fake_popen, target_dir):
    assessment_id = _create_assessment_for(target_dir)
    assert _all_assessments()[0].responsible_ai_risk is None

    result = _run_skill(fake_popen, target_dir, tier="medium", extra=["--assessment", str(assessment_id)])

    assert result.exit_code == 0, result.output
    [assessment] = _all_assessments()  # attached, not a second auto-created case file
    assert assessment.id == assessment_id
    assert assessment.responsible_ai_risk == "moderate"
    with RunRepository() as repo:
        [attached] = repo.list_runs(assessment_id=assessment_id, limit=10)
    assert attached.skill_id == SKILL_ID
    assert "Responsible AI: moderate (provisional)" in _show(assessment_id)


# ---------- badge derivation edge cases ----------


def test_a_missing_report_file_means_not_rated(fake_popen, target_dir):
    assert _run_skill(fake_popen, target_dir, tier="high").exit_code == 0
    [assessment] = _all_assessments()
    with RunRepository() as repo:
        [run] = repo.list_runs(assessment_id=assessment.id, limit=10)
    Path(run.report_path).unlink()

    [assessment] = _all_assessments()
    assert assessment.responsible_ai_risk is None
    assert assessment.responsible_ai_status is None


def test_an_assessment_without_a_report_path_is_not_rated(target_dir):
    with RunRepository() as repo:
        project_id = repo.upsert_project("id-1", "P1", "local")
        assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
        run_uuid = repo.create_run(
            project_id=project_id, skill_id=SKILL_ID, skill_name="Responsible AI Compliance",
            agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
        )
        repo.complete_run(
            run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path="",
            prompt_path=None, stderr_excerpt=None,
        )
        assessment = repo.get_assessment(assessment_id)

    assert assessment.responsible_ai_risk is None
