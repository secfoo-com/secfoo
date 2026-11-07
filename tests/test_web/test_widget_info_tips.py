"""Widget info buttons (macro info_tip) on the Threat Modeling dashboard,
and the clearer Model depth mix / STRIDE matrix."""

from __future__ import annotations

import html
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app

STATIC_JS = Path(__file__).parents[2] / "src" / "secfoo" / "web" / "static" / "js" / "interactive.js"

TM_REPORT = """\
# Threat Modeling Report

## 1. Executive Summary
Summary. **Overall risk rating:** High

**Model depth:** {depth}

## Threat Register
| ID | Threat | STRIDE | Asset class | Archetype | Disposition | Test reference |
|----|--------|--------|-------------|-----------|-------------|----------------|
| T1 | Forged token | S | Process | Auth bypass | Gap | none |
"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    return TestClient(create_app())


def _seed(tmp_path, project: str, depth: str) -> None:
    repo = RunRepository()
    project_id = repo.upsert_project(f"https://github.com/{project}", project, "github")
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="in_progress")
    run_uuid = repo.create_run(project_id=project_id, skill_id="threat-modeling", skill_name="Threat Modeling",
                               agent_id="claude", confluence_urls=[])
    path = tmp_path / f"{run_uuid}.md"
    path.write_text(TM_REPORT.format(depth=depth))
    repo.complete_run(run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(path),
                      prompt_path=None, stderr_excerpt=None)
    repo.close()


WIDGETS = [
    "Coverage", "Open threats past due", "Mitigated but untested", "Median threats per model",
    "STRIDE × asset-class coverage", "Threat disposition", "Accepted threats", "Models needing rework",
    "Recurring threat patterns", "Model depth mix", "Threats found post-build", "Falsified assumptions",
]


def test_every_threat_modeling_widget_has_an_info_tip(client, tmp_path):
    _seed(tmp_path, "acme/app", "Lightweight")
    html = client.get("/activities/threat-modeling").text
    tips = re.findall(r'<details class="info-tip[^"]*">.*?</details>', html, re.S)
    titles = [re.search(r'<p class="info-tip__title">([^<]*)</p>', t).group(1) for t in tips]
    # The activity page also shows the generic severity card under the
    # program dashboard. Architecture, SAST, SCA, and secret scanning hide it.
    assert titles == WIDGETS + ["Findings by severity"]
    for tip in tips:
        # An accessible button and a real explanation, not an empty panel.
        assert 'aria-label="What is' in tip
        body = re.sub(r"<[^>]+>", " ", tip.split('class="info-tip__title"', 1)[1])
        assert len(body.split()) >= 15


def test_model_depth_mix_explains_each_depth(client, tmp_path):
    _seed(tmp_path, "acme/a", "Lightweight")
    _seed(tmp_path, "acme/b", "Lightweight")
    _seed(tmp_path, "acme/c", "Full")
    html = client.get("/activities/threat-modeling").text
    card = html[html.index('<h4 class="card__title">Model depth mix</h4>'):]
    card = card[:card.index("</ul>")]
    assert "(3 models)" in card
    assert "Whole system" in card and "One feature or new data flow" in card and "Fast checklist pass" in card
    counts = re.findall(r'<span class="depth-mix__count">(\d+)</span>', card)
    assert counts == ["1", "0", "2"]
    assert "More lightweight than full models" in html


def test_no_lightweight_hint_when_models_are_full(client, tmp_path):
    _seed(tmp_path, "acme/a", "Full")
    assert "More lightweight than full models" not in client.get("/activities/threat-modeling").text


def test_stride_matrix_names_its_letters_and_colours(client, tmp_path):
    _seed(tmp_path, "acme/app", "Full")
    html = client.get("/activities/threat-modeling").text
    for name in ("Spoofing", "Tampering", "Repudiation", "Information disclosure", "Denial of service",
                 "Elevation of privilege"):
        assert f'<abbr title="{name}">' in html
    assert "None found" in html and "1–2 threats" in html and "3 or more" in html


def test_info_tips_close_on_outside_click_and_escape():
    js = STATIC_JS.read_text()
    assert "details.info-tip[open]" in js
    assert '"Escape"' in js and '"toggle"' in js


def test_long_lists_scroll_after_ten_rows():
    js = STATIC_JS.read_text()
    assert "[data-scroll-rows]" in js
    assert "maxHeight" in js
    tm = (STATIC_JS.parents[2] / "templates" / "activities" / "threat_modeling_dashboard.html").read_text()
    for marker in ("rework-list widget-scroll", "pattern-list widget-scroll", "miss-list widget-scroll", "assume-list widget-scroll"):
        assert marker in tm
    assert tm.count('data-scroll-rows="10"') >= 6


def _assert_titled_tips(page: str, expected: list[str]) -> None:
    tips = re.findall(r'<details class="info-tip[^"]*">.*?</details>', page, re.S)
    titles = [
        html.unescape(re.search(r'<p class="info-tip__title">([^<]*)</p>', tip).group(1))
        for tip in tips
    ]
    assert titles == expected
    for tip in tips:
        assert 'aria-label="What is' in tip
        body = re.sub(r"<[^>]+>", " ", tip.split('class="info-tip__title"', 1)[1])
        assert len(body.split()) >= 15, body


@pytest.mark.parametrize(
    ("path", "titles"),
    [
        (
            "/activities/security-architecture-review",
            [
                "Coverage", "Exceptions past expiry", "Open findings past due",
                "Unverified mitigations", "Cycle time p90", "CCM domain conformance",
                "Risk disposition", "Exception aging", "Unreviewed & stale",
                "Top recurring root causes", "Gate decision mix", "Most-deviated standards",
                "Uncovered CCM domains",
            ],
        ),
        (
            "/activities/sast",
            [
                "Open findings", "Exploitable", "Verified", "Severe", "Awaiting sign-off",
                "CVSS severity", "Top vulnerability types", "Top findings",
            ],
        ),
        (
            "/activities/sca-reachability",
            [
                "Coverage", "Distinct vulnerabilities", "Reachable", "Unrecognized ecosystem",
                "Severity", "Vulnerabilities by ecosystem", "Top vulnerabilities",
            ],
        ),
        (
            "/activities/secret-scanning",
            [
                "Secrets found", "Looks live", "Found in documentation",
                "Version-control history only", "Severity", "By source", "Top findings",
            ],
        ),
        (
            "/",
            [
                "Applications reviewed", "Total findings", "Third-party assessments",
                "Responsible AI coverage", "AI spend", "Findings by severity",
                "Activity coverage", "Responsible AI risk mix", "AI spend by agent",
            ],
        ),
        ("/third-party", ["Vendor CCM v4 conformance"]),
        ("/responsible-ai", ["Assessments with a risk rating", "High-risk", "Provisional"]),
        (
            "/activities/prompt-review",
            ["Projects covered", "Runs", "Total findings", "Critical + High", "Findings by severity"],
        ),
    ],
)
def test_program_pages_explain_each_widget(client, path, titles):
    resp = client.get(path)
    assert resp.status_code == 200
    _assert_titled_tips(resp.text, titles)


def test_linked_stat_cards_keep_the_info_button_clickable(client):
    """The info control must not sit inside the link, or the click both
    opens the note and navigates away."""
    sast = client.get("/activities/sast").text
    overview = client.get("/").text
    assert '<a class="stat-card"' not in sast
    assert '<a class="stat-card"' not in overview
    assert 'href="/activities/sast/findings?status=open"' in sast
    assert 'href="/third-party"' in overview
    assert 'href="/responsible-ai"' in overview
    assert sast.count('class="stat-card__cover"') == 1
    assert overview.count('class="stat-card__cover"') == 2


def test_assessment_findings_card_explains_repeat_runs(client, tmp_path):
    repo = RunRepository()
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="in_progress")
    repo.close()
    html = client.get(f"/assessments/{assessment_id}").text
    _assert_titled_tips(html, ["Findings by severity"])
    assert "heading-with-info" in html


def test_section_heading_info_tips_follow_the_heading_text(client, tmp_path):
    _seed(tmp_path, "acme/app", "Full")
    html = client.get("/activities/threat-modeling").text
    for title in ("Models needing rework", "Recurring threat patterns"):
        heading = re.search(rf'<h2 class="([^"]*)">{title}\s*<details class="info-tip info-tip--inline">', html)
        assert heading, f"{title}: info button must come right after the heading text"
        assert "heading-with-info" in heading.group(1)
