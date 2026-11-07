"""Widget info buttons (macro info_tip) on the Threat Modeling dashboard,
and the clearer Model depth mix / STRIDE matrix."""

from __future__ import annotations

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
    assert titles == WIDGETS
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
