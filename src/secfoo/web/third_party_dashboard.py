"""Computes the Third-Party page's CCM v4 heatmap: how many of the 17 CSA
Cloud Controls Matrix domains have supporting vendor-provided evidence,
aggregated across every third-party assessment's most recent Third-Party
Risk Assessment run.

Mirrors architecture_dashboard.py's ccm_rows shape exactly (same keys:
code/name/score/hatched) so the identical `.conformance-bar` template
markup renders both dashboards -- "does OUR design conform" and "does
THIS VENDOR's documentation show conformance" are different questions
asked of the same CCM v4 framework, not two different frameworks that
happen to share a name.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secfoo.report.architecture import CCM_DOMAINS, conformance_to_score, extract_ccm_conformance
from secfoo.storage.repository import RunRepository
from secfoo.web.dashboard_common import read_report

SKILL_ID = "third-party-risk-assessment"

_read = read_report


@dataclass
class ThirdPartyDashboard:
    ccm_rows: list[dict] = field(default_factory=list)
    uncovered_ccm_domains: list[str] = field(default_factory=list)
    assessed_vendor_count: int = 0


def build(repo: RunRepository) -> ThirdPartyDashboard:
    dash = ThirdPartyDashboard()

    assessments = repo.list_assessments(assessment_type="third_party", limit=10_000)
    ccm_scores: dict[str, list[float]] = {code: [] for code, _ in CCM_DOMAINS}
    ccm_assessed: dict[str, bool] = {code: False for code, _ in CCM_DOMAINS}

    for assessment in assessments:
        runs = repo.list_runs(
            assessment_id=assessment.id, skill_id=SKILL_ID, status="success", limit=1
        )
        if not runs or not runs[0].report_path:
            continue
        text = _read(runs[0].report_path)
        if not text:
            continue

        domain_values = extract_ccm_conformance(text)
        if not domain_values:
            continue
        dash.assessed_vendor_count += 1
        for code, value in domain_values.items():
            score = conformance_to_score(value)
            if score is not None:
                ccm_scores[code].append(score)
                ccm_assessed[code] = True

    for code, name in CCM_DOMAINS:
        scores = ccm_scores[code]
        avg = round(sum(scores) / len(scores)) if scores else None
        dash.ccm_rows.append({"code": code, "name": name, "score": avg, "hatched": avg is None})
    dash.uncovered_ccm_domains = [name for code, name in CCM_DOMAINS if not ccm_assessed[code]]

    return dash
