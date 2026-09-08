"""Computes the SAST activity page's extended dashboard: a findings
funnel, a CVSS-band breakdown, a "Top Vulnerability Types" (CWE) breakdown,
and Open/Closed Findings lists.

Unlike the other activity dashboards, this reads primarily from the
persistent `sast_findings` table rather than re-parsing report text on
every request. Report parsing happens at write time via
report/sast.py and runner.py's post-run lifecycle hook.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from secfoo.report.sast import SKILL_ID
from secfoo.storage.models import SastFindingRecord
from secfoo.storage.repository import RunRepository

_CVSS_BANDS = ("critical", "high", "medium", "low", "none")


@dataclass
class SastDashboard:
    funnel: dict[str, int] = field(default_factory=dict)
    cvss_band_counts: dict[str, int] = field(default_factory=dict)
    top_cwe_counts: list[tuple[str, int]] = field(default_factory=list)
    open_findings: list[SastFindingRecord] = field(default_factory=list)
    closed_findings: list[SastFindingRecord] = field(default_factory=list)
    open_findings_by_key: dict[str, SastFindingRecord] = field(default_factory=dict)


def _cvss_band(score: float | None) -> str:
    if score is None:
        return "none"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def build(repo: RunRepository) -> SastDashboard:
    dash = SastDashboard()

    dash.open_findings = repo.list_sast_findings(status="open")
    dash.closed_findings = repo.list_sast_findings(status="closed")
    dash.open_findings_by_key = {f.fingerprint: f for f in dash.open_findings}

    band_counter: Counter[str] = Counter()
    cwe_counter: Counter[str] = Counter()
    verified_count = 0
    severe_count = 0
    exploitable_count = 0

    for finding in dash.open_findings:
        band = _cvss_band(finding.cvss_score)
        band_counter[band] += 1
        if finding.cwe and finding.cwe.strip().lower() != "unverified":
            cwe_counter[finding.cwe.strip()] += 1
        if (finding.verdict or "").strip().lower() == "confirmed":
            verified_count += 1
        if band in ("high", "critical"):
            severe_count += 1
        if (finding.verdict or "").strip().lower() != "latent":
            exploitable_count += 1

    dash.cvss_band_counts = {band: band_counter.get(band, 0) for band in _CVSS_BANDS}
    dash.top_cwe_counts = cwe_counter.most_common(10)
    dash.funnel = {
        "findings": len(dash.open_findings),
        "exploitable": exploitable_count,
        "verified": verified_count,
        "severe": severe_count,
    }

    return dash
