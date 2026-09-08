from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from secfoo.cvss import CvssError, parse_vector
from secfoo.cvss import rating as cvss_rating
from secfoo.report.architecture import classify_design_verdict
from secfoo.skills.loader import load_all_skills

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Focused analysis activities that get their own sidebar entry, in the order
# a reviewer normally works through them: understand the design, model the
# threats, then hunt concrete defects. The AI and deployment skills are
# deliberately not here -- they're reached through Assessments and the
# Responsible AI page instead, and a sidebar listing every skill stops
# being navigation.
SIDEBAR_ACTIVITY_IDS = [
    "security-architecture-review",
    "threat-modeling",
    "sast",
    "sca-reachability",
    "secret-scanning",
]


def _sidebar_activities() -> list[dict[str, str]]:
    skills = load_all_skills()
    return [
        {"id": skill_id, "label": skills[skill_id].nav_label}
        for skill_id in SIDEBAR_ACTIVITY_IDS
        if skill_id in skills
    ]


# Curated presentation order for skill lists (dashboard coverage panel,
# project activity table). Deliberately workflow order, not alphabetical:
# understand the design, model the threats, then hunt concrete defects in
# code / dependencies / secrets, with the AI and deployment activities last.
# Any skill not listed here sorts to the end alphabetically, so dropping in
# a new definitions/*.md still shows up without editing this list.
DISPLAY_SKILL_ORDER = [
    "security-architecture-review",
    "threat-modeling",
    "sast",
    "sca-reachability",
    "secret-scanning",
    "third-party-risk-assessment",
    "prompt-review",
    "deployment-readiness",
    "responsible-ai-compliance",
]


def ordered_skills() -> list:
    """All skills in DISPLAY_SKILL_ORDER, unlisted ones appended A-Z."""
    rank = {skill_id: index for index, skill_id in enumerate(DISPLAY_SKILL_ORDER)}
    return sorted(
        load_all_skills().values(),
        key=lambda skill: (rank.get(skill.id, len(rank)), skill.nav_label),
    )

_STATUS_BADGE_CLASS = {
    "success": "badge--success",
    "failed": "badge--error",
    "timeout": "badge--warning",
    "binary_not_found": "badge--error",
    "running": "badge--primary",
    "pending": "badge--neutral",
}

_SEVERITY_BADGE_CLASS = {
    "critical": "badge--error",
    "high": "badge--error",
    "medium": "badge--warning",
    "low": "badge--teal",
    "info": "badge--neutral",
}

# A CVSS band (cvss.rating()'s output) is a distinct axis from the report's
# own 3-tier Severity -- both can disagree for the same finding -- so it
# gets its own filter rather than reusing severity_badge_class, even though
# the underlying badge CSS classes are the same.
_CVSS_BADGE_CLASS = {
    "critical": "badge--error",
    "high": "badge--error",
    "medium": "badge--warning",
    "low": "badge--teal",
    "none": "badge--neutral",
}

_ASSESSMENT_TYPE_LABEL = {"internal": "Internal", "third_party": "Third-Party"}

_ASSESSMENT_STATUS_LABEL = {
    "ready": "Ready",
    "in_progress": "In Progress",
    "completed": "Completed",
    "blocked": "Blocked",
}

_ASSESSMENT_STATUS_BADGE = {
    "ready": "badge--neutral",
    "in_progress": "badge--primary",
    "completed": "badge--success",
    "blocked": "badge--error",
}

_RESPONSIBLE_AI_RISK_BADGE = {"high-risk": "badge--error", "moderate": "badge--warning"}
_RESPONSIBLE_AI_STATUS_BADGE = {"provisional": "badge--neutral", "confirmed": "badge--success"}


def status_badge_class(status: str) -> str:
    return _STATUS_BADGE_CLASS.get(status, "badge--neutral")


def severity_badge_class(tier: str) -> str:
    return _SEVERITY_BADGE_CLASS.get(tier.lower(), "badge--neutral")


def cvss_badge_class(band: str) -> str:
    return _CVSS_BADGE_CLASS.get(band.lower(), "badge--neutral")


def cvss_rating_label(score: float | None) -> str:
    """A stored `cvss_score` -> its none/low/medium/high/critical band,
    via the same FIRST.org bands cvss.py computes with -- kept as a
    template-facing wrapper so a template never has to import cvss.py
    directly for what's otherwise a one-line lookup.
    """
    if score is None:
        return "none"
    return cvss_rating(score)


def cvss_network_reachable(vector: str | None) -> bool:
    """True when a CVSS vector's Attack Vector is Network (AV:N) -- read as
    "reachable without local/physical access", the basis for a SAST
    finding's "External" badge. False for a missing or malformed vector,
    never a guess.
    """
    if not vector:
        return False
    try:
        return parse_vector(vector)["AV"] == "N"
    except CvssError:
        return False


def assessment_type_label(value: str) -> str:
    return _ASSESSMENT_TYPE_LABEL.get(value, value)


def assessment_status_label(value: str) -> str:
    return _ASSESSMENT_STATUS_LABEL.get(value, value)


def assessment_status_badge_class(value: str) -> str:
    return _ASSESSMENT_STATUS_BADGE.get(value, "badge--neutral")


def responsible_ai_risk_badge_class(value: str | None) -> str:
    return _RESPONSIBLE_AI_RISK_BADGE.get(value or "", "badge--neutral")


def responsible_ai_status_badge_class(value: str | None) -> str:
    return _RESPONSIBLE_AI_STATUS_BADGE.get(value or "", "badge--neutral")


_DESIGN_VERDICT_BUCKET_BADGE = {"approve": "badge--success", "conditions": "badge--warning", "reject": "badge--error"}


def design_verdict_badge_class(value: str | None) -> str:
    """Maps the Security Architecture Review contract's closing verdict
    line to a badge, via the same classification the dashboard's
    gate-decision mix uses (report/architecture.classify_design_verdict)
    so the two can't drift apart.
    """
    bucket = classify_design_verdict(value)
    return _DESIGN_VERDICT_BUCKET_BADGE.get(bucket, "badge--neutral")


def format_timestamp(value: str | None) -> str:
    if not value:
        return "-"
    return value[:19].replace("T", " ")


def format_duration(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.1f}s"


def severity_rows(critical: int, high: int, medium: int, low: int, info: int) -> list[dict]:
    """Rows for the severity-bar chart: one per tier, with a bar width
    expressed as a percentage of the tier total (not of the page, so an
    all-zero report still renders five empty bars rather than dividing by
    zero).
    """
    total = critical + high + medium + low + info
    tiers = [
        ("critical", "Critical", critical),
        ("high", "High", high),
        ("medium", "Medium", medium),
        ("low", "Low", low),
        ("info", "Informational", info),
    ]
    return [
        {"key": key, "label": label, "count": count, "percent": round(count / total * 100, 1) if total else 0}
        for key, label, count in tiers
    ]


templates.env.globals["sidebar_activities"] = _sidebar_activities()

templates.env.filters["status_badge"] = status_badge_class
templates.env.filters["fmt_time"] = format_timestamp
templates.env.filters["fmt_duration"] = format_duration
templates.env.filters["severity_badge"] = severity_badge_class
templates.env.filters["cvss_badge"] = cvss_badge_class
templates.env.filters["cvss_rating_label"] = cvss_rating_label
templates.env.filters["cvss_network_reachable"] = cvss_network_reachable
templates.env.filters["assessment_type_label"] = assessment_type_label
templates.env.filters["assessment_status_label"] = assessment_status_label
templates.env.filters["assessment_status_badge"] = assessment_status_badge_class
templates.env.filters["responsible_ai_risk_badge"] = responsible_ai_risk_badge_class
templates.env.filters["responsible_ai_status_badge"] = responsible_ai_status_badge_class
templates.env.filters["design_verdict_badge"] = design_verdict_badge_class
