from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProjectRecord:
    id: int
    identifier: str
    display_name: str
    kind: str
    first_seen_at: str
    last_run_at: str


@dataclass(frozen=True)
class RunRecord:
    id: int
    run_uuid: str
    project_id: int
    skill_id: str
    skill_name: str
    agent_id: str
    confluence_urls: list[str]
    status: str
    exit_code: int | None
    started_at: str
    finished_at: str | None
    duration_seconds: float | None
    report_path: str | None
    prompt_path: str | None
    stderr_excerpt: str | None
    assessment_id: int | None = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    cloud_synced_at: str | None = None
    project_display_name: str | None = None


@dataclass(frozen=True)
class AssessmentRecord:
    id: int
    project_id: int
    assessment_type: str
    status: str
    application_id: str | None
    sar_number: str | None
    reviewer: str | None
    review_date: str | None
    notes: str | None
    created_at: str
    updated_at: str
    assessment_uuid: str | None = None
    project_display_name: str | None = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    # Derived, not stored: see RunRepository._responsible_ai_badges.
    responsible_ai_risk: str | None = None
    responsible_ai_status: str | None = None


@dataclass(frozen=True)
class AttachmentRecord:
    id: int
    assessment_id: int
    file_path: str
    original_name: str
    attachment_kind: str
    uploaded_at: str


@dataclass(frozen=True)
class ExceptionRecord:
    id: int
    project_id: int
    assessment_id: int | None
    title: str
    standard_or_control: str | None
    justification: str
    granted_by: str
    status: str
    created_at: str
    updated_at: str
    expires_at: str
    project_display_name: str | None = None


@dataclass(frozen=True)
class PostBuildFindingRecord:
    id: int
    project_id: int
    run_id: int | None
    title: str
    description: str | None
    discovered_by: str | None
    discovered_at: str
    created_at: str
    project_display_name: str | None = None


@dataclass(frozen=True)
class ThreatAcceptanceRecord:
    id: int
    project_id: int
    run_id: int | None
    threat_ref: str
    title: str
    justification: str
    accepted_by: str
    status: str
    expires_at: str | None
    created_at: str
    updated_at: str
    project_display_name: str | None = None


@dataclass(frozen=True)
class OsvLookupRecord:
    ecosystem: str
    package: str
    version: str
    vulns: list[dict]
    queried_at: str


@dataclass(frozen=True)
class SastFindingRecord:
    id: int
    project_id: int
    fingerprint: str
    current_ref: str
    title: str
    severity: str
    cwe: str | None
    owasp: str | None
    verdict: str | None
    location_file: str
    location_line: str | None
    cvss_vector: str | None
    cvss_score: float | None
    status: str
    first_seen_run_id: int
    first_seen_at: str
    last_seen_run_id: int
    last_seen_at: str
    closed_in_run_id: int | None
    closed_at: str | None
    description: str | None = None
    recommendation: str | None = None
    project_display_name: str | None = None
