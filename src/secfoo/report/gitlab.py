"""Serialize exported structured findings as GitLab security reports, without I/O.

GitLab's merge-request security widget and Vulnerability Report don't read
SARIF; they read their own report JSON (security-report-schemas v15). SAST
findings become a SAST report (`artifacts: reports: sast:`) and
secret-scanning findings a Secret Detection report
(`artifacts: reports: secret_detection:`). SCA findings have no place in
either: GitLab's dependency-scanning format describes dependency files,
which secfoo doesn't record.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from secfoo.__about__ import __version__
from secfoo.report.sarif import _line, _sites

SCHEMA_VERSION = "15.0.7"
_SCHEMA_URL = (
    "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/"
    f"v{SCHEMA_VERSION}/dist/{{name}}-report-format.json"
)

# report type -> (secfoo skill it carries, GitLab vulnerability category, schema file name)
REPORT_TYPES = {
    "sast": ("sast", "sast", "sast"),
    "secret_detection": ("secret-scanning", "secret_detection", "secret-detection"),
}

_SEVERITIES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}
# Field limits from the v15 schema.
_NAME_MAX = 255
_DESCRIPTION_MAX = 1_048_576
_SOLUTION_MAX = 7_000
# Secret Detection requires a commit; GitLab's own analyzer uses this
# placeholder when the scan isn't tied to one.
_NO_COMMIT = "0000000"
_TOOL = {
    "id": "secfoo",
    "name": "secfoo",
    "url": "https://github.com/secfoo-com/secfoo",
    "vendor": {"name": "secfoo"},
    "version": __version__,
}


def _text(value: object, limit: int) -> str | None:
    text = str(value or "").strip()
    return text[:limit] if text else None


def _timestamp(value: datetime) -> str:
    # The schema's pattern has no fraction and no zone.
    return value.strftime("%Y-%m-%dT%H:%M:%S")


def _location(record: dict) -> dict:
    """The finding's first site (#112), else its location_file/location_line."""
    path, start, end = record.get("location_file"), record.get("location_line"), None
    for site in _sites(record):
        if isinstance(site, dict) and str(site.get("path") or "").strip():
            path, start, end = site.get("path"), site.get("start_line"), site.get("end_line")
            break
    location: dict = {}
    path = str(path or "").strip().replace("\\", "/")
    if path:
        location["file"] = path
    start_line = _line(start)
    if start_line is not None:
        location["start_line"] = start_line
        end_line = _line(end)
        if end_line is not None and end_line > start_line:
            location["end_line"] = end_line
    return location


def _identifiers(skill: str, record: dict) -> list[dict]:
    # GitLab treats the first identifier as the primary one and tracks a
    # vulnerability by it plus its location, so the per-finding secfoo
    # fingerprint goes first: two findings sharing a CWE stay separate.
    identifiers = []
    fingerprint = str(record.get("fingerprint") or "").strip()
    if fingerprint:
        identifiers.append({
            "type": "secfoo_fingerprint",
            "name": f"secfoo fingerprint {fingerprint}",
            "value": fingerprint,
        })
    cwes = sorted(set(re.findall(r"\bCWE-([1-9][0-9]*)\b", str(record.get("cwe") or "").upper())), key=int)
    for number in cwes:
        identifiers.append({
            "type": "cwe",
            "name": f"CWE-{number}",
            "value": number,
            "url": f"https://cwe.mitre.org/data/definitions/{number}.html",
        })
    if not identifiers:
        identifiers.append({"type": "secfoo_skill", "name": f"secfoo {skill}", "value": skill})
    return identifiers


def _vulnerability_id(skill: str, record: dict, location: dict, index: int) -> str:
    # Fingerprints are unique per project, so the project is part of the key.
    fingerprint = str(record.get("fingerprint") or "").strip()
    if fingerprint:
        key = f"{record.get('project') or ''}/{skill}/{fingerprint}"
    else:
        key = f"{record.get('project') or ''}/{skill}/{location.get('file', '')}/{location.get('start_line', '')}/{index}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/secfoo-com/secfoo#" + key))


def _commit(record: dict) -> dict:
    ref = str(record.get("current_ref") or "").strip()
    return {"sha": ref if re.fullmatch(r"[0-9a-fA-F]{7,64}", ref) else _NO_COMMIT}


def findings_to_gitlab(
    records: list[dict], *, report_type: str, start_time: datetime, end_time: datetime | None = None,
) -> dict:
    """Build a GitLab `sast` or `secret_detection` report (schema v15).

    Records from other skills are left out. Secret evidence is never
    copied: the report names the secret type and where it is, not the value.
    """
    skill, category, schema_name = REPORT_TYPES[report_type]
    vulnerabilities = []
    for index, record in enumerate(records):
        if record.get("skill_id") != skill:
            continue
        location = _location(record)
        if report_type == "secret_detection":
            title = record.get("secret_type") or record.get("title")
            description = record.get("exposure") or record.get("construct")
            solution = record.get("remediation")
            location["commit"] = _commit(record)
        else:
            title = record.get("title")
            description = record.get("description") or record.get("construct")
            solution = record.get("recommendation")
        severity = str(record.get("severity") or "").strip().lower()
        vulnerability = {
            "id": _vulnerability_id(skill, record, location, index),
            "category": category,
            "name": _text(title, _NAME_MAX) or f"{skill} finding",
            "severity": _SEVERITIES.get(severity, "Unknown"),
            "identifiers": _identifiers(skill, record),
            "location": location,
        }
        description = _text(description, _DESCRIPTION_MAX)
        if description:
            vulnerability["description"] = description
        solution = _text(solution, _SOLUTION_MAX)
        if solution:
            vulnerability["solution"] = solution
        vulnerabilities.append(vulnerability)
    return {
        "schema": _SCHEMA_URL.format(name=schema_name),
        "version": SCHEMA_VERSION,
        "scan": {
            "analyzer": dict(_TOOL),
            "scanner": dict(_TOOL),
            "type": report_type,
            "start_time": _timestamp(start_time),
            "end_time": _timestamp(end_time or start_time),
            "status": "success",
        },
        "vulnerabilities": vulnerabilities,
    }
