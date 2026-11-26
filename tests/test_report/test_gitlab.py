"""GitLab SAST / Secret Detection report contract tests, validated offline
against the v15 report schemas."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker

from secfoo.__about__ import __version__
from secfoo.report.gitlab import findings_to_gitlab

FIXTURES = Path(__file__).parents[1] / "fixtures"
VALIDATORS = {
    report_type: Draft7Validator(
        json.loads((FIXTURES / f"gitlab-{name}-report-format-15.json").read_text()), format_checker=FormatChecker(),
    )
    for report_type, name in (("sast", "sast"), ("secret_detection", "secret-detection"))
}
NOW = datetime(2026, 11, 26, 9, 30, 15, 123456, tzinfo=timezone.utc)


def gitlab_report(records, report_type="sast", **kwargs):
    document = findings_to_gitlab(records, report_type=report_type, start_time=NOW, **kwargs)
    VALIDATORS[report_type].validate(document)
    return document


RECORDS = [
    {"skill_id": "sast", "project": "proj", "fingerprint": "fp-sqli", "severity": "High", "cwe": "CWE-89",
     "title": "SQL injection", "description": "Untrusted query", "recommendation": "Use bound parameters",
     "location_file": "app/db.py", "location_line": "42"},
    {"skill_id": "sast", "project": "proj", "fingerprint": "fp-other", "severity": "High", "cwe": "CWE-89",
     "title": "Another query"},
    {"skill_id": "sca-reachability", "severity": "Medium", "issue": "Unsafe dependency"},
    {"skill_id": "secret-scanning", "project": "proj", "fingerprint": "fp-key", "severity": "Critical",
     "secret_type": "API token", "evidence": "never-copy-secret-evidence", "exposure": "Committed to CI config",
     "remediation": "Rotate the token", "current_ref": "0123456789abcdef0123456789abcdef01234567",
     "location_file": "ci.yml", "location_line": "7"},
]


def test_sast_report_validates_and_carries_only_sast_findings():
    document = gitlab_report(RECORDS)
    assert document["version"] == "15.0.7"
    assert document["schema"].endswith("/v15.0.7/dist/sast-report-format.json")
    scan = document["scan"]
    assert scan["type"] == "sast"
    assert scan["analyzer"]["version"] == scan["scanner"]["version"] == __version__
    assert scan["start_time"] == scan["end_time"] == "2026-11-26T09:30:15"
    first, second = document["vulnerabilities"]
    assert first["category"] == "sast"
    assert first["name"] == "SQL injection"
    assert first["description"] == "Untrusted query"
    assert first["solution"] == "Use bound parameters"
    assert first["severity"] == "High"
    assert first["location"] == {"file": "app/db.py", "start_line": 42}
    assert first["identifiers"] == [
        {"type": "secfoo_fingerprint", "name": "secfoo fingerprint fp-sqli", "value": "fp-sqli"},
        {"type": "cwe", "name": "CWE-89", "value": "89", "url": "https://cwe.mitre.org/data/definitions/89.html"},
    ]
    # Same CWE, different finding: the primary identifier and id keep them apart.
    assert first["identifiers"][0] != second["identifiers"][0]
    assert first["id"] != second["id"]
    assert second["location"] == {}
    assert RECORDS[0]["location_line"] == "42"  # Serialization doesn't mutate source records.


def test_secret_detection_report_validates_and_never_copies_evidence():
    document = gitlab_report(RECORDS, report_type="secret_detection")
    assert document["scan"]["type"] == "secret_detection"
    assert document["schema"].endswith("/v15.0.7/dist/secret-detection-report-format.json")
    (vulnerability,) = document["vulnerabilities"]
    assert vulnerability["category"] == "secret_detection"
    assert vulnerability["name"] == "API token"
    assert vulnerability["severity"] == "Critical"
    assert vulnerability["description"] == "Committed to CI config"
    assert vulnerability["solution"] == "Rotate the token"
    assert vulnerability["location"] == {
        "file": "ci.yml", "start_line": 7, "commit": {"sha": "0123456789abcdef0123456789abcdef01234567"},
    }
    assert "never-copy-secret-evidence" not in json.dumps(document)


@pytest.mark.parametrize("ref", [None, "", "working-tree", "not a sha"])
def test_secret_without_a_commit_uses_the_placeholder_sha(ref):
    document = gitlab_report([{"skill_id": "secret-scanning", "current_ref": ref}], report_type="secret_detection")
    assert document["vulnerabilities"][0]["location"]["commit"] == {"sha": "0000000"}


@pytest.mark.parametrize(("severity", "expected"), [
    ("Critical", "Critical"), (" HIGH ", "High"), ("Medium", "Medium"), ("Low", "Low"),
    ("Info", "Info"), ("Informational", "Info"), (None, "Unknown"), ("unverified", "Unknown"),
])
def test_severity_mapping(severity, expected):
    document = gitlab_report([{"skill_id": "sast", "severity": severity}])
    assert document["vulnerabilities"][0]["severity"] == expected


def test_ids_are_stable_and_scoped_to_the_project():
    record = {"skill_id": "sast", "project": "a", "fingerprint": "fp"}
    first = gitlab_report([record])["vulnerabilities"][0]["id"]
    assert gitlab_report([record])["vulnerabilities"][0]["id"] == first
    assert gitlab_report([{**record, "project": "b"}])["vulnerabilities"][0]["id"] != first


def test_findings_without_fingerprint_or_cwe_still_have_an_identifier():
    (vulnerability,) = gitlab_report([{"skill_id": "sast", "cwe": "unverified"}])["vulnerabilities"]
    assert vulnerability["identifiers"] == [{"type": "secfoo_skill", "name": "secfoo sast", "value": "sast"}]
    assert vulnerability["name"] == "sast finding"


def test_first_site_wins_and_invalid_lines_are_dropped():
    sites = [{"path": "src\\a.py", "start_line": 3, "end_line": 9}, {"path": "b.py", "start_line": 1}]
    document = gitlab_report([
        {"skill_id": "sast", "locations": json.dumps(sites), "location_file": "ignored.py"},
        {"skill_id": "sast", "location_file": "c.py", "location_line": "4-8"},
    ])
    first, second = document["vulnerabilities"]
    assert first["location"] == {"file": "src/a.py", "start_line": 3, "end_line": 9}
    assert second["location"] == {"file": "c.py"}


def test_long_fields_are_truncated_to_the_schema_limits():
    (vulnerability,) = gitlab_report([
        {"skill_id": "sast", "title": "t" * 300, "recommendation": "r" * 8000},
    ])["vulnerabilities"]
    assert len(vulnerability["name"]) == 255
    assert len(vulnerability["solution"]) == 7000


def test_empty_exports_are_valid():
    for report_type in ("sast", "secret_detection"):
        assert gitlab_report([], report_type=report_type)["vulnerabilities"] == []
