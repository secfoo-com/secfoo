"""SARIF contract tests, validated offline against the complete 2.1.0 schema."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker

from secfoo.__about__ import __version__
from secfoo.report.sarif import findings_to_sarif

SCHEMA = json.loads((Path(__file__).parents[1] / "fixtures" / "sarif-schema-2.1.0.json").read_text())
VALIDATOR = Draft7Validator(SCHEMA, format_checker=FormatChecker())


def validate_sarif(document):
    VALIDATOR.validate(document)
    return document["runs"][0]


def test_mixed_skills_and_rules_validate_against_sarif_schema():
    records = [
        {"skill_id": "sast", "severity": "High", "cwe": "CWE-89", "title": "SQL injection",
         "description": "Untrusted query", "location_file": "app/db.py", "location_line": "42"},
        {"skill_id": "sast", "severity": "High", "cwe": "CWE-89", "title": "Another query"},
        {"skill_id": "sast", "severity": "Low", "cwe": "CWE-89", "title": "Lower impact query"},
        {"skill_id": "sca-reachability", "severity": "Medium", "issue": "Unsafe dependency"},
        {"skill_id": "secret-scanning", "severity": "Critical", "secret_type": "API token",
         "evidence": "never-copy-secret-evidence", "location_file": "ci.yml"},
    ]
    run = validate_sarif(findings_to_sarif(records))
    assert run["tool"]["driver"]["version"] == __version__
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert len(rules) == 4
    assert results[0]["ruleIndex"] == results[1]["ruleIndex"]
    assert results[0]["ruleIndex"] != results[2]["ruleIndex"]
    assert "external/cwe/cwe-89" in rules[0]["properties"]["tags"]
    assert rules[0]["properties"]["security-severity"] == "7.0"
    assert rules[1]["properties"]["security-severity"] == "1.0"
    assert results[0]["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 42},
    }
    assert results[3]["message"]["text"] == "Unsafe dependency"
    assert results[4]["message"]["text"] == "API token"
    assert "never-copy-secret-evidence" not in json.dumps(run)
    assert records[0]["location_line"] == "42"  # Serialization doesn't mutate source records.


@pytest.mark.parametrize(("severity", "level", "score"), [
    ("Critical", "error", "9.0"), (" HIGH ", "error", "7.0"),
    ("Medium", "warning", "4.0"), ("Low", "note", "1.0"),
    ("Info", "note", "0.0"), ("Informational", "note", "0.0"),
    (None, "warning", None), ("unverified", "warning", None),
])
def test_severity_mapping(severity, level, score):
    run = validate_sarif(findings_to_sarif([{"skill_id": "sast", "severity": severity}]))
    assert run["results"][0]["level"] == level
    assert run["tool"]["driver"]["rules"][0]["properties"].get("security-severity") == score


@pytest.mark.parametrize(("path", "uri"), [
    ("src/a b#?.py", "src/a%20b%23%3F.py"),
    ("//server/share/a b.py", "file://server/share/a%20b.py"),
    ("src/a:b.py", "src/a%3Ab.py"),
    ("src/é.py", "src/%C3%A9.py"),
    ("/work/a b.py", "file:///work/a%20b.py"),
    ("C:\\work\\a b.py", "file:///C:/work/a%20b.py"),
    ("src\\a.py", "src/a.py"),
])
def test_file_uris(path, uri):
    run = validate_sarif(findings_to_sarif([{"skill_id": "sast", "location_file": path}]))
    assert run["results"][0]["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": uri}}


@pytest.mark.parametrize("line", [None, "", "0", "-2", "4-8", "unknown", "1.5"])
def test_invalid_lines_omit_region(line):
    run = validate_sarif(findings_to_sarif([{"skill_id": "sast", "location_file": "a.py", "location_line": line}]))
    assert "region" not in run["results"][0]["locations"][0]["physicalLocation"]


def test_missing_files_omit_locations_and_empty_exports_are_valid():
    run = validate_sarif(findings_to_sarif([{"skill_id": "sast", "location_line": "4"}]))
    assert "locations" not in run["results"][0]
    empty = validate_sarif(findings_to_sarif([]))
    assert empty["results"] == []
    assert empty["tool"]["driver"]["rules"] == []


def test_cwe_tags_are_normalized_deduplicated_and_unknown_values_ignored():
    run = validate_sarif(findings_to_sarif([
        {"skill_id": "sast", "cwe": "cwe-89, CWE-79, CWE-89"},
        {"skill_id": "sast", "cwe": "unverified"},
    ]))
    rules = run["tool"]["driver"]["rules"]
    assert rules[0]["properties"]["tags"] == ["security", "external/cwe/cwe-79", "external/cwe/cwe-89"]
    assert rules[1]["properties"]["tags"] == ["security"]
