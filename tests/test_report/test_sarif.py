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


def test_multi_site_and_range_locations_emit_per_site_sarif_regions():
    records = [
        {
            "skill_id": "sast",
            "severity": "High",
            "cwe": "CWE-79",
            "title": "Autoescape disabled",
            "location_file": "server.js",
            "location_line": "135",
            "locations": [
                {"path": "server.js", "start_line": 135, "end_line": 137},
                {"path": "app/views/layout.html", "start_line": 75, "end_line": None},
            ],
        },
        {
            "skill_id": "secret-scanning",
            "severity": "Medium",
            "secret_type": "Seeded passwords",
            "location_file": "artifacts/db-reset.js",
            "location_line": "18",
            "locations": [
                {"path": "artifacts/db-reset.js", "start_line": 18, "end_line": None},
                {"path": "test/e2e/fixtures/users/*.json", "start_line": None, "end_line": None},
            ],
        },
    ]
    run = validate_sarif(findings_to_sarif(records))
    assert run["results"][0]["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "server.js"},
                "region": {"startLine": 135, "endLine": 137},
            }
        },
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "app/views/layout.html"},
                "region": {"startLine": 75},
            }
        },
    ]
    assert run["results"][1]["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "artifacts/db-reset.js"},
                "region": {"startLine": 18},
            }
        },
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "test/e2e/fixtures/users/%2A.json"},
            }
        },
    ]


def test_nodegoat_sample_sarif_validates_and_every_result_has_a_real_uri():
    sample_dir = Path(__file__).parents[2] / "examples" / "sample-output" / "nodegoat"
    sarif_doc = json.loads((sample_dir / "findings.sarif").read_text(encoding="utf-8"))
    run = validate_sarif(sarif_doc)
    assert len(run["results"]) == 18

    for result in run["results"]:
        assert result.get("locations"), f"missing locations on {result['ruleId']}"
        for loc in result["locations"]:
            physical = loc["physicalLocation"]
            uri = physical["artifactLocation"]["uri"]
            assert uri
            assert "%3A" not in uri
            assert "%2C" not in uri
            assert "%3B" not in uri
            assert "`" not in uri
            assert "," not in uri
            assert ";" not in uri

    jsonl_records = [
        json.loads(line)
        for line in (sample_dir / "findings.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(jsonl_records) == 18
    for record in jsonl_records:
        assert record["locations"], f"missing locations in JSONL record {record['current_ref']}"
        assert all(ch not in record["location_file"] for ch in (",", ";", "`", ":"))
    rebuilt_run = validate_sarif(findings_to_sarif(jsonl_records))
    assert [r["locations"] for r in rebuilt_run["results"]] == [r["locations"] for r in run["results"]]
