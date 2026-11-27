"""Pure parser tests for the Responsible AI output contract (#131)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secfoo.report.responsible_ai import (
    DIMENSIONS,
    AIProfile,
    ai_bom_diff,
    parse_responsible_ai_report,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "reports"


def _report(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_contract_report_yields_the_seven_dimensions_in_contract_order():
    parsed = parse_responsible_ai_report(_report("responsible-ai-compliance-contract.md"))

    assert parsed.overall_rating == "medium"
    assert tuple(row.dimension for row in parsed.dimensions) == DIMENSIONS
    assert len(DIMENSIONS) == 7

    by_dimension = {row.dimension: row for row in parsed.dimensions}
    assert by_dimension["Human oversight"].status == "partial"
    assert by_dimension["Human oversight"].finding_ids == ("F1",)
    assert "review/approve.py" in by_dimension["Human oversight"].evidence
    assert by_dimension["Data provenance & consent"].status == "adequate"
    assert by_dimension["Data provenance & consent"].finding_ids == ()
    assert by_dimension["Bias & fairness"].status == "missing"


def test_contract_report_reads_profile_and_dimension_tagged_findings():
    parsed = parse_responsible_ai_report(_report("responsible-ai-compliance-contract.md"))

    assert parsed.profile.models == ("gpt-4o", "claude-3-5-sonnet")
    assert parsed.profile.providers == ("OpenAI", "Anthropic")
    assert parsed.profile.stakes_tier == "high"
    assert parsed.profile.decides.startswith("Loan preapproval")

    assert [finding.finding_id for finding in parsed.findings] == ["F1", "F2", "F3"]
    assert [finding.dimension for finding in parsed.findings] == [
        "Human oversight",
        "Transparency to end users",
        "Auditability & recourse",
    ]
    assert parsed.findings[0].framework == "NIST AI RMF GOVERN 4.2"
    assert parsed.findings[1].framework == "EU AI Act Art. 26"
    assert parsed.findings[0].stakes == "high"
    assert "rubber stamp" in parsed.findings[0].description
    assert parsed.remediation_roadmap.startswith("1.")


def test_legacy_cwe_shaped_report_still_yields_findings_but_no_dimensions():
    parsed = parse_responsible_ai_report(_report("responsible-ai-compliance.md"))

    assert parsed.overall_rating == "low"
    assert len(parsed.findings) == 6
    assert all(finding.dimension == "" for finding in parsed.findings)
    assert parsed.dimensions == ()


@pytest.mark.parametrize("text", ["", "# Not a report", "## Summary\nno rating here"])
def test_incomplete_reports_never_raise(text):
    parsed = parse_responsible_ai_report(text)

    assert parsed.overall_rating is None
    assert parsed.dimensions == ()
    assert parsed.findings == ()
    assert parsed.profile == AIProfile()


def test_ai_bom_diff_ignores_tools_and_compares_names_case_insensitively():
    profile = AIProfile(models=("GPT-4o", "claude-3-5-sonnet", "gpt-4o"))
    items = [
        {"kind": "model", "name": "gpt-4o", "provider": "OpenAI"},
        {"kind": "model", "name": "Gemini 1.5"},
        {"kind": "tool", "name": "claude-3-5-sonnet"},
    ]

    diff = ai_bom_diff(profile, items)

    assert diff["shared"] == ["GPT-4o"]
    assert diff["code_only"] == ["claude-3-5-sonnet"]
    assert diff["bom_only"] == ["Gemini 1.5"]


def test_ai_bom_diff_with_no_bom_is_all_code_only():
    diff = ai_bom_diff(AIProfile(models=("gpt-4o",)), [])

    assert diff["code_only"] == ["gpt-4o"]
    assert diff["bom_only"] == []
    assert diff["shared"] == []
