from __future__ import annotations

from secfoo.report.severity import count_severities, extract_overall_risk_rating

SAMPLE_REPORT = """\
# Threat Assessment Report

## Summary
Some issues found. **Overall risk rating:** High.

## Findings

### [HIGH] F1: Example finding
- **Severity:** High

### [MEDIUM] F2: Another finding
- **Severity:** Medium

### [MEDIUM] F3: Yet another
- **Severity:** Medium

### [LOW] F4: Minor finding
- **Severity:** Low
"""


def test_count_severities_tallies_each_tier():
    counts = count_severities(SAMPLE_REPORT)
    assert counts.high == 1
    assert counts.medium == 2
    assert counts.low == 1
    assert counts.critical == 0
    assert counts.info == 0
    assert counts.total == 4


def test_count_severities_recognizes_critical_and_informational():
    text = "### [CRITICAL] F1: x\n### [INFORMATIONAL] F2: y\n### [INFO] F3: z\n"
    counts = count_severities(text)
    assert counts.critical == 1
    assert counts.info == 2


def test_count_severities_empty_report_is_all_zero():
    counts = count_severities("# Report\n\nNo findings.")
    assert counts.total == 0


def test_extract_overall_risk_rating_parses_value():
    assert extract_overall_risk_rating(SAMPLE_REPORT) == "high"


def test_extract_overall_risk_rating_missing_returns_none():
    assert extract_overall_risk_rating("# Report\nNo rating here.") is None
