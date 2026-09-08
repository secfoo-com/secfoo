from __future__ import annotations

from secfoo.report.architecture import (
    classify_design_verdict,
    conformance_to_score,
    count_trust_boundaries,
    extract_assumption_validity_counts,
    extract_ccm_conformance,
    extract_design_verdict,
    extract_falsified_assumptions,
    extract_mermaid_diagram,
    extract_model_depth,
    extract_root_causes,
    extract_standards_deviated,
    extract_threat_register_rows,
    extract_verdict_counts,
    is_process_assured,
)

SAMPLE_REPORT = """\
# Security Architecture Review Report

## 3. Data Flow Diagram

```mermaid
flowchart LR
  user([End user]) -->|"B1: HTTPS"| api["API service"]
  api -->|"B2: parameterized SQL"| db[("Primary DB")]
```

## 4. Trust Boundaries

| ID | Boundary | What crosses it | Enforced by | Gap |
|----|----------|------------------|--------------|-----|
| B1 | Internet -> API | HTTPS request | TLS + session middleware | - |
| B2 | API -> DB | SQL query | Parameterization | - |

## 11. Design Verdict & Remediation Roadmap

**Design verdict:** Sound with conditions

Conditions: rotate the hardcoded key before shipping.
"""


def test_extract_mermaid_diagram_returns_the_source():
    diagram = extract_mermaid_diagram(SAMPLE_REPORT)
    assert diagram is not None
    assert "flowchart LR" in diagram
    assert "B1: HTTPS" in diagram
    # Must not include the fence markers themselves.
    assert "```" not in diagram


def test_extract_mermaid_diagram_returns_none_when_absent():
    assert extract_mermaid_diagram("# Report\n\nNo diagram here.") is None


def test_extract_design_verdict_parses_the_value():
    assert extract_design_verdict(SAMPLE_REPORT) == "Sound with conditions"


def test_extract_design_verdict_returns_none_for_other_skills():
    # SAST/SCA/secret-scanning reports never carry this line.
    assert extract_design_verdict("# SAST Report\n\n**Overall risk rating:** High\n") is None


def test_extract_design_verdict_stops_at_line_end_not_full_stop():
    text = "**Design verdict:** Not sound.\n\nThe primary blocking issue is X.\n"
    assert extract_design_verdict(text) == "Not sound"


def test_count_trust_boundaries_counts_distinct_ids():
    assert count_trust_boundaries(SAMPLE_REPORT) == 2


def test_count_trust_boundaries_deduplicates_repeated_ids():
    text = "| B1 | x |\n| B1 | x |\n| B2 | y |\n"
    assert count_trust_boundaries(text) == 2


def test_count_trust_boundaries_zero_for_reports_without_the_scheme():
    assert count_trust_boundaries("# Threat Modeling Report\n\nNo boundary table here.\n") == 0


# ---------------------------------------------------------------------------
# Verdict counts, root causes, standards -- all parsed from the Findings
# Register table specifically, not prose.
# ---------------------------------------------------------------------------

REGISTER_REPORT = """\
# Security Architecture Review Report

## 8. CCM Domain Conformance

| Domain | Code | Conformance | Evidence |
|---|---|---|---|
| Audit & Assurance | A&A | Partial | some logs exist |
| Application & Interface Security | AIS | Conformant | input validation present |
| Human Resources Security | HRS | Not Assessed (process-assured) | HR handled externally |
| Datacenter Security | DCS | Not Applicable | fully serverless |

## 9. Findings Register

| ID | Finding | Severity | Category | Standard | Verdict |
|----|---------|----------|----------|----------|---------|
| A1 | Hardcoded key | High | Secrets Management | ISO 27001 A.10 | Confirmed |
| A2 | Missing rate limit | Medium | Authorization | N/A | Conditional |
| A3 | Weak crypto | Low | Secrets Management | PCI DSS Req 3 | Latent |

## 10. Detailed Findings

Prose here might casually say a control is "confirmed" working, or that
authorization looks "conditional" on config -- this must not be double
counted by the register parser above.

## 12. Design Verdict & Remediation Roadmap

**Design verdict:** Sound with conditions
"""


def test_extract_verdict_counts_from_register_only():
    counts = extract_verdict_counts(REGISTER_REPORT)
    assert counts == {"confirmed": 1, "conditional": 1, "latent": 1}


def test_extract_verdict_counts_ignores_prose_mentions():
    # The Detailed Findings prose above mentions "confirmed" and
    # "conditional" in passing -- must not inflate the register counts.
    text = "# R\n\n## 9. Findings Register\n\nNo findings.\n\n## 10. Detailed Findings\nSomething confirmed here, conditional there.\n"
    assert extract_verdict_counts(text) == {"confirmed": 0, "conditional": 0, "latent": 0}


def test_extract_root_causes_returns_category_per_finding():
    assert extract_root_causes(REGISTER_REPORT) == ["Secrets Management", "Authorization", "Secrets Management"]


def test_extract_standards_deviated_excludes_na():
    standards = extract_standards_deviated(REGISTER_REPORT)
    assert standards == ["ISO 27001 A.10", "PCI DSS Req 3"]
    assert "N/A" not in standards


def test_extract_ccm_conformance_all_four_states():
    conformance = extract_ccm_conformance(REGISTER_REPORT)
    assert conformance["A&A"] == "Partial"
    assert conformance["AIS"] == "Conformant"
    assert conformance["HRS"] == "Not Assessed (process-assured)"
    assert conformance["DCS"] == "Not Applicable"


def test_extract_ccm_conformance_ignores_unrecognized_codes():
    text = "| Some Row | XYZ | Conformant | evidence |\n"
    assert extract_ccm_conformance(text) == {}


def test_conformance_to_score_mapping():
    assert conformance_to_score("Conformant") == 100.0
    assert conformance_to_score("Partial") == 50.0
    assert conformance_to_score("Non-conformant") == 0.0
    assert conformance_to_score("Not Assessed (process-assured)") is None
    assert conformance_to_score("Not Applicable") is None


def test_is_process_assured():
    assert is_process_assured("Not Assessed (process-assured)") is True
    assert is_process_assured("Conformant") is False


def test_classify_design_verdict_all_three_buckets():
    assert classify_design_verdict("Sound") == "approve"
    assert classify_design_verdict("Sound with conditions") == "conditions"
    assert classify_design_verdict("Not sound") == "reject"
    assert classify_design_verdict(None) is None
    assert classify_design_verdict("") is None


def test_classify_design_verdict_not_sound_not_confused_with_sound():
    # "not sound" contains "sound" as a substring -- must check it first.
    assert classify_design_verdict("Not sound -- critical gaps remain") == "reject"


# ---------------------------------------------------------------------------
# Threat Modeling: threat register, model depth, assumptions
# ---------------------------------------------------------------------------

THREAT_MODEL_REPORT = """\
# Threat Model Report

## 1. Executive Summary

**Overall risk rating:** Medium
**Model depth:** Feature-level.

## 4. Assumptions

| ID | Assumption | Validity | Note |
|----|------------|----------|------|
| X1 | Upstream gateway authenticates all requests | Falsified | found a bypass route |
| X2 | Platform isolates tenants at the network layer | Holds | verified in config |
| X3 | Downstream service validates its own input | Unverified | not checked this round |

## 8. Threat Register

| ID | Threat | Archetype | Asset Class | Boundary | STRIDE | Severity | Disposition | Test Reference |
|----|--------|-----------|-------------|----------|--------|----------|--------------|-----------------|
| T1 | Unauthenticated call to internal svc | Unauthenticated internal service call | Process | B1 | E | High | Gap | none |
| T2 | Model prompt injection via tool output | Unbounded tool invocation | Model/Agent | B1 | T | Medium | Mitigated | test_prompt_inj_01 |

## 10. Detailed Threats

Prose here might casually mention a threat is "mitigated" or an assumption
"holds" -- this must not be double counted by the register/assumptions
parsers above.
"""


def test_extract_threat_register_rows_parses_all_columns():
    rows = extract_threat_register_rows(THREAT_MODEL_REPORT)
    assert len(rows) == 2
    assert rows[0] == {
        "id": "T1",
        "threat": "Unauthenticated call to internal svc",
        "archetype": "Unauthenticated internal service call",
        "asset_class": "Process",
        "boundary": "B1",
        "stride": "E",
        "severity": "High",
        "disposition": "Gap",
        "test_reference": "none",
    }
    assert rows[1]["disposition"] == "Mitigated"
    assert rows[1]["test_reference"] == "test_prompt_inj_01"


def test_extract_threat_register_rows_empty_for_reports_without_the_section():
    assert extract_threat_register_rows("# R\n\nNo threats here.\n") == []


def test_extract_model_depth_normalizes_recognized_labels():
    assert extract_model_depth(THREAT_MODEL_REPORT) == "Feature-level"
    assert extract_model_depth("**Model depth:** Full\n") == "Full"
    assert extract_model_depth("**Model depth:** Lightweight.\n") == "Lightweight"


def test_extract_model_depth_returns_raw_value_when_unrecognized():
    assert extract_model_depth("**Model depth:** Somewhere in between\n") == "Somewhere in between"


def test_extract_model_depth_returns_none_when_absent():
    assert extract_model_depth("# R\n\nNo depth line.\n") is None


def test_extract_assumption_validity_counts():
    counts = extract_assumption_validity_counts(THREAT_MODEL_REPORT)
    assert counts == {"holds": 1, "falsified": 1, "unverified": 1}


def test_extract_assumption_validity_counts_ignores_prose_mentions():
    text = "# R\n\n## 4. Assumptions\n\nNo table here.\n\n## 10. Detailed Threats\nAn assumption holds, apparently.\n"
    assert extract_assumption_validity_counts(text) == {"holds": 0, "falsified": 0, "unverified": 0}


def test_extract_falsified_assumptions_returns_only_falsified_text():
    assert extract_falsified_assumptions(THREAT_MODEL_REPORT) == ["Upstream gateway authenticates all requests"]
