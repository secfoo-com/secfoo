from __future__ import annotations

from secfoo.report.secret_scanning import (
    extract_findings_register_rows,
    extract_narrative_by_id,
    findings_with_narrative,
)

SAMPLE_REPORT = """\
# Secret Scanning Report

## 1. Executive Summary
Test summary. **Overall risk rating:** High

## 2. Scope
Scanned src/ and .github/workflows/, including git history back to the first commit.

## 3. Findings Register
| ID | Secret type | Location | Source | Validity | Severity |
|----|-------------|----------|--------|----------|----------|
| S1 | AWS access key | `deploy/ci.yml:14` | config | Looks live | High |
| S2 | Slack webhook URL | `docs/onboarding` (Confluence) | docs | Unclear | Medium |
| S3 | Legacy DB password | `git log -- config/old.py:8` | history | Placeholder | Low |

## 4. Detailed Findings

### [HIGH] S1: AWS access key in deploy/ci.yml
- **Type:** AWS access key, **Source:** config, **Validity:** Looks live
- **Location:** `deploy/ci.yml:14`
- **Evidence:** AKIAJ4F2...
- **Exposure:** Anyone with read access to the CI config can use this key against the production AWS account.
- **Remediation:** Rotate the key immediately, then move it to a secret manager.

### [MEDIUM] S2: Slack webhook URL in onboarding docs
- **Type:** Slack webhook URL, **Source:** docs, **Validity:** Unclear
- **Location:** Onboarding runbook (Confluence)
- **Evidence:** https://hooks.slack.com/services/T000...
- **Exposure:** Anyone who can read the onboarding page could post to the team's Slack channel.
- **Remediation:** Rotate the webhook and confirm the page is access-restricted.

### [LOW] S3: Legacy DB password in removed file
- **Type:** Legacy DB password, **Source:** history, **Validity:** Placeholder
- **Location:** `config/old.py:8` (removed, still in git history)
- **Evidence:** changeme123
- **Exposure:** Looks like a placeholder default, low real-world exposure.
- **Remediation:** Confirm it was never live; if uncertain, rotate anyway and rewrite history.

## 5. Documentation & Confluence Coverage
| Source | Reached? | Secrets found |
|--------|----------|----------------|
| Onboarding runbook | Yes | 1 |

## 6. Remediation Roadmap
P0: S1.

## 7. Prevention
Add pre-commit secret scanning and move remaining secrets to a manager.
"""


def test_extract_findings_register_rows_parses_all_columns():
    rows = extract_findings_register_rows(SAMPLE_REPORT)
    assert len(rows) == 3
    assert rows[0] == {
        "id": "S1",
        "secret_type": "AWS access key",
        "location": "`deploy/ci.yml:14`",
        "source": "config",
        "validity": "Looks live",
        "severity": "High",
    }


def test_extract_findings_register_rows_skips_header_and_separator():
    rows = extract_findings_register_rows(SAMPLE_REPORT)
    types = {r["secret_type"] for r in rows}
    assert "Secret type" not in types
    assert not any(set(t) <= {"-", ":", " "} for t in types)


def test_extract_findings_register_rows_empty_for_reports_without_section():
    assert extract_findings_register_rows("# R\n\nNo findings register here.\n") == []


def test_extract_findings_register_rows_preserves_docs_and_history_locations():
    rows = extract_findings_register_rows(SAMPLE_REPORT)
    s2 = next(r for r in rows if r["id"] == "S2")
    assert s2["source"] == "docs"
    assert "Confluence" in s2["location"]
    s3 = next(r for r in rows if r["id"] == "S3")
    assert s3["source"] == "history"
    assert s3["validity"] == "Placeholder"


def test_extract_narrative_by_id():
    narrative = extract_narrative_by_id(SAMPLE_REPORT)
    assert narrative["S1"]["evidence"] == "AKIAJ4F2..."
    assert "production AWS account" in narrative["S1"]["exposure"]
    assert "Rotate the key immediately" in narrative["S1"]["remediation"]
    assert narrative["S2"]["evidence"].startswith("https://hooks.slack.com")


def test_extract_narrative_by_id_empty_for_reports_without_section():
    assert extract_narrative_by_id("# R\n\nNo detailed findings here.\n") == {}


def test_findings_with_narrative_joins_register_and_detail():
    results = findings_with_narrative(SAMPLE_REPORT)
    assert len(results) == 3
    s1 = next(r for r in results if r["id"] == "S1")
    assert s1["secret_type"] == "AWS access key"
    assert s1["evidence"] == "AKIAJ4F2..."
    assert s1["remediation"].startswith("Rotate the key immediately")


def test_findings_with_narrative_empty_for_reports_without_a_findings_register():
    assert findings_with_narrative("# R\n\nNo findings register.\n") == []
