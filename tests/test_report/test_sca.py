from __future__ import annotations

from secfoo.report.sca import (
    extract_cve_by_dependency_id,
    extract_dependency_inventory_rows,
    extract_narrative_by_dependency_id,
    extract_risk_register_rows,
    inventory_lookup,
    osv_keys_for_report,
    resolve_ecosystem,
)

SAMPLE_REPORT = """\
# SCA Report — Reachability & Upgrade Triage

## 1. Executive Summary
Test summary. **Overall risk rating:** High

## 2. Dependency Inventory

| Package | Version | Direct/Transitive | Ecosystem | Source manifest |
|---------|---------|--------------------|-----------|------------------|
| aiohttp | 3.8.0 | Direct | Python | requirements.txt |
| @babel/core | 7.0.0-beta.1 | Direct | Node.js | package.json |
| some-alpine-pkg | 1.0.0 | Direct | Alpine | Dockerfile |

## 3. Version Hygiene
No notable issues.

## 4. Risk Register

| ID | Package | Version | Issue | Severity | Reachability | Fixed in |
|----|---------|---------|-------|----------|---------------|----------|
| D1 | aiohttp | 3.8.0 | Invalid IPv6 URL DoS class issue | High | Reachable | 3.8.1 |
| D2 | @babel/core | 7.0.0-beta.1 | prototype pollution class issue | Medium | Conditionally reachable | 7.0.1 |
| D3 | ghost-package | 9.9.9 | unverified class issue, not in inventory | Low | Not reachable | unknown |
| D4 | some-alpine-pkg | 1.0.0 | unverified issue class | Medium | Reachable | unknown |

## 5. Detailed Findings

### [HIGH] D1: aiohttp@3.8.0 — Invalid IPv6 URL DoS
- **Package / version:** aiohttp 3.8.0, **CVE:** CVE-2022-33124, **Severity:** High
- **Reachability:** Reachable, evidence at app.py:42
- **Fixed in:** 3.8.1, patch bump
- **Breaking changes:** none expected
- **Recommendation:** upgrade to 3.8.1

### [MEDIUM] D2: @babel/core@7.0.0-beta.1 — prototype pollution class issue
- **Package / version:** @babel/core 7.0.0-beta.1, **CVE:** unverified, **Severity:** Medium
- **Reachability:** Conditionally reachable, evidence at build.js:10
- **Fixed in:** 7.0.1, minor bump
- **Breaking changes:** none expected
- **Recommendation:** upgrade to 7.0.1

### [LOW] D3: ghost-package@9.9.9 — unverified class issue, not in inventory
- **Package / version:** ghost-package 9.9.9, **CVE:** unverified, **Severity:** Low
- **Reachability:** Not reachable, no call site found
- **Fixed in:** unknown
- **Breaking changes:** none expected
- **Recommendation:** monitor upstream

### [MEDIUM] D4: some-alpine-pkg@1.0.0 — unverified issue class
- **Package / version:** some-alpine-pkg 1.0.0, **CVE:** unverified, **Severity:** Medium
- **Reachability:** Reachable, evidence at Dockerfile:3
- **Fixed in:** unknown
- **Breaking changes:** none expected
- **Recommendation:** review base image

## 6. Reachability Summary
| Package | Affected API | Called from | Verdict |
|---------|--------------|-------------|---------|
| aiohttp | URL parser | app.py:42 | Reachable |

## 7. Upgrade Plan
P0: none.

## 8. Supply-Chain Hygiene
No install-time scripts observed.
"""


def test_extract_dependency_inventory_rows_parses_all_columns():
    rows = extract_dependency_inventory_rows(SAMPLE_REPORT)
    assert len(rows) == 3
    assert rows[0] == {
        "package": "aiohttp",
        "version": "3.8.0",
        "directness": "Direct",
        "ecosystem": "Python",
        "source_manifest": "requirements.txt",
    }
    # Scoped npm package name (contains "@" and would contain "/" too,
    # e.g. "@babel/core" -- no "/" here only because this fixture package
    # has none, but the pipe-delimited cell regex doesn't care either way).
    assert rows[1]["package"] == "@babel/core"
    assert rows[1]["version"] == "7.0.0-beta.1"
    assert rows[1]["ecosystem"] == "Node.js"
    assert rows[2]["ecosystem"] == "Alpine"


def test_extract_dependency_inventory_rows_skips_header_and_separator():
    rows = extract_dependency_inventory_rows(SAMPLE_REPORT)
    packages = {r["package"] for r in rows}
    assert "Package" not in packages
    assert not any(set(p) <= {"-", ":", " "} for p in packages)


def test_extract_dependency_inventory_rows_empty_for_reports_without_section():
    assert extract_dependency_inventory_rows("# R\n\nNo dependency table here.\n") == []


def test_extract_risk_register_rows_parses_all_columns():
    rows = extract_risk_register_rows(SAMPLE_REPORT)
    assert len(rows) == 4
    assert rows[0] == {
        "id": "D1",
        "package": "aiohttp",
        "version": "3.8.0",
        "issue": "Invalid IPv6 URL DoS class issue",
        "severity": "High",
        "reachability": "Reachable",
        "fixed_in": "3.8.1",
    }
    assert rows[1]["reachability"] == "Conditionally reachable"


def test_extract_risk_register_rows_includes_row_whose_package_is_not_in_inventory():
    """D3's package ("ghost-package") never appears in the Dependency
    Inventory table above -- extraction itself must still return it
    as-is; it's the dashboard builder's job to notice the missing join
    and mark ecosystem unknown, not this module's.
    """
    rows = extract_risk_register_rows(SAMPLE_REPORT)
    d3 = next(r for r in rows if r["id"] == "D3")
    assert d3["package"] == "ghost-package"

    inventory_packages = {r["package"] for r in extract_dependency_inventory_rows(SAMPLE_REPORT)}
    assert "ghost-package" not in inventory_packages


def test_extract_risk_register_rows_empty_for_reports_without_section():
    assert extract_risk_register_rows("# R\n\nNo risk register here.\n") == []


def test_extract_cve_by_dependency_id_maps_ids_to_report_text():
    result = extract_cve_by_dependency_id(SAMPLE_REPORT)
    assert result == {
        "D1": "CVE-2022-33124",
        "D2": "unverified",
        "D3": "unverified",
        "D4": "unverified",
    }


def test_extract_cve_by_dependency_id_empty_for_reports_without_section():
    assert extract_cve_by_dependency_id("# R\n\nNo detailed findings here.\n") == {}


def test_extract_cve_by_dependency_id_ignores_prose_mentions_outside_a_block():
    text = (
        "# R\n\n## 5. Detailed Findings\n\n"
        "Prose here might mention **CVE:** CVE-9999-0000 without a heading above it.\n"
    )
    assert extract_cve_by_dependency_id(text) == {}


def test_extract_narrative_by_dependency_id_parses_evidence_and_recommendation():
    result = extract_narrative_by_dependency_id(SAMPLE_REPORT)
    assert result["D1"]["reachability_evidence"] == "Reachable, evidence at app.py:42"
    assert result["D1"]["recommendation"] == "upgrade to 3.8.1"
    assert result["D2"]["reachability_evidence"] == "Conditionally reachable, evidence at build.js:10"
    assert result["D3"]["recommendation"] == "monitor upstream"


def test_extract_narrative_by_dependency_id_empty_for_reports_without_section():
    assert extract_narrative_by_dependency_id("# R\n\nNo detailed findings here.\n") == {}


def test_inventory_lookup_keys_by_lowercased_package_and_exact_version():
    lookup = inventory_lookup(SAMPLE_REPORT)
    assert lookup[("aiohttp", "3.8.0")] == "Python"
    assert lookup[("@babel/core", "7.0.0-beta.1")] == "Node.js"


def test_resolve_ecosystem_recognized_value():
    lookup = inventory_lookup(SAMPLE_REPORT)
    ecosystem_raw, ecosystem_osv = resolve_ecosystem("aiohttp", "3.8.0", lookup)
    assert ecosystem_raw == "Python"
    assert ecosystem_osv == "PyPI"


def test_resolve_ecosystem_unrecognized_value_never_guesses():
    lookup = inventory_lookup(SAMPLE_REPORT)
    ecosystem_raw, ecosystem_osv = resolve_ecosystem("some-alpine-pkg", "1.0.0", lookup)
    assert ecosystem_raw == "Alpine"
    assert ecosystem_osv is None


def test_resolve_ecosystem_package_absent_from_inventory():
    lookup = inventory_lookup(SAMPLE_REPORT)
    ecosystem_raw, ecosystem_osv = resolve_ecosystem("ghost-package", "9.9.9", lookup)
    assert ecosystem_raw is None
    assert ecosystem_osv is None


def test_osv_keys_for_report_returns_only_recognized_ecosystems():
    keys = osv_keys_for_report(SAMPLE_REPORT)
    # D1 (aiohttp/Python), D2 (@babel/core/Node.js) recognize; D3 (not in
    # inventory) and D4 (Alpine, unrecognized) must never be included.
    assert keys == {("PyPI", "aiohttp", "3.8.0"), ("npm", "@babel/core", "7.0.0-beta.1")}


def test_osv_keys_for_report_empty_for_reports_without_a_risk_register():
    assert osv_keys_for_report("# R\n\nNo risk register.\n") == set()
