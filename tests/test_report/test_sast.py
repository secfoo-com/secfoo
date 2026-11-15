from __future__ import annotations

import pytest

from secfoo.report.sast import (
    extract_description_by_id,
    extract_findings_register_rows,
    extract_recommendation_by_id,
    findings_with_fingerprints,
    fingerprint_for_row,
    parse_location,
    parse_locations,
)

SAMPLE_REPORT = """\
# SAST Report

## 1. Executive Summary
Test summary. **Overall risk rating:** High

## 2. Scope
Python, reviewed src/.

## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | SQL Injection via raw query | High | CWE-89 | A03:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | `app/db.py:42` | Confirmed |
| F2 | Second SQLi sink in same file | High | CWE-89 | A03:2021 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | `app/db.py:120` | Confirmed |
| F3 | Reflected XSS in search page | Medium | CWE-79 | A03:2021 | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | `app/views.py:8` | Confirmed |
| F4 | Weak crypto, unverified impact | Low | unverified | unverified | AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N | `app/crypto.py` | Latent |

## 4. Detailed Findings

### [HIGH] F1: SQL Injection via raw query
- **Severity:** High, **CWE:** CWE-89, **OWASP:** A03:2021, **Verdict:** Confirmed
- **Location:** `app/db.py:42`
- **Description:** Untrusted search term concatenated directly into a raw SQL query.
- **Vulnerable code:** ```query = f"SELECT * FROM users WHERE name = '{name}'"```
- **Recommendation:** Use parameterized queries.

### [HIGH] F2: Second SQLi sink in same file
- **Severity:** High, **CWE:** CWE-89, **OWASP:** A03:2021, **Verdict:** Confirmed
- **Location:** `app/db.py:120`
- **Description:** A second, unrelated raw query built from an admin filter param.
- **Vulnerable code:** ```query = f"SELECT * FROM logs WHERE user = '{user}'"```
- **Recommendation:** Use parameterized queries here too.

### [MEDIUM] F3: Reflected XSS in search page
- **Severity:** Medium, **CWE:** CWE-79, **OWASP:** A03:2021, **Verdict:** Confirmed
- **Location:** `app/views.py:8`
- **Description:** Search term rendered without escaping.
- **Vulnerable code:** ```return f"<div>{query}</div>"```
- **Recommendation:** Escape output or use the template autoescaper.

### [LOW] F4: Weak crypto, unverified impact
- **Severity:** Low, **CWE:** unverified, **OWASP:** unverified, **Verdict:** Latent
- **Location:** `app/crypto.py`
- **Description:** MD5 used for a non-security checksum; latent, not currently reachable.
- **Vulnerable code:** ```digest = hashlib.md5(data).hexdigest()```
- **Recommendation:** Migrate to SHA-256 if this ever becomes security-relevant.

## 5. Taint Summary
| Source | Sink | Path | Sanitized? |
|--------|------|------|------------|
| HTTP request | SQL query | app/db.py:42 | No |

## 6. Remediation Roadmap
P0: F1, F2.

## 7. Code-Fix Appendix
```diff
- query = f"SELECT * FROM users WHERE name = '{name}'"
+ query = "SELECT * FROM users WHERE name = %s"
```
"""


def test_extract_findings_register_rows_parses_all_columns():
    rows = extract_findings_register_rows(SAMPLE_REPORT)
    assert len(rows) == 4
    assert rows[0] == {
        "id": "F1",
        "title": "SQL Injection via raw query",
        "severity": "High",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "location": "`app/db.py:42`",
        "verdict": "Confirmed",
    }


def test_extract_findings_register_rows_skips_header_and_separator():
    rows = extract_findings_register_rows(SAMPLE_REPORT)
    titles = {r["title"] for r in rows}
    assert "Finding" not in titles
    assert not any(set(t) <= {"-", ":", " "} for t in titles)


def test_extract_findings_register_rows_empty_for_reports_without_section():
    assert extract_findings_register_rows("# R\n\nNo findings register here.\n") == []


def test_extract_findings_register_rows_allows_unverified_cwe_and_owasp():
    rows = extract_findings_register_rows(SAMPLE_REPORT)
    f4 = next(r for r in rows if r["id"] == "F4")
    assert f4["cwe"] == "unverified"
    assert f4["owasp"] == "unverified"


def test_extract_description_by_id():
    result = extract_description_by_id(SAMPLE_REPORT)
    assert result["F1"] == "Untrusted search term concatenated directly into a raw SQL query."
    assert result["F3"] == "Search term rendered without escaping."


def test_extract_description_by_id_empty_for_reports_without_section():
    assert extract_description_by_id("# R\n\nNo detailed findings here.\n") == {}


def test_extract_recommendation_by_id():
    result = extract_recommendation_by_id(SAMPLE_REPORT)
    assert result["F1"] == "Use parameterized queries."
    assert result["F4"] == "Migrate to SHA-256 if this ever becomes security-relevant."


def test_parse_location_splits_file_and_line():
    assert parse_location("`app/db.py:42`") == ("app/db.py", "42")


def test_parse_location_handles_missing_line_number():
    assert parse_location("`app/crypto.py`") == ("app/crypto.py", None)


def test_parse_location_handles_no_backticks():
    assert parse_location("app/db.py:42") == ("app/db.py", "42")


def test_parse_location_strips_backticks_from_a_multi_location_cell():
    """A multi-site cell resolves to the primary site in `parse_location`
    while `parse_locations` preserves every call site in order.
    """
    file_path, line = parse_location("`web/app.py:35`, `cli.py:308`")
    assert file_path == "web/app.py"
    assert line == "35"
    assert parse_locations("`web/app.py:35`, `cli.py:308`") == [
        ("web/app.py", 35, None),
        ("cli.py", 308, None),
    ]


@pytest.mark.parametrize(
    ("raw_location", "expected_sites", "expected_primary"),
    [
        (
            "config/env/all.js:8-9",
            [("config/env/all.js", 8, 9)],
            ("config/env/all.js", "8"),
        ),
        (
            "server.js:78-102, app/routes/session.js:116, …",
            [("server.js", 78, 102), ("app/routes/session.js", 116, None)],
            ("server.js", "78"),
        ),
        (
            "app/data/user-dao.js:25, :61",
            [("app/data/user-dao.js", 25, None), ("app/data/user-dao.js", 61, None)],
            ("app/data/user-dao.js", "25"),
        ),
        (
            "`server.js:135-137`, `app/views/layout.html:75`",
            [("server.js", 135, 137), ("app/views/layout.html", 75, None)],
            ("server.js", "135"),
        ),
        (
            "`app/data/user-dao.js:25`, `:61`",
            [("app/data/user-dao.js", 25, None), ("app/data/user-dao.js", 61, None)],
            ("app/data/user-dao.js", "25"),
        ),
        (
            "`artifacts/db-reset.js:18,27,35`; `test/e2e/fixtures/users/*.json`; `test/security/profile-test.js:37`",
            [
                ("artifacts/db-reset.js", 18, None),
                ("artifacts/db-reset.js", 27, None),
                ("artifacts/db-reset.js", 35, None),
                ("test/e2e/fixtures/users/*.json", None, None),
                ("test/security/profile-test.js", 37, None),
            ],
            ("artifacts/db-reset.js", "18"),
        ),
        (
            "C:\\work\\app.js:10-20; /srv/app/db.py:42:7",
            [("C:\\work\\app.js", 10, 20), ("/srv/app/db.py", 42, None)],
            ("C:\\work\\app.js", "10"),
        ),
        (
            "app/db.py:8-8, app/other.py:20-12",
            [("app/db.py", 8, None), ("app/other.py", 12, 20)],
            ("app/db.py", "8"),
        ),
    ],
)
def test_parse_locations_handles_ranges_lists_and_bare_continuations(
    raw_location, expected_sites, expected_primary
):
    assert parse_locations(raw_location) == expected_sites
    assert parse_location(raw_location) == expected_primary


def test_fingerprint_and_code_region_match_between_line_and_line_range(tmp_path):
    (tmp_path / "config" / "env").mkdir(parents=True)
    source = "\n".join(f"const line{i} = {i};" for i in range(1, 30))
    (tmp_path / "config" / "env" / "all.js").write_text(source, encoding="utf-8")

    row_range = {"cwe": "CWE-798", "location": "`config/env/all.js:8-9`, `artifacts/db-reset.js:15-18`"}
    row_single = {"cwe": "CWE-798", "location": "`config/env/all.js:8`"}
    assert fingerprint_for_row(row_range) == fingerprint_for_row(row_single)

    report_template = """\
# SAST Report

## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | Hardcoded secret | Medium | CWE-798 | A07:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | {loc} | Confirmed |
"""
    r_range = findings_with_fingerprints(
        report_template.format(loc="`config/env/all.js:8-9`, `artifacts/db-reset.js:15-18`"),
        workdir=tmp_path,
    )[0]
    r_single = findings_with_fingerprints(
        report_template.format(loc="`config/env/all.js:8`"),
        workdir=tmp_path,
    )[0]
    assert r_range["location_file"] == "config/env/all.js"
    assert r_range["location_line"] == "8"
    assert r_range["locations"] == [
        {"path": "config/env/all.js", "start_line": 8, "end_line": 9},
        {"path": "artifacts/db-reset.js", "start_line": 15, "end_line": 18},
    ]
    assert r_range["code_region_hash"] is not None
    assert r_range["code_region_hash"] == r_single["code_region_hash"]
    assert r_range["fingerprint"] == r_single["fingerprint"]


def test_fingerprint_for_row_is_stable_for_identical_cwe_and_file_without_region_hash():
    row_a = {"cwe": "CWE-89", "location": "`app/db.py:42`"}
    row_b = {"cwe": "CWE-89", "location": "`app/db.py:99`"}  # line drift without region hash
    assert fingerprint_for_row(row_a) == fingerprint_for_row(row_b)


def test_fingerprint_for_row_differs_when_region_hash_differs():
    row = {"cwe": "CWE-89", "location": "`app/db.py:42`"}
    assert fingerprint_for_row(row, region_hash="aaa") != fingerprint_for_row(row, region_hash="bbb")


def test_fingerprint_for_row_differs_across_different_cwe_or_file():
    base = {"cwe": "CWE-89", "location": "`app/db.py:42`"}
    different_cwe = {"cwe": "CWE-79", "location": "`app/db.py:42`"}
    different_file = {"cwe": "CWE-89", "location": "`app/other.py:42`"}
    assert fingerprint_for_row(base) != fingerprint_for_row(different_cwe)
    assert fingerprint_for_row(base) != fingerprint_for_row(different_file)


def test_fingerprint_for_row_ignores_title_by_design():
    reworded = {"cwe": "CWE-89", "location": "`app/db.py:42`"}
    original = {"cwe": "CWE-89", "location": "`app/db.py:42`"}
    assert fingerprint_for_row(original) == fingerprint_for_row(reworded)


def test_findings_with_fingerprints_disambiguates_same_cwe_same_file_collision():
    """F1 and F2 are two genuinely different SQLi sinks, same CWE, same
    file -- must NOT collapse onto the same fingerprint.
    """
    results = findings_with_fingerprints(SAMPLE_REPORT)
    f1 = next(r for r in results if r["id"] == "F1")
    f2 = next(r for r in results if r["id"] == "F2")
    assert f1["fingerprint"] != f2["fingerprint"]


def test_findings_with_fingerprints_no_collision_case_gets_no_line_component():
    """F3 (XSS) and F4 (crypto) are the only findings of their respective
    CWEs -- their fingerprint must equal the plain no-line-bucket
    fingerprint, so a later run with the line shifted still matches.
    """
    results = findings_with_fingerprints(SAMPLE_REPORT)
    f3 = next(r for r in results if r["id"] == "F3")
    assert f3["fingerprint"] == fingerprint_for_row({"cwe": "CWE-79", "location": "`app/views.py:999`"})


def test_findings_with_fingerprints_includes_joined_narrative_and_location():
    results = findings_with_fingerprints(SAMPLE_REPORT)
    f1 = next(r for r in results if r["id"] == "F1")
    assert f1["location_file"] == "app/db.py"
    assert f1["location_line"] == "42"
    assert f1["description"] == "Untrusted search term concatenated directly into a raw SQL query."
    assert f1["recommendation"] == "Use parameterized queries."


def test_findings_with_fingerprints_empty_for_reports_without_a_findings_register():
    assert findings_with_fingerprints("# R\n\nNo findings register.\n") == []
