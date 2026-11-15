"""Tests for documentation coverage parser and run reconciliation (#125)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secfoo.context_brief import build_context_brief
from secfoo.context_sources import parse_context_source
from secfoo.report.context_coverage import (
    MAX_NOTES_CHARS,
    MAX_ROWS,
    MAX_SOURCE_CHARS,
    coverage_for_run,
    parse_documentation_coverage,
)


def _minimal_pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode()
    return bytes(out)


# 1. standard table under "### Documentation coverage" parses all four columns.
def test_standard_table_parses_all_four_columns() -> None:
    report = """\
# Security Assessment Report

### Documentation coverage
| Source | Type | Reached | Notes |
|--------|------|---------|-------|
| https://example.com/arch | Confluence page | Yes | Read successfully |
"""
    rows = parse_documentation_coverage(report)
    assert len(rows) == 1
    assert rows[0].source == "https://example.com/arch"
    assert rows[0].type == "Confluence page"
    assert rows[0].reached is True
    assert rows[0].notes == "Read successfully"


# 2. headings variants and legacy format
@pytest.mark.parametrize(
    ("heading", "table_block", "notes_expected"),
    [
        (
            "## Documentation coverage",
            "| Source | Type | Reached | Notes |\n|---|---|---|---|\n| https://example.com/page | URL | Yes | All good |",
            "All good",
        ),
        (
            "## 5. Documentation coverage",
            "| Source | Type | Reached | Notes |\n|---|---|---|---|\n| https://example.com/page | URL | Yes | All good |",
            "All good",
        ),
        (
            "## 5. Documentation & Confluence Coverage",
            "| Source | Reached? | Secrets found |\n|---|---|---|\n| https://example.com/page | Yes | 3 secrets |",
            "3 secrets",
        ),
    ],
)
def test_heading_variants_and_legacy_headers(
    heading: str,
    table_block: str,
    notes_expected: str,
) -> None:
    report = f"""\
# Report
{heading}
{table_block}
"""
    rows = parse_documentation_coverage(report)
    assert len(rows) == 1
    assert rows[0].source == "https://example.com/page"
    assert rows[0].reached is True
    assert rows[0].notes == notes_expected


# 3. no heading / heading without table / header missing a reached column -> []
@pytest.mark.parametrize(
    "bad_report",
    [
        "# Report\n\nNo coverage section here.\n",
        "# Report\n\n### Documentation coverage\n\nNo table following this heading.\n",
        (
            "# Report\n\n### Documentation coverage\n"
            "| Source | Type | Notes |\n"
            "|---|---|---|\n"
            "| https://x.com | URL | ok |\n"
        ),
    ],
)
def test_missing_heading_or_table_or_column_returns_empty(bad_report: str) -> None:
    assert parse_documentation_coverage(bad_report) == []


# 4. separator row skipped; header not returned; stops at next heading or blank line; second table ignored
def test_separator_skipped_and_table_bounds() -> None:
    report = """\
# Report
### Documentation coverage
| Source | Type | Reached | Notes |
|:-------|:-----|:--------|:------|
| https://first.test | URL | Yes | First |

| Source | Type | Reached | Notes |
|---|---|---|---|
| https://second.test | URL | Yes | Ignored second table |

## 6. Next Section
| Col1 | Col2 |
"""
    rows = parse_documentation_coverage(report)
    assert len(rows) == 1
    assert rows[0].source == "https://first.test"
    assert rows[0].notes == "First"


# 5. escaped pipe in a cell; backticks and **bold** stripped; extra whitespace collapsed
def test_escaped_pipe_formatting_and_whitespace() -> None:
    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| `https://example.test/a\\|b` | **local file** | **Yes** | multiple   spaces  \\|  and   words |
"""
    rows = parse_documentation_coverage(report)
    assert len(rows) == 1
    assert rows[0].source == "https://example.test/a|b"
    assert rows[0].type == "local file"
    assert rows[0].reached is True
    assert rows[0].notes == "multiple spaces | and words"


# 6. reached parametrized: True, False, Partial
@pytest.mark.parametrize(
    ("reached_str", "expected_reached"),
    [
        ("Yes", True),
        ("yes", True),
        ("**Yes**", True),
        ("Y", True),
        ("True", True),
        ("Reached", True),
        ("\u2705", True),
        ("\u2713", True),
        ("No", False),
        ("not reached", False),
        ("n/a", False),
        ("-", False),
        ("", False),
        ("Unreachable", False),
    ],
)
def test_reached_boolean_parsing(reached_str: str, expected_reached: bool) -> None:
    report = f"""\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| src1 | file | {reached_str} | note |
"""
    rows = parse_documentation_coverage(report)
    assert len(rows) == 1
    assert rows[0].reached is expected_reached


@pytest.mark.parametrize(
    ("reached_str", "notes_in", "expected_notes"),
    [
        ("Partial", "", "Partial"),
        ("Partial", "page 2 only", "Partial: page 2 only"),
        ("Partial - page 2 only", "", "Partial: page 2 only"),
    ],
)
def test_reached_partial_modifies_notes(
    reached_str: str,
    notes_in: str,
    expected_notes: str,
) -> None:
    report = f"""\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| src1 | file | {reached_str} | {notes_in} |
"""
    rows = parse_documentation_coverage(report)
    assert len(rows) == 1
    assert rows[0].reached is False
    assert rows[0].notes == expected_notes
    assert rows[0].notes.startswith("Partial")


# 7. caps: 1000-char source/notes truncated to caps; 150 data rows return MAX_ROWS
def test_caps_and_max_rows() -> None:
    long_source = "s" * 1000
    long_notes = "n" * 1000
    report = f"""\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| {long_source} | file | Yes | {long_notes} |
"""
    rows = parse_documentation_coverage(report)
    assert len(rows) == 1
    assert len(rows[0].source) == MAX_SOURCE_CHARS
    assert len(rows[0].notes) == MAX_NOTES_CHARS

    many_rows_lines = ["### Documentation coverage", "| Source | Type | Reached | Notes |", "|---|---|---|---|"]
    for i in range(150):
        many_rows_lines.append(f"| src_{i} | type_{i} | Yes | note_{i} |")
    many_rows_report = "\n".join(many_rows_lines)
    parsed_many = parse_documentation_coverage(many_rows_report)
    assert len(parsed_many) == MAX_ROWS


# 8. CRLF input parses the same as LF
def test_crlf_input_matches_lf() -> None:
    report_lf = """\
# Report
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| https://example.com/doc | URL | Yes | ok |
"""
    report_crlf = report_lf.replace("\n", "\r\n")
    assert parse_documentation_coverage(report_crlf) == parse_documentation_coverage(report_lf)


# 9. coverage_for_run: brief None -> []
def test_coverage_for_run_brief_none() -> None:
    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| https://example.com | URL | Yes | ok |
"""
    assert coverage_for_run(None, report, run_succeeded=True) == []


# 10. URL matched by substring inside [Page](url) markup
def test_coverage_for_run_url_matched_by_substring() -> None:
    url = "https://acme.atlassian.net/wiki/x"
    source = parse_context_source(url)
    brief = build_context_brief([source], [])
    assert brief is not None

    report = f"""\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| [Arch Page]({url}) | Confluence page | Yes | verified |
"""
    records = coverage_for_run(brief, report, run_succeeded=True)
    assert len(records) == 1
    assert records[0].source == url
    assert records[0].reached is True
    assert records[0].notes == "verified"


# 11. positional fallback when counts equal and labels do not match
def test_coverage_for_run_positional_fallback() -> None:
    s1 = parse_context_source("https://example.com/one")
    s2 = parse_context_source("https://example.com/two")
    brief = build_context_brief([s1, s2], [])
    assert brief is not None

    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| Unmatched Alpha | URL | Yes | first note |
| Unmatched Beta | URL | No | second note |
"""
    records = coverage_for_run(brief, report, run_succeeded=True)
    assert len(records) == 2
    assert records[0].source == "https://example.com/one"
    assert records[0].reached is True
    assert records[0].notes == "first note"
    assert records[1].source == "https://example.com/two"
    assert records[1].reached is False
    assert records[1].notes == "second note"


# 12. missing row for a URL -> reached False, "not reported by the agent"
def test_coverage_for_run_missing_row_for_url() -> None:
    s = parse_context_source("https://example.com/missing")
    brief = build_context_brief([s], [])
    assert brief is not None

    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
"""
    records = coverage_for_run(brief, report, run_succeeded=True)
    assert len(records) == 1
    assert records[0].reached is False
    assert records[0].notes == "not reported by the agent"


# 13. run_succeeded False -> URL "run did not complete"; an inlined local file stays reached True
def test_coverage_for_run_run_succeeded_false(tmp_path: Path) -> None:
    doc = tmp_path / "inlined.md"
    doc.write_text("# Inlined", encoding="utf-8")
    s_file = parse_context_source(str(doc))
    s_url = parse_context_source("https://example.com/url")
    brief = build_context_brief([s_url, s_file], [])
    assert brief is not None

    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| https://example.com/url | URL | Yes | Agent saw it |
| inlined.md | local file | Yes | Agent saw it |
"""
    records = coverage_for_run(brief, report, run_succeeded=False)
    assert len(records) == 2

    # URL record when run failed
    assert records[0].source == "https://example.com/url"
    assert records[0].reached is False
    assert records[0].notes == "run did not complete"

    # Inlined local file stays True
    assert records[1].source == "inlined.md"
    assert records[1].reached is True


# 14. local file secfoo could not read stays False with entry note, even if agent wrote Yes
def test_coverage_for_run_unread_local_file_stays_false(tmp_path: Path) -> None:
    empty_pdf = tmp_path / "scanned.pdf"
    empty_pdf.write_bytes(_minimal_pdf(""))
    source = parse_context_source(str(empty_pdf))
    brief = build_context_brief([source], [])
    assert brief is not None
    assert brief.entries[0].reached is False

    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| scanned.pdf | local file | Yes | Agent claimed read |
"""
    records = coverage_for_run(brief, report, run_succeeded=True)
    assert len(records) == 1
    assert records[0].source == "scanned.pdf"
    assert records[0].reached is False
    assert "no extractable text" in records[0].notes


# 15. extra agent row appended when run succeeded and not appended when it did not
def test_coverage_for_run_extra_agent_rows() -> None:
    s = parse_context_source("https://example.com/doc")
    brief = build_context_brief([s], [])
    assert brief is not None

    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| https://example.com/doc | URL | Yes | ok |
| Extra Agent Discovery | | Yes | Found via search |
"""
    records_success = coverage_for_run(brief, report, run_succeeded=True)
    assert len(records_success) == 2
    assert records_success[1].source == "Extra Agent Discovery"
    assert records_success[1].type == "reported by the agent"
    assert records_success[1].reached is True
    assert records_success[1].notes == "Found via search"

    records_fail = coverage_for_run(brief, report, run_succeeded=False)
    assert len(records_fail) == 1
    assert records_fail[0].source == "https://example.com/doc"


# 16. no record field contains str(tmp_path)
def test_coverage_for_run_no_absolute_paths(tmp_path: Path) -> None:
    nested = tmp_path / "nested" / "dir"
    nested.mkdir(parents=True)
    doc = nested / "system_spec.md"
    doc.write_text("# Spec\nContent", encoding="utf-8")
    source = parse_context_source(str(doc))
    brief = build_context_brief([source], [])
    assert brief is not None

    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| system_spec.md | local file | Yes | Inlined |
"""
    records = coverage_for_run(brief, report, run_succeeded=True)
    assert len(records) == 1
    assert str(tmp_path) not in records[0].source
    assert str(tmp_path) not in records[0].type
    assert str(tmp_path) not in records[0].notes


def test_coverage_for_run_exact_match_precedence_over_substring() -> None:
    s1 = parse_context_source("https://x.example/wiki/1")
    s2 = parse_context_source("https://x.example/wiki/12")
    brief = build_context_brief([s1, s2], [])
    assert brief is not None

    report = """\
### Documentation coverage
| Source | Type | Reached | Notes |
|---|---|---|---|
| https://x.example/wiki/12 | URL | Yes | note for 12 |
| https://x.example/wiki/1 | URL | Yes | note for 1 |
"""
    records = coverage_for_run(brief, report, run_succeeded=True)
    assert len(records) == 2
    assert records[0].source == "https://x.example/wiki/1"
    assert records[0].notes == "note for 1"
    assert records[1].source == "https://x.example/wiki/12"
    assert records[1].notes == "note for 12"
