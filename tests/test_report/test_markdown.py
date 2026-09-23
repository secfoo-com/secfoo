from __future__ import annotations

from secfoo.report.markdown import render_report_html, strip_preamble

SAMPLE_REPORT = """\
# Threat Assessment Report

## Summary
Overall risk is moderate.

## Findings

### [HIGH] Missing auth check
- **Severity:** High
- **Location:** app.py
- **Description:** desc
- **Recommendation:** fix it

### [LOW] Verbose error messages
- **Severity:** Low
- **Location:** N/A
- **Description:** desc2
- **Recommendation:** fix it too

## Coverage Notes
Reviewed everything.
"""


def test_render_report_html_produces_html():
    html = render_report_html(SAMPLE_REPORT)
    assert "<h1>Threat Assessment Report</h1>" in html
    assert "Missing auth check" in html


def test_severity_badges_injected_with_correct_classes():
    html = render_report_html(SAMPLE_REPORT)
    assert 'badge--error">HIGH</span> Missing auth check' in html
    assert 'badge--teal">LOW</span> Verbose error messages' in html


def test_raw_html_in_report_is_escaped_not_executed():
    """Report content is agent-generated Markdown, possibly derived from an
    untrusted target repo, and gets rendered with Jinja's `|safe`. Raw HTML
    (e.g. a <script> tag the agent quoted from a malicious repo, or a
    prompt-injection attempt) must render as inert text, not live markup.
    """
    html = render_report_html("# Report\n\n<script>alert(document.cookie)</script>\n")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_malformed_report_still_renders_plain():
    html = render_report_html("Just some plain text, no structure.")
    assert "Just some plain text" in html


def test_strip_preamble_removes_leading_chatter():
    text = "Nothing else to check here. I have enough to produce the report now.\n\n" + SAMPLE_REPORT
    assert strip_preamble(text) == SAMPLE_REPORT


def test_strip_preamble_leaves_clean_report_unchanged():
    assert strip_preamble(SAMPLE_REPORT) == SAMPLE_REPORT


def test_strip_preamble_leaves_text_unchanged_when_no_heading_found():
    text = "Just some plain text, no heading at all."
    assert strip_preamble(text) == text


def test_strip_preamble_falls_back_to_numbered_section_one():
    """Regression test for the copilot adapter: it unpromptedly runs its
    own native security-scan tool first (an unrelated "##"/"###" preamble
    with no single top-level "#" heading anywhere) before going straight
    into the required numbered sections without ever writing the "#
    <Skill> Report" title. The primary anchor never fires here, so this
    must fall back to "## 1. Executive Summary" instead of giving up.
    """
    required_report = "## 1. Executive Summary\nRisk is high.\n\n## 2. Scope\n..."
    text = (
        "## Security Findings\n\n"
        "### Alert 1\n**Severity: CRITICAL**\nSome native alert content.\n\n"
        "## Remediation Roadmap\n- fix it\n\n"
        + required_report
    )
    assert strip_preamble(text) == required_report


def test_strip_preamble_fallback_ignores_unrelated_numbered_sections():
    """The fallback must match the literal "## 1. Executive Summary"
    text, not just any "## 1. <anything>" heading -- otherwise a
    preamble that numbers its own unrelated section "1." (a plan, a
    to-do list) gets matched instead of the real report, cutting to the
    wrong, earlier point rather than past the preamble entirely.
    """
    required_report = "## 1. Executive Summary\nThe real content that should be kept."
    text = (
        "## My plan\n1. Read the target files\n2. Check for issues\n\n"
        "## 1. Setup notes before I start\n"
        "This has nothing to do with the real report at all.\n\n"
        + required_report
    )
    assert strip_preamble(text) == required_report


def test_strip_preamble_prefers_top_level_heading_over_numbered_fallback():
    """When both anchors are present, the title must win so the report
    keeps its own heading -- proved by placing "## 1. Executive Summary"
    chatter *before* the real title, which the fallback alone would
    match and cut into instead of skipping past entirely.
    """
    text = "## 1. Executive Summary\nThis mentions the section name but isn't the report.\n\n" + SAMPLE_REPORT
    assert strip_preamble(text) == SAMPLE_REPORT


FINDINGS_REGISTER_REPORT = """\
# Threat Assessment Report

## Findings Register

| ID | Finding | Severity | Verdict | CWE |
|----|---------|----------|---------|-----|
| F1 | Missing auth | High | Confirmed | CWE-306 |
| F2 | Weak default cred | Medium | Conditional (host reachable) | CWE-1188 |

## Security Controls Matrix

| Control | Status | Evidence |
|---|---|---|
| Authentication | Implemented | JWT enforced |
| Authorization | Partial | RBAC exists, but self-elevation possible |
| CORS | Not Implemented | wildcard origin |
"""


def test_pipe_tables_render_as_real_html_tables():
    # Regression test: the bare "commonmark" preset does NOT parse GFM pipe
    # tables -- they used to silently fall through as a plain <p> of
    # literal "| a | b |" text instead of an actual <table>.
    html = render_report_html(FINDINGS_REGISTER_REPORT)
    assert "<table" in html
    assert "<th>ID</th>" in html
    assert "<td>" in html
    assert "| F1 | Missing auth |" not in html


def test_tables_get_design_system_wrap_and_class():
    html = render_report_html(FINDINGS_REGISTER_REPORT)
    assert '<div class="table-wrap"><table class="table">' in html
    assert html.count('<div class="table-wrap">') == html.count("</table></div>")


def test_exact_match_cells_get_severity_and_verdict_badges():
    html = render_report_html(FINDINGS_REGISTER_REPORT)
    assert '<td><span class="badge badge--error">High</span></td>' in html
    assert '<td><span class="badge badge--error">Confirmed</span></td>' in html
    # "Conditional (host reachable)" is not an exact match -- must not be badged.
    assert "Conditional (host reachable)</td>" in html
    assert 'badge--warning">Conditional (host reachable)' not in html


def test_exact_match_cells_get_controls_matrix_status_badges():
    html = render_report_html(FINDINGS_REGISTER_REPORT)
    assert '<td><span class="badge badge--success">Implemented</span></td>' in html
    assert '<td><span class="badge badge--warning">Partial</span></td>' in html
    assert '<td><span class="badge badge--error">Not Implemented</span></td>' in html


def test_prose_mentioning_severity_words_is_not_badged():
    report = "# Report\n\n## Summary\nThis is a High severity concern overall.\n"
    html = render_report_html(report)
    assert "badge--error" not in html
    assert "High severity concern" in html


DIFF_REPORT = """\
# Threat Assessment Report

## Code-Fix Appendix

```diff
--- a/app.py
+++ b/app.py
@@
 def handler():
+    check_auth()
-    pass
```
"""


def test_diff_blocks_get_add_and_del_line_spans():
    html = render_report_html(DIFF_REPORT)
    assert '<span class="diff-add">+    check_auth()</span>' in html
    assert '<span class="diff-del">-    pass</span>' in html
    # File header lines (+++/---) are diff metadata, not changed lines.
    assert "diff-add\">+++" not in html
    assert "diff-del\">---" not in html


# ---------------------------------------------------------------------------
# Mermaid diagrams
# ---------------------------------------------------------------------------

MERMAID_REPORT = """\
# Security Architecture Review Report

## 3. Architecture Overview

```mermaid
flowchart LR
  user([End user]) -->|"HTTPS"| api["API service"]
  api --> db[("Primary DB")]
```
"""


def test_mermaid_block_becomes_a_mermaid_figure():
    html = render_report_html(MERMAID_REPORT)
    assert '<pre class="mermaid">' in html
    assert 'class="mermaid-figure"' in html
    # Must NOT stay a plain code block, or mermaid.js will never see it.
    assert 'class="language-mermaid"' not in html


def test_mermaid_source_stays_html_escaped():
    """mermaid.js reads textContent (which the browser unescapes), so the
    diagram still parses -- while unescaped agent output never enters the
    DOM. Report content can originate from an untrusted target repo.
    """
    html = render_report_html(MERMAID_REPORT)
    assert "--&gt;" in html
    assert "-->" not in html.split('<pre class="mermaid">')[1].split("</pre>")[0]


def test_mermaid_figure_is_not_wrapped_as_a_table():
    html = render_report_html(MERMAID_REPORT)
    mermaid_part = html.split('class="mermaid-figure"')[1]
    assert "table-wrap" not in mermaid_part.split("</figure>")[0]


def test_non_mermaid_code_blocks_are_untouched():
    html = render_report_html("# R\n\n```python\nprint('hi')\n```\n")
    assert 'class="language-python"' in html
    assert "mermaid" not in html


def test_script_tag_inside_mermaid_block_is_escaped():
    html = render_report_html('# R\n\n```mermaid\nflowchart LR\n  a["<script>alert(1)</script>"]\n```\n')
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
