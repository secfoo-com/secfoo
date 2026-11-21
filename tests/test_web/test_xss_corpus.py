"""XSS regression corpus for agent-written report content (#118).

Reports are agent output over repositories that may be hostile, and the run
page renders them with `|safe`. Every payload below goes through the real
renderer and the real pages that show report data (the run page, the SAST
findings list and detail, the secret-scanning findings), and each page must
have nothing executable that the same page with harmless content lacks: no
new script, frame, object, form, base or meta element, no inline event
handler, and no link or resource URL with a scheme other than http(s).
"""

from __future__ import annotations

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secfoo.report.markdown import render_report_html
from secfoo.runner import update_sast_findings, update_secret_findings
from secfoo.storage.repository import RunRepository
from secfoo.web import secret_scanning_dashboard
from secfoo.web.app import STATIC_DIR, create_app

SAMPLE = Path(__file__).parents[2] / "examples" / "sample-output" / "nodegoat"

# name -> Markdown. Grouped as the issue lists them; each has the marker
# alert(1) or a foreign host so a leak is easy to spot in a failure.
CORPUS = {
    # raw HTML
    "script": "<script>alert(1)</script>",
    "script_block": "<script>\nalert(1)\n</script>",
    "img_onerror": "<img src=x onerror=alert(1)>",
    "svg_onload": "<svg onload=alert(1)><circle r=1 /></svg>",
    "svg_script": "<svg>\n<script>alert(1)</script>\n</svg>",
    "iframe": '<iframe src="javascript:alert(1)"></iframe>',
    "iframe_srcdoc": '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    "object": '<object data="javascript:alert(1)"></object>',
    "style": "<style>body{background:url(javascript:alert(1))}</style>",
    "meta_refresh": '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    "base": '<base href="javascript:alert(1)//">',
    "form": '<form action="javascript:alert(1)"><button>go</button></form>',
    "inline_handler": "**<b onclick=alert(1)>x</b>**",
    "comment_breakout": "<!-- --><script>alert(1)</script> -->",
    "cdata": "<![CDATA[<script>alert(1)</script>]]>",
    "math": "<math><mtext><a href=javascript:alert(1)>x</a></mtext></math>",
    # images: any image would be fetched on page load (exfiltration)
    "md_image": '![x](https://evil.example/x.png "t")',
    "md_image_js": "![x](javascript:alert(1))",
    "md_image_data_svg": "![x](data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+)",
    "md_image_ref": "![x][i]\n\n[i]: https://evil.example/x.png",
    # javascript: and other schemes in links
    "js_link": "[c](javascript:alert(1))",
    "js_link_case": "[c](JaVaScRiPt:alert(1))",
    "js_link_space": "[c](<  javascript:alert(1)>)",
    "js_link_entity": "[c](&#106;avascript:alert(1))",
    "js_link_hex_entity": "[c](&#x6A;avascript&#x3A;alert(1))",
    "js_link_tab": "[c](java\tscript:alert(1))",
    "js_link_newline": "[c](java\nscript:alert(1))",
    "js_link_null": "[c](java\x00script:alert(1))",
    "js_link_percent": "[c](javascript%3Aalert(1))",
    "js_reference_link": "[c][r]\n\n[r]: javascript:alert(1)",
    "js_autolink": "<javascript:alert(1)>",
    "vbscript": "[c](vbscript:msgbox(1))",
    "data_link": "[c](data:text/html,<script>alert(1)</script>)",
    "data_autolink": "<data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
    "file_link": "[c](file:///etc/passwd)",
    "protocol_relative": "[c](//evil.example/x)",
    "credentials_link": "[c](https://user:pass@evil.example)",
    # quotes in link titles and URLs (attribute breakout)
    "title_double_quote": '[c](https://ok.example "a\\" onmouseover=\\"alert(1)")',
    "title_single_quote": "[c](https://ok.example 'x\" onclick=\"alert(1)')",
    "title_paren": '[c](https://ok.example (x" onfocus="alert(1)))',
    "href_quote": '[c](https://ok.example/"onmouseover="alert(1))',
    "href_angle": "[c](<https://ok.example/\"><script>alert(1)</script>>)",
    # entities and headings (the badge post-processing rewrites <h3>)
    "entity_heading": "### [High] &lt;script&gt;alert(1)&lt;/script&gt;",
    "entity_double_escape": "### [High] &amp;lt;img src=x onerror=alert(1)&amp;gt;",
    "html_heading": "### [Critical] <img src=x onerror=alert(1)>",
    "badge_breakout": '### [High"><script>alert(1)</script>] title',
    "badge_cell": "| Severity |\n|---|\n| Critical\" onmouseover=\"alert(1) |",
    "table_cell_html": "| a | b |\n|---|---|\n| <script>alert(1)</script> | High |",
    # code: diff colouring and fence info strings
    "diff_block": "```diff\n+<script>alert(1)</script>\n- <img src=x onerror=alert(1)>\n```",
    "fence_info": '```"><script>alert(1)</script>\nx\n```',
    "inline_code": "`<script>alert(1)</script>`",
    # Mermaid: the source stays escaped text; mermaid.js runs in strict mode
    "mermaid_label_html": '```mermaid\ngraph TD\nA["<img src=x onerror=alert(1)>"] --> B\n```',
    "mermaid_click": "```mermaid\ngraph TD\nA --> B\nclick A call alert(1)\nclick B href \"javascript:alert(1)\"\n```",
    "mermaid_init_directive": '```mermaid\n%%{init: {"securityLevel": "loose"}}%%\ngraph TD\nA --> B\n```',
    "mermaid_pre_breakout": "```mermaid\n</pre><script>alert(1)</script>\n```",
    "mermaid_info_breakout": '```mermaid" onclick="alert(1)\ngraph TD\n```',
}

_ELEMENTS = {
    "script", "iframe", "frame", "frameset", "object", "embed", "applet", "base", "meta", "link",
    "form", "img", "image", "svg", "math", "video", "audio", "source", "track", "style", "template",
    "portal",
}
_URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "xlink:href", "background", "ping"}


class _Executable(HTMLParser):
    """Collects everything on a page that could run code or fetch a
    resource, so two pages can be compared."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: Counter = Counter()

    def handle_starttag(self, tag, attrs):
        if tag in _ELEMENTS:
            # A dashboard <script src> or <link href> is identified by its URL.
            self.found[(tag, dict(attrs).get("src") or dict(attrs).get("href") or dict(attrs).get("rel"))] += 1
        for name, value in attrs:
            value = (value or "").strip()
            handler = name.startswith("on") or name in {"srcdoc", "formaction"}
            if handler or (name in _URL_ATTRS and not _plain_url(value)):
                self.found[(tag, name, value)] += 1

    handle_startendtag = handle_starttag


def _plain_url(value: str) -> bool:
    """Same-origin path, fragment, or an http(s) URL with a host."""
    lowered = "".join(value.split()).lower()
    if lowered.startswith("//"):
        return False
    if lowered.startswith(("/", "#", "?")) or lowered == "":
        return True
    return lowered.startswith(("http://", "https://"))


def executable(html: str) -> Counter:
    parser = _Executable()
    parser.feed(html)
    parser.close()
    return parser.found


# ---------- the renderer on its own ----------

@pytest.mark.parametrize("name", CORPUS)
def test_rendered_report_has_nothing_executable(name):
    html = render_report_html(f"# SAST Report\n\n## 1. Executive Summary\n\n{CORPUS[name]}\n")
    assert executable(html) == Counter(), html


@pytest.mark.parametrize("name", CORPUS)
def test_payload_inside_a_finding_detail_block_has_nothing_executable(name):
    report = f"## 4. Detailed Findings\n\n### [HIGH] F1: title\n\n**Location:** `a.py:1`\n\n{CORPUS[name]}\n"
    assert executable(render_report_html(report)) == Counter()


def test_mermaid_source_stays_escaped_text():
    html = render_report_html(CORPUS["mermaid_pre_breakout"])
    assert '<pre class="mermaid">&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;\n</pre>' in html


def test_mermaid_runs_in_strict_mode_and_directives_cannot_change_it():
    """securityLevel "strict" makes Mermaid sanitize labels and drop click
    handlers; Mermaid's `secure` list (securityLevel is on it by default)
    is what stops a %%{init}%% directive in agent output from loosening it."""
    init = (STATIC_DIR / "js" / "mermaid-init.js").read_text(encoding="utf-8")
    assert 'securityLevel: "strict"' in init
    assert "secure:" not in init  # overriding `secure` could drop securityLevel from it


# ---------- the pages that show report data ----------

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.web.routes.runs.STORE_DIR", tmp_path)
    monkeypatch.setattr("secfoo.web.run_status.run_dir", lambda uuid: tmp_path / "reports" / uuid)
    # Render as an install with `secfoo vendor mermaid` done (CI has it):
    # diagrams are then live <pre class="mermaid"> blocks, the riskier case.
    monkeypatch.setattr("secfoo.web.app.mermaid_bundle_available", lambda: True)
    client = TestClient(create_app())
    client.store = tmp_path
    return client


def _completed_run(store: Path, skill_id: str, report: str) -> tuple[RunRepository, int, int, str]:
    repo = RunRepository()
    project_id = repo.upsert_project("p", "Payments API", "local")
    run_uuid = repo.create_run(project_id=project_id, skill_id=skill_id, skill_name=skill_id, agent_id="claude",
                               confluence_urls=[])
    report_path = store / f"{run_uuid}.md"
    report_path.write_text(report, encoding="utf-8")
    repo.complete_run(run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
                      prompt_path=None, stderr_excerpt=None)
    return repo, project_id, repo.get_run(run_uuid).id, run_uuid


def _poison_sast(payload: str) -> str:
    """The NodeGoat SAST report with the payload as F1's title, location,
    CWE and construct, and appended to its detail block."""
    one_line = " ".join(payload.split()).replace("|", "/")  # a register cell cannot hold a pipe
    report = (SAMPLE / "sast-report.md").read_text(encoding="utf-8")
    head, register_and_rest = report.split("## 3. Findings Register", 1)
    lines = register_and_rest.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("| F1 "):
            cells = line.split("|")
            cells[2] = f" {one_line} "
            cells[7] = f" `{one_line}`, `app.js:1` "
            lines[i] = "|".join(cells)
            break
    rest = "\n".join(lines).replace(
        "### [HIGH] F1: Server-side JS injection via `eval()` on POST body",
        f"### [HIGH] F1: {one_line}\n\n**Construct:** {one_line}\n\n{payload}\n",
    )
    return head + "## 3. Findings Register" + rest


def _baseline_and_poisoned(client, payload, build_report, pages):
    """`pages(run_uuid, repo)` -> list of URLs. Returns (baseline, poisoned)
    executable counters for each page, harmless content first."""
    results = []
    # The baseline has a harmless diagram, so pages that load Mermaid for
    # one (with the bundle vendored, as in CI) load it in the baseline too.
    for content in (HARMLESS, payload):
        client.store.joinpath("db.sqlite").unlink(missing_ok=True)
        repo, project_id, run_id, run_uuid = _completed_run(client.store, *build_report(content))
        update = update_sast_findings if build_report is _sast_report else update_secret_findings
        update(repo, project_id=project_id, run_id=run_id, report_text=build_report(content)[1])
        urls = pages(run_uuid, repo)
        repo.close()
        page_results = []
        for url in urls:
            response = client.get(url)
            assert response.status_code == 200, url
            page_results.append(executable(response.text))
        results.append(page_results)
    return results


HARMLESS = "plain text\n\n```mermaid\ngraph TD\n  A --> B\n```\n"


def _sast_report(content):
    return "sast", _poison_sast(content)


def _secret_report(content):
    one_line = " ".join(content.split()).replace("|", "/")
    report = (SAMPLE / "secret-scanning-report.md").read_text(encoding="utf-8")
    lines = report.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("| S1 "):
            cells = line.split("|")
            cells[2] = f" {one_line} "
            cells[3] = f" `{one_line}` "
            lines[i] = "|".join(cells)
            break
    return "secret-scanning", "\n".join(lines) + f"\n\n{content}\n"


def _sast_pages(run_uuid, repo):
    finding = next(f for f in repo.list_sast_findings() if f.current_ref == "F1")
    return [f"/runs/{run_uuid}", "/activities/sast/findings", f"/activities/sast/findings/{finding.fingerprint}",
            "/activities/sast", "/"]


def _secret_pages(run_uuid, repo):
    dash = secret_scanning_dashboard.build(repo)
    return [f"/runs/{run_uuid}", "/activities/secret-scanning/findings", "/activities/secret-scanning"] + [
        f"/activities/secret-scanning/findings/{key}" for key in sorted(dash.findings_by_key)
    ]


@pytest.mark.parametrize("name", CORPUS)
def test_sast_pages_with_a_poisoned_report_have_nothing_new_that_executes(client, name):
    baseline, poisoned = _baseline_and_poisoned(client, CORPUS[name], _sast_report, _sast_pages)
    for url_index, (plain, bad) in enumerate(zip(baseline, poisoned)):
        assert not bad - plain, (url_index, bad - plain)


@pytest.mark.parametrize("name", CORPUS)
def test_secret_scanning_pages_with_a_poisoned_report_have_nothing_new_that_executes(client, name):
    baseline, poisoned = _baseline_and_poisoned(client, CORPUS[name], _secret_report, _secret_pages)
    for url_index, (plain, bad) in enumerate(zip(baseline, poisoned)):
        assert not bad - plain, (url_index, bad - plain)


def test_the_comparison_would_catch_a_leak():
    """The checker itself: a page that gained a handler, a script or a
    javascript: link is not equal to its baseline."""
    plain = executable('<p>x</p><script src="/static/js/theme.js"></script>')
    for leaked in ('<p onclick="alert(1)">x</p>', "<script>alert(1)</script>", '<a href="javascript:alert(1)">x</a>',
                   '<a href=" JAVA SCRIPT:alert(1)">x</a>', '<img src="/x">', '<a href="//evil.example">x</a>'):
        assert executable(f'{leaked}<script src="/static/js/theme.js"></script>') != plain, leaked
