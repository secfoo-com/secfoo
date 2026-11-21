"""Write the seed corpora in fuzz/corpus/<harness>/.

    python fuzz/make_seed_corpus.py

Seeds are real inputs (the sample exports and reports in examples/, the
documented config.toml, small real PDF/DOCX/PPTX files) so fuzzing starts
from valid structure. `crash-*` files are the reproducers of crashes the
harnesses found (#121); tests/test_property_fuzz_targets.py replays every
corpus file on every platform, so a fixed crash can't come back unnoticed.

Rerunning overwrites these files; libFuzzer's own discoveries go to the
WORK folder CI passes first, never here.
"""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "fuzz" / "corpus"
EXAMPLES = ROOT / "examples"

SESSION = {"type": "session", "id": "11111111-2222-3333-4444-555555555555", "language": "python",
           "runtime": "3.12.4", "source": "sensor", "started_at": "2026-11-08T10:00:00Z",
           "ended_at": "2026-11-08T16:00:00Z", "app": "payments-api", "env": "prod", "instance": "pod-1",
           "sensor_version": "0.1.0", "app_functions_total": 1840, "app_functions_executed": 1362}
LOAD = {"type": "load", "session": SESSION["id"], "ecosystem": "PyPI", "package": "pyyaml", "version": "5.3",
        "path": "/app/.venv/lib/python3.12/site-packages/yaml", "first_seen": "2026-11-08T10:00:01Z"}
HIT = {"type": "hit", "session": SESSION["id"], "finding_fingerprint": "fuzz-fp-1", "symbol": "yaml.load",
       "route": "POST /upload", "auth": "authenticated", "count": 42, "first_seen": "2026-11-08T10:05:00Z",
       "last_seen": "2026-11-08T15:59:00Z", "entry_frame": "app/upload.py:31",
       "stack_sample": ["site-packages/yaml/__init__.py:79", "app/upload.py:31"]}


def _ndjson(*events: dict | str) -> bytes:
    return "".join((e if isinstance(e, str) else json.dumps(e)) + "\n" for e in events).encode("utf-8")


def _write(harness: str, name: str, data: bytes) -> None:
    folder = CORPUS / harness
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(data)


def _copy(harness: str, source: Path, name: str | None = None) -> None:
    folder = CORPUS / harness
    folder.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, folder / (name or source.name))


def parsers() -> None:
    for report in ("sast-report.md", "secret-scanning-report.md"):
        _copy("parsers", EXAMPLES / "sample-output" / "nodegoat" / report)
    for skill in sorted((EXAMPLES / "skills").glob("*.md")):
        _copy("parsers", skill, f"skill-{skill.name}")


def sarif_export() -> None:
    lines = (EXAMPLES / "sample-output" / "nodegoat" / "findings.jsonl").read_text(encoding="utf-8").splitlines()
    _write("sarif_export", "nodegoat-findings.jsonl", ("\n".join(lines) + "\n").encode("utf-8"))
    _write("sarif_export", "paths-and-runtime.jsonl", _ndjson(
        {"skill_id": "sast", "severity": "High", "cwe": "CWE-89, CWE-564", "title": "SQL injection",
         "location_file": "C:\\work\\app db.py", "location_line": "12"},
        {"skill_id": "secret-scanning", "severity": "Critical", "secret_type": "AWS key",
         "location_file": "//server/share/ci.yml", "location_line": "0"},
        {"skill_id": "sca-reachability", "severity": "Medium", "issue": "CVE-2020-1747", "package": "pyyaml",
         "runtime": {"state": "reached", "routes": [{"route": "POST /upload"}, {"route": "GET /health"}]}},
        {"skill_id": "sast", "severity": "informational", "location_file": "/abs/a%b.py", "location_line": "7-9"},
    ))
    # Crash reproducer: int() refuses strings over 4300 digits.
    _write("sarif_export", "crash-location-line-5000-digits.jsonl", _ndjson(
        {"skill_id": "sast", "severity": "High", "location_file": "a.py", "location_line": "1" * 5000}))


def skill_loader() -> None:
    for skill in sorted((EXAMPLES / "skills").glob("*.md")):
        _copy("skill_loader", skill)
    _copy("skill_loader", ROOT / "src" / "secfoo" / "skills" / "definitions" / "sast.md", "builtin-sast.md")
    # Crash reproducer: invalid UTF-8 escaped _build_skill as UnicodeDecodeError.
    _write("skill_loader", "crash-invalid-utf8.md",
           b"---\nid: broken-encoding\nname: Broken\ndescription: x\nversion: 1\n---\nReview \xff\xfe this.\n")


DOCUMENTED_CONFIG = """\
[defaults]
agent = "claude"
depth = "quick"
exclude = ["vendor/", "some-cloned-repo/"]
fail_on = "high"
max_cost_usd = 2.00

[agents.claude]
model = "claude-sonnet-4-6"

[agents.api]
max_input_tokens = 150000

[[mcp_servers]]
name = "Atlassian-Rovo-MCP"
command = "npx"
args = ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"]

[[mcp_servers]]
name = "wiki"
url = "https://wiki.internal/mcp"
transport = "http"
headers = { Authorization = "Bearer x" }

[skills]
paths = ["~/team-skills"]

[memory]
enabled = false
"""

CONFIG_CRASHES = {
    # Each escaped load_config as something other than ConfigError.
    "crash-defaults-not-a-table.toml": b"defaults = 1\n",
    "crash-mcp-servers-string.toml": b"mcp_servers = 'x'\n",
    "crash-mcp-servers-table.toml": b"[mcp_servers]\nname = 'a'\ncommand = 'x'\n",
    "crash-mcp-name-list.toml": b"[[mcp_servers]]\nname = [1]\ncommand = 'x'\n",
    "crash-invalid-utf8.toml": b"[defaults]\nagent = \"\xff\xfe\"\n",
    # Loaded, then crashed later in a subprocess argument list / `secfoo run`.
    "crash-mcp-args-number.toml": b"[[mcp_servers]]\nname = 'a'\ncommand = 'npx'\nargs = [1, 2]\n",
    "crash-mcp-command-number.toml": b"[[mcp_servers]]\nname = 'a'\ncommand = 5\n",
    "crash-mcp-env-table.toml": b"[[mcp_servers]]\nname = 'a'\ncommand = 'x'\nenv = { A = { B = 1 } }\n",
    "crash-defaults-timeout-string.toml": b"[defaults]\ntimeout = 'soon'\n",
}


def config() -> None:
    _write("config", "documented.toml", DOCUMENTED_CONFIG.encode("utf-8"))
    _write("config", "empty.toml", b"")
    for name, data in CONFIG_CRASHES.items():
        _write("config", name, data)


def docext() -> None:
    import docx
    from pptx import Presentation
    from pptx.util import Inches
    from pypdf import PdfWriter

    document = docx.Document()
    document.add_paragraph("SOC 2 Type II report: access control and encryption at rest.")
    table = document.add_table(rows=2, cols=2)
    table.cell(0, 0).text, table.cell(0, 1).text = "Control", "Status"
    table.cell(1, 0).text, table.cell(1, 1).text = "MFA", "Implemented"
    buffer = io.BytesIO()
    document.save(buffer)
    _write("docext", "report.docx.bin", bytes([1]) + buffer.getvalue())
    # Crash reproducer (#118): a central-directory "version needed to
    # extract" zipfile does not support makes ZipFile() itself raise
    # NotImplementedError, which escaped the upload route's type check.
    cd = buffer.getvalue().find(b"PK\x01\x02")
    patched = bytearray(buffer.getvalue())
    patched[cd + 6:cd + 8] = (236).to_bytes(2, "little")
    _write("docext", "crash-zip-unsupported-version.docx.bin", bytes([1]) + bytes(patched))

    presentation = Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[5])
    slide.shapes.title.text = "Pen test summary"
    shape = slide.shapes.add_table(2, 2, Inches(1), Inches(2), Inches(6), Inches(1)).table
    shape.cell(0, 0).text, shape.cell(0, 1).text = "Finding", "Severity"
    shape.cell(1, 0).text, shape.cell(1, 1).text = "XSS", "High"
    buffer = io.BytesIO()
    presentation.save(buffer)
    _write("docext", "summary.pptx.bin", bytes([2]) + buffer.getvalue())

    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buffer = io.BytesIO()
    writer.write(buffer)
    _write("docext", "blank.pdf.bin", bytes([0]) + buffer.getvalue())
    # A hand-written PDF with a text content stream, so extraction has text to find.
    _write("docext", "text.pdf.bin", bytes([0]) + _text_pdf("ISO 27001 certificate"))


def _text_pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R "
         b"/Resources << /Font << /F1 5 0 R >> >> >>"),
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = b"%PDF-1.4\n", []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out


def runtime_ingest() -> None:
    _write("runtime_ingest", "batch.ndjson", _ndjson(SESSION, LOAD, HIT))
    _write("runtime_ingest", "mixed-valid-and-invalid.ndjson", _ndjson(
        SESSION, "not json", {"type": "hit", "session": "unknown", "finding_fingerprint": "x", "symbol": "a.b",
                              "count": 1},
        {**HIT, "route": "GET /users/42?token=x"}, {**HIT, "finding_fingerprint": "not-a-finding"}, ""))
    # Crash reproducers. Each used to roll back the whole batch (a 500 from the
    # ingest API); now the bad line is skipped and the session line is kept.
    _write("runtime_ingest", "crash-deep-nesting.ndjson", _ndjson(SESSION, "[" * 20000 + "]" * 20000))
    _write("runtime_ingest", "crash-int-over-4300-digits.ndjson",
           _ndjson(SESSION, '{"type":"hit","count":1' + "0" * 5000 + "}"))
    _write("runtime_ingest", "crash-lone-surrogate.ndjson",
           _ndjson(SESSION, json.dumps({**SESSION, "id": "s2", "app": "\ud800"})))
    _write("runtime_ingest", "crash-count-over-int64.ndjson", _ndjson(SESSION, {**HIT, "count": 2**64}))
    _write("runtime_ingest", "crash-surrogate-entry-frame.ndjson",
           _ndjson(SESSION, json.dumps({**HIT, "entry_frame": "app/\udcff.py:3"})))


def main() -> None:
    for build in (parsers, sarif_export, skill_loader, config, docext, runtime_ingest):
        build()
    for folder in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        print(f"{folder.relative_to(ROOT)}: {len(list(folder.iterdir()))} file(s)")


if __name__ == "__main__":
    main()
