"""#121: property tests for the fuzz harnesses in fuzz/, on every platform.

Atheris (coverage-guided, `.github/workflows/fuzz.yml`) only runs on Linux.
These tests drive the *same* `check` function each harness defines with
Hypothesis-generated inputs, and replay every file in fuzz/corpus/ --
including the `crash-*` reproducers of crashes the harnesses found -- so the
invariants hold on Windows and macOS too, and a fixed crash can't return.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

FUZZ_DIR = Path(__file__).resolve().parents[1] / "fuzz"
sys.path.insert(0, str(FUZZ_DIR))

import fuzz_config
import fuzz_docext
import fuzz_parsers
import fuzz_runtime_ingest
import fuzz_sarif_export
import fuzz_skill_loader

HARNESSES = {
    "parsers": fuzz_parsers, "sarif_export": fuzz_sarif_export, "skill_loader": fuzz_skill_loader,
    "config": fuzz_config, "docext": fuzz_docext, "runtime_ingest": fuzz_runtime_ingest,
}
CORPUS = FUZZ_DIR / "corpus"
SLOW = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


# ---------- the corpora: seeds and crash reproducers ----------


def test_every_harness_has_a_seed_corpus():
    assert sorted(p.name for p in CORPUS.iterdir() if p.is_dir()) == sorted(HARNESSES)
    for name in HARNESSES:
        assert any((CORPUS / name).iterdir()), f"fuzz/corpus/{name} is empty"


@pytest.mark.parametrize("path", sorted(CORPUS.rglob("*.*")), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_corpus_file_replays_without_a_crash(path):
    HARNESSES[path.parent.name].check(path.read_bytes())


def test_replay_mode_runs_without_atheris(monkeypatch, capsys):
    """`python fuzz/fuzz_x.py crash-file` reproduces a CI crash anywhere."""
    import _common

    monkeypatch.setattr(sys, "argv", ["fuzz_config.py", str(CORPUS / "config"), "-max_total_time=60"])
    monkeypatch.setitem(sys.modules, "atheris", None)  # as if not installed
    with pytest.raises(SystemExit) as exc:
        _common.main(fuzz_config.check)
    assert exc.value.code == 0 and "replayed" in capsys.readouterr().out


def test_replay_mode_without_inputs_explains_itself(monkeypatch):
    import _common

    monkeypatch.setattr(sys, "argv", ["fuzz_config.py"])
    monkeypatch.setitem(sys.modules, "atheris", None)
    with pytest.raises(SystemExit, match="pip install atheris"):
        _common.main(fuzz_config.check)


# ---------- SARIF / JSONL export ----------

_PATHS = st.one_of(
    st.sampled_from(["app/db.py", "C:\\work\\a b.py", "C:/x.py", "C:", "//server/share/x.py", "//", "\\\\?\\C:\\x",
                     "/abs/a%b.py", "file:///etc/passwd", " ", "a\\b\\c.py", "../../etc/passwd"]),
    st.text(max_size=40),
)
_LINES = st.one_of(st.integers(-5, 10**12).map(str), st.text(max_size=12), st.none(), st.integers(),
                   st.integers(4290, 5100).map(lambda n: "1" * n))
_VALUE = st.one_of(st.none(), st.text(max_size=60), st.integers(), st.floats(allow_nan=False))
_RECORD = st.fixed_dictionaries(
    {"skill_id": st.one_of(st.sampled_from(["sast", "sca-reachability", "secret-scanning"]), st.text(max_size=30))},
    optional={
        "severity": st.one_of(st.sampled_from(["Critical", " HIGH ", "medium", "Informational", "info"]), _VALUE),
        "cwe": st.one_of(st.sampled_from(["CWE-89", "cwe-79, CWE-22", "CWE-0", "CWE-089"]), _VALUE),
        "title": _VALUE, "issue": _VALUE, "secret_type": _VALUE, "description": _VALUE, "construct": _VALUE,
        "evidence": _VALUE, "location_file": _PATHS, "location_line": _LINES,
        "runtime": st.fixed_dictionaries({
            "state": st.sampled_from(["reached", "not_reached", "unknown"]),
            "routes": st.lists(st.fixed_dictionaries({"route": st.text(max_size=30)}), max_size=4)}),
    },
)


@SLOW
@given(st.lists(_RECORD, max_size=12))
def test_export_of_any_finding_records_is_valid_sarif_and_jsonl(records):
    fuzz_sarif_export.check("\n".join(json.dumps(r) for r in records).encode("utf-8"))


@SLOW
@given(st.binary(max_size=2048))
def test_export_harness_survives_arbitrary_bytes(data):
    fuzz_sarif_export.check(data)


def test_a_huge_location_line_is_dropped_not_fatal():
    from secfoo.report.sarif import findings_to_sarif

    result = findings_to_sarif([{"skill_id": "sast", "location_file": "a.py", "location_line": "1" * 5000}])
    location = result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location == {"artifactLocation": {"uri": "a.py"}}  # the file is kept, the bogus line isn't


def test_jsonl_export_matches_the_previous_inline_format():
    from secfoo.report.jsonl import findings_to_jsonl

    assert findings_to_jsonl([]) == ""
    assert findings_to_jsonl([{"b": 1, "a": "x"}, {"c": None}]) == '{"a": "x", "b": 1}\n{"c": null}\n'


# ---------- skill loader ----------

# A file on disk is bytes; text with lone surrogates can't be encoded into
# one, so those are left to the arbitrary-bytes test below.
_KEYS = st.one_of(st.sampled_from(["id", "name", "description", "version", "output", "short_name", "category"]),
                  st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters=":\r\n"),
                          max_size=12))
_FIELD = st.one_of(st.sampled_from(["generic", "sast", "my-review", "1", "-3", "١٢", "1e3", "x" * 5000, ""]),
                   st.integers().map(str),
                   st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\r\n"),
                           max_size=40))


@given(st.dictionaries(_KEYS, _FIELD, max_size=9), st.text(max_size=200), st.sampled_from(["\n", "\r\n"]))
def test_any_frontmatter_loads_or_fails_with_skill_load_error(fields, body, newline):
    text = newline.join(["---", *(f"{k}: {v}" for k, v in fields.items()), "---", body])
    fuzz_skill_loader.check(text.encode("utf-8"))


@given(st.binary(max_size=1024))
def test_skill_loader_survives_arbitrary_bytes(data):
    fuzz_skill_loader.check(b"---\nid: x\n---\n" + data)
    fuzz_skill_loader.check(data)


def test_invalid_utf8_skill_is_a_skill_load_error():
    from secfoo.skills.loader import SkillLoadError, _build_skill

    with pytest.raises(SkillLoadError, match="not valid UTF-8"):
        _build_skill(b"---\nid: a\n---\n\xff", source="url", path=None, origin="https://x/s.md")


# ---------- config.toml ----------

def _toml_string(value: str) -> str:
    return json.dumps(value)  # a JSON string is a valid TOML basic string, \uXXXX escapes included


_TOML_SCALAR = st.one_of(
    st.integers(-(2**63), 2**63 - 1).map(str), st.booleans().map(lambda b: "true" if b else "false"),
    st.floats(allow_nan=False, allow_infinity=False).map(repr), st.text(max_size=20).map(_toml_string),
)
_TOML_VALUE = st.recursive(
    _TOML_SCALAR,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4).map(lambda items: "[" + ", ".join(items) + "]"),
        st.dictionaries(st.text(min_size=1, max_size=8), inner, max_size=3).map(
            lambda table: "{" + ", ".join(f"{_toml_string(k)} = {v}" for k, v in table.items()) + "}"),
    ),
    max_leaves=8,
)
_SECTION_KEYS = {
    "defaults": ["agent", "depth", "timeout", "exclude", "fail_on", "max_cost_usd"],
    "skills": ["paths"],
    "memory": ["enabled"],
}
_PLAUSIBLE = st.sampled_from(['"claude"', '"quick"', "600", '["vendor/"]', '"high"', "2.5", "true", '"npx"',
                              '["-y", "x"]', '"stdio"', '"http"', '"https://x/mcp"', '{ A = "b" }', "0", '""'])


@st.composite
def _config_toml(draw) -> str:
    out = []
    for key in draw(st.lists(st.sampled_from(["defaults", "agents", "mcp_servers", "skills", "memory"]),
                             unique=True, max_size=5)):
        shape = draw(st.sampled_from(["scalar", "table", "array_of_tables"]))
        if shape == "scalar":
            out.append(f"{key} = {draw(_TOML_VALUE)}")
        elif key == "mcp_servers" and shape == "array_of_tables":
            for _ in range(draw(st.integers(1, 3))):
                out.append("[[mcp_servers]]")
                for field in draw(st.lists(st.sampled_from(
                        ["name", "command", "url", "args", "env", "headers", "transport"]), unique=True)):
                    out.append(f"{field} = {draw(st.one_of(_PLAUSIBLE, _TOML_VALUE))}")
        elif key == "agents":
            for agent in draw(st.lists(st.sampled_from(["claude", "api", "codex"]), unique=True, max_size=3)):
                out.append(f"[agents.{agent}]")
                for field in draw(st.lists(st.sampled_from(["model", "max_input_tokens"]), unique=True)):
                    out.append(f"{field} = {draw(st.one_of(_PLAUSIBLE, _TOML_VALUE))}")
        else:
            out.append(f"[{key}]")
            for field in draw(st.lists(st.sampled_from(_SECTION_KEYS.get(key, ["x"])), unique=True)):
                out.append(f"{field} = {draw(st.one_of(_PLAUSIBLE, _TOML_VALUE))}")
    return "\n".join(out) + "\n"


@SLOW
@given(_config_toml())
def test_any_config_loads_with_declared_types_or_fails_with_config_error(text):
    fuzz_config.check(text.encode("utf-8"))


@given(st.binary(max_size=512))
def test_config_loader_survives_arbitrary_bytes(data):
    fuzz_config.check(data)


def test_the_documented_example_config_still_loads(tmp_path):
    """Stricter validation must not reject what docs/REFERENCE.md shows."""
    from secfoo.settings import load_config

    path = tmp_path / "config.toml"
    path.write_bytes((CORPUS / "config" / "documented.toml").read_bytes())
    config = load_config(path)
    assert config.defaults.agent == "claude" and config.defaults.max_cost_usd == 2.0
    assert [s.name for s in config.mcp_servers] == ["Atlassian-Rovo-MCP", "wiki"]
    assert config.mcp_servers[1].transport == "http" and config.memory_enabled is False


@pytest.mark.parametrize(("text", "message"), [
    ("defaults = 1", r"\[defaults\] must be a table"),
    ("mcp_servers = 'x'", "array of tables"),
    ("[mcp_servers]\nname = 'a'", "array of tables"),
    ("[[mcp_servers]]\nname = [1]\ncommand = 'x'", "name must be a string"),
    ("[[mcp_servers]]\nname = 'a'\ncommand = 'npx'\nargs = [1]", r"mcp_servers\.a\.args must be an array of strings"),
    ("[[mcp_servers]]\nname = 'a'\ncommand = 5", r"mcp_servers\.a\.command must be a non-empty string"),
    ("[[mcp_servers]]\nname = 'a'\ncommand = 'x'\nenv = { A = 1 }", r"mcp_servers\.a\.env must be a table of strings"),
    ("[[mcp_servers]]\nname = 'a'\nurl = 'https://x'\ntransport = 'ftp'", "transport must be one of stdio, sse, http"),
    ("[defaults]\ntimeout = 'soon'", "defaults.timeout must be a positive integer"),
    ("[defaults]\nagent = 3", "defaults.agent must be a non-empty string"),
])
def test_config_errors_name_the_bad_key(tmp_path, text, message):
    from secfoo.settings import ConfigError, load_config

    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_non_utf8_config_is_a_config_error(tmp_path):
    from secfoo.settings import ConfigError, load_config

    path = tmp_path / "config.toml"
    path.write_bytes(b"[defaults]\nagent = \"\xff\"\n")
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        load_config(path)


def test_an_unknown_agent_in_config_is_a_clean_cli_error(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from secfoo import cli

    path = tmp_path / "config.toml"
    path.write_text('[defaults]\nagent = "nope"\n', encoding="utf-8")
    monkeypatch.setattr("secfoo.settings.CONFIG_PATH", path)
    monkeypatch.setattr(cli, "CONFIG_PATH", path)
    result = CliRunner().invoke(cli.app, ["run", "--skill", "sast", "--target", str(tmp_path), "--yes"])
    assert result.exit_code == 1
    assert "defaults.agent must be one of" in result.output and "Traceback" not in result.output


# ---------- document extraction ----------

_SEEDS = sorted((CORPUS / "docext").iterdir())


@settings(SLOW, max_examples=40)
@given(st.sampled_from(_SEEDS), st.lists(st.tuples(st.integers(0, 10**6), st.integers(0, 255)), max_size=12))
def test_mutated_documents_extract_to_text_or_empty(seed, flips):
    data = bytearray(seed.read_bytes())
    for position, value in flips:
        data[1 + position % (len(data) - 1)] = value  # byte 0 picks the format; keep it
    fuzz_docext.check(bytes(data))


@settings(SLOW, max_examples=30)
@given(st.binary(max_size=2048))
def test_arbitrary_bytes_extract_to_text_or_empty(data):
    fuzz_docext.check(data)


def test_document_seeds_actually_contain_text():
    from secfoo.docext import extract_text

    texts = {}
    for seed in _SEEDS:
        suffix, body = fuzz_docext.split(seed.read_bytes())
        path = fuzz_docext._DIR / f"seed{suffix}"
        path.write_bytes(body)
        texts[seed.name] = extract_text(path)
    assert "MFA | Implemented" in texts["report.docx.bin"]
    assert "XSS | High" in texts["summary.pptx.bin"]
    assert "ISO 27001" in texts["text.pdf.bin"]


# ---------- runtime ingest ----------

_SURROGATE = st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF)
_JSON_TEXT = st.one_of(st.text(max_size=30), st.lists(st.one_of(st.characters(), _SURROGATE), max_size=8).map("".join))
_JSON_VALUE = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(-(2**70), 2**70), st.floats(allow_nan=False), _JSON_TEXT),
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(st.text(max_size=8), inner, max_size=4)),
    max_leaves=10,
)
_EVENT_FIELDS = ["type", "id", "language", "source", "started_at", "ended_at", "app", "env", "session", "ecosystem",
                 "package", "version", "finding_fingerprint", "symbol", "route", "auth", "count", "first_seen",
                 "last_seen", "entry_frame", "stack_sample", "app_functions_total", "app_functions_executed"]
_VALID_BASE = {
    "id": "s1", "session": "s1", "language": "python", "source": "sensor", "started_at": "2026-11-08T10:00:00Z",
    "ecosystem": "PyPI", "package": "p", "version": "1", "finding_fingerprint": fuzz_runtime_ingest.FINGERPRINT,
    "symbol": "p.f", "count": 1,
}
# A valid-looking event with some fields replaced by arbitrary JSON values:
# close enough to the contract to get past the first checks.
_PLAUSIBLE_EVENT = st.builds(
    lambda kind, overrides: {"type": kind, **_VALID_BASE, **overrides},
    st.sampled_from(["session", "load", "hit", "other"]),
    st.dictionaries(st.sampled_from(_EVENT_FIELDS), _JSON_VALUE, max_size=4),
)
_LINE = st.one_of(
    _PLAUSIBLE_EVENT.map(json.dumps),
    st.dictionaries(st.sampled_from(_EVENT_FIELDS), _JSON_VALUE, max_size=8).map(json.dumps),
    _JSON_VALUE.map(json.dumps),
    st.text(max_size=60),
    st.integers(1, 30000).map(lambda n: "[" * n + "]" * n),
    st.integers(4250, 5000).map(lambda n: '{"type":"hit","count":' + "9" * n + "}"),
)


@SLOW
@given(st.lists(_LINE, max_size=12))
def test_any_batch_stores_or_skips_every_line(lines):
    fuzz_runtime_ingest.check("\n".join(lines).encode("utf-8", errors="surrogatepass"))


@given(st.binary(max_size=2048))
def test_ingest_survives_arbitrary_bytes(data):
    fuzz_runtime_ingest.check(data)


@pytest.mark.parametrize("path", sorted((CORPUS / "runtime_ingest").glob("crash-*")), ids=lambda p: p.name)
def test_one_bad_line_no_longer_loses_the_whole_batch(path, tmp_path):
    from secfoo.runtime.evidence import ingest_events
    from secfoo.storage.repository import RunRepository

    with RunRepository(db_path=tmp_path / "db.sqlite") as repo:
        project = repo.upsert_project("/app", "app", "local")
        lines = path.read_text(encoding="utf-8").splitlines()
        report = ingest_events(repo.connection, project, lines)
        assert report.sessions >= 1  # the good session line before the bad one was committed
        assert len(report.skipped) >= 1
        assert repo.connection.execute("SELECT COUNT(*) FROM runtime_sessions").fetchone()[0] >= 1
