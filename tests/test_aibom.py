from __future__ import annotations

import pytest

from secfoo.aibom import AIBOMParseError, parse_ai_bom

VALID_JSON = """\
{
  "models": [
    {"name": "gemini-2.5-flash", "provider": "Google", "version": "2.5", "purpose": "risk classification"}
  ],
  "tools": [
    {"name": "LangChain", "type": "framework", "version": "0.3.x"}
  ]
}
"""

VALID_CSV = """\
kind,name,provider_or_type,version,purpose
model,gemini-2.5-flash,Google,2.5,risk classification
tool,LangChain,framework,0.3.x,
"""


def test_parse_json_ai_bom(tmp_path):
    path = tmp_path / "ai-bom.json"
    path.write_text(VALID_JSON)
    summary = parse_ai_bom(path)
    assert len(summary.models) == 1
    assert summary.models[0]["name"] == "gemini-2.5-flash"
    assert summary.models[0]["provider_or_type"] == "Google"
    assert len(summary.tools) == 1
    assert summary.tools[0]["name"] == "LangChain"


def test_parse_csv_ai_bom(tmp_path):
    path = tmp_path / "ai-bom.csv"
    path.write_text(VALID_CSV)
    summary = parse_ai_bom(path)
    assert len(summary.models) == 1
    assert len(summary.tools) == 1
    assert summary.tools[0]["purpose"] is None


def test_parse_json_malformed_raises_clear_error(tmp_path):
    path = tmp_path / "ai-bom.json"
    path.write_text("{not valid json")
    with pytest.raises(AIBOMParseError, match="invalid JSON"):
        parse_ai_bom(path)


def test_parse_json_missing_name_raises(tmp_path):
    path = tmp_path / "ai-bom.json"
    path.write_text('{"models": [{"provider": "Google"}]}')
    with pytest.raises(AIBOMParseError, match="name"):
        parse_ai_bom(path)


def test_parse_csv_missing_required_columns_raises(tmp_path):
    path = tmp_path / "ai-bom.csv"
    path.write_text("foo,bar\n1,2\n")
    with pytest.raises(AIBOMParseError, match="kind"):
        parse_ai_bom(path)


def test_parse_csv_unknown_kind_raises(tmp_path):
    path = tmp_path / "ai-bom.csv"
    path.write_text("kind,name\nvendor,Something\n")
    with pytest.raises(AIBOMParseError, match="unknown 'kind'"):
        parse_ai_bom(path)


def test_parse_unsupported_extension_raises(tmp_path):
    path = tmp_path / "ai-bom.txt"
    path.write_text("nope")
    with pytest.raises(AIBOMParseError, match="unsupported"):
        parse_ai_bom(path)
