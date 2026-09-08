from __future__ import annotations

import json

from secfoo.agents.gemini import GeminiAdapter


def test_build_command_no_yolo_flag(tmp_path):
    adapter = GeminiAdapter()
    cmd = adapter.build_command("hi", workdir=tmp_path)
    assert "--yolo" not in cmd
    assert "--skip-trust" in cmd
    assert "--output-format" in cmd
    assert "json" in cmd


def test_extract_report_response_key():
    adapter = GeminiAdapter()
    assert adapter.extract_report(json.dumps({"response": "R"})) == "R"


def test_extract_report_result_key_fallback():
    adapter = GeminiAdapter()
    assert adapter.extract_report(json.dumps({"result": "R2"})) == "R2"


def test_extract_report_non_json_passthrough():
    adapter = GeminiAdapter()
    assert adapter.extract_report("plain text") == "plain text"
