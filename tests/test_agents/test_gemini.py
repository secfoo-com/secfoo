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


def test_run_success_leaves_cost_usd_none(fake_popen, tmp_path):
    """Gemini CLI's JSON output has no reported spend figure -- cost_usd
    must stay None rather than a guessed/estimated value."""
    fake_popen(returncode=0, stdout=json.dumps({"response": "R"}), stderr="")
    adapter = GeminiAdapter()
    result = adapter.run("hi", workdir=tmp_path)
    assert result.cost_usd is None
def test_extract_usage_sums_tokens_across_models_without_cost():
    stdout = json.dumps({
        "response": "report",
        "stats": {
            "models": {
                "gemini-pro": {"tokens": {"prompt": 1000, "candidates": 200}},
                "gemini-flash": {"tokens": {"prompt": 50, "candidates": 5}},
            }
        },
    })
    usage = GeminiAdapter().extract_usage(stdout)
    assert usage.input_tokens == 1050
    assert usage.output_tokens == 205
    assert usage.cost_usd is None


def test_extract_usage_unknown_without_stats():
    assert GeminiAdapter().extract_usage(json.dumps({"response": "r"})).input_tokens is None
    assert GeminiAdapter().extract_usage("not json").input_tokens is None
