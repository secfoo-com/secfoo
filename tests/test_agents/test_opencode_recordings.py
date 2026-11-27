"""Replay the real opencode 2.3.0 transcripts recorded for issue #116.

The fixtures are produced by ``scripts/record_agent.py`` from actual CLI runs;
replaying them here keeps argv/output drift from silently returning.
"""

from __future__ import annotations

import json
from pathlib import Path

from secfoo.agents.opencode import OpenCodeAdapter

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "agents" / "opencode" / "2.3.0"


def recording(scenario: str) -> dict:
    path = FIXTURES / f"{scenario}.json"
    assert path.is_file(), f"missing recording: {path}"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["cli_version"] == "2.3.0"
    assert data["agent"] == "opencode"
    assert data["verified_by"]
    return data


def test_success_recording_parses_report_and_matches_printed_usage(fake_popen, tmp_path):
    data = recording("success")
    assert data["status"] == "completed" and data["exit_code"] == 0
    assert data["workdir"] == "examples"
    assert "--standalone" in data["command"]
    assert "secret scanning" in data["prompt"] and "QUICK" in data["prompt"]

    fake_popen(stdout=data["stdout"], returncode=data["exit_code"])
    result = OpenCodeAdapter().run(data["prompt"], workdir=tmp_path)
    assert result.status == "success"
    assert "# Secret Scanning Report" in result.raw_report
    # Values summed from the step_finish events the CLI actually printed.
    assert (result.input_tokens, result.output_tokens) == (46675, 3382)
    assert result.cost_usd == 0.0


def test_auth_failure_recording_names_the_cause(fake_popen, tmp_path):
    data = recording("auth_failure")
    assert data["exit_code"] == 1 and data["stderr"] == ""

    fake_popen(stdout=data["stdout"], returncode=data["exit_code"])
    result = OpenCodeAdapter().run(data["prompt"], workdir=tmp_path)
    assert result.status == "failed"
    assert result.stderr.startswith("secfoo: ")
    assert "Model unavailable: anthropic/claude-sonnet-4-6" in result.stderr


def test_timeout_recording_maps_to_timeout(fake_popen, tmp_path):
    data = recording("timeout")
    assert data["status"] == "timeout" and data["exit_code"] is None

    fake_popen(stdout=data["stdout"], raise_timeout=True)
    result = OpenCodeAdapter().run(data["prompt"], workdir=tmp_path, timeout=3)
    assert result.status == "timeout"
    assert result.timed_out is True
    assert result.raw_report == ""


def test_binary_missing_maps_to_binary_not_found(fake_popen, tmp_path, monkeypatch):
    fake_popen(binary_available=False)
    monkeypatch.setattr("secfoo.agents.base.shutil.which", lambda name: None)
    result = OpenCodeAdapter().run("review", workdir=tmp_path)
    assert result.status == "binary_not_found"
    assert "'opencode' not found on PATH" in result.stderr


def test_permission_recording_confirms_writes_are_denied(fake_popen, tmp_path):
    data = recording("permission_denied")
    assert data["exit_code"] == 0  # the CLI refuses the write but still answers
    fake_popen(stdout=data["stdout"], returncode=data["exit_code"])
    result = OpenCodeAdapter().run(data["prompt"], workdir=tmp_path)
    assert result.status == "success"
    assert "was not created" in result.raw_report
    assert "couldn't create the file" in result.raw_report


def test_flag_drift_recording_documents_why_the_argv_changed(fake_popen, tmp_path):
    data = recording("flag_drift")
    assert data["exit_code"] == 1
    assert "--pure" in data["command"] and "--dir" in data["command"]
    assert "Unrecognized flag: --pure" in data["stderr"]
    assert "Unrecognized flag: --dir" in data["stderr"]

    command = OpenCodeAdapter().build_command("review", workdir=tmp_path)
    assert "--pure" not in command and "--dir" not in command


def test_readonly_config_is_shipped_and_loaded_in_standalone_mode(tmp_path):
    adapter = OpenCodeAdapter()
    config = Path(adapter.extra_env["OPENCODE_CONFIG"])
    assert config.is_file()
    rules = json.loads(config.read_text(encoding="utf-8"))["permissions"]
    assert rules[0] == {"action": "*", "resource": "*", "effect": "deny"}
    assert {(rule["action"], rule["effect"]) for rule in rules[1:]} == {
        ("read", "allow"), ("glob", "allow"), ("grep", "allow")
    }
    assert "--standalone" in adapter.build_command("review", workdir=tmp_path)
