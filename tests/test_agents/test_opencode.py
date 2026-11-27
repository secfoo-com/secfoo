from __future__ import annotations

import json
import subprocess
from pathlib import Path

from secfoo.agents import ADAPTERS, get_adapter
from secfoo.agents.codex import CodexAdapter
from secfoo.agents.opencode import OpenCodeAdapter
from secfoo.cli import AgentId


def test_registered_for_cli():
    assert ADAPTERS["opencode"] is OpenCodeAdapter
    assert isinstance(get_adapter("opencode"), OpenCodeAdapter)
    assert AgentId("opencode") is AgentId.OPENCODE


def test_build_command_is_noninteractive_and_does_not_auto_approve(tmp_path):
    command = OpenCodeAdapter().build_command("review", workdir=tmp_path)
    assert command == ["opencode", "run", "--standalone", "--format", "json"]
    assert "--auto" not in command
    assert "--pure" not in command  # removed in v2.3.0
    assert "--dir" not in command  # removed in v2.3.0; cwd is set by run()


def test_run_sets_readonly_config_and_pipes_prompt(fake_popen, tmp_path, monkeypatch):
    monkeypatch.setenv("SECFOO_TEST_INHERITED", "present")
    monkeypatch.setenv("OPENCODE_CONFIG", "somewhere-else.json")
    fake = fake_popen(stdout='{"type":"text","part":{"text":"report"}}', returncode=0)
    result = OpenCodeAdapter().run("review\nfiles", workdir=tmp_path)
    assert result.raw_report == "report"
    assert fake.call_kwargs["stdin"] == subprocess.PIPE
    assert fake.stdin_input == "review\nfiles"
    env = fake.call_kwargs["env"]
    assert env["SECFOO_TEST_INHERITED"] == "present"
    config_path = Path(env["OPENCODE_CONFIG"])
    assert config_path.is_file()
    rules = json.loads(config_path.read_text(encoding="utf-8"))["permissions"]
    assert rules[0] == {"action": "*", "resource": "*", "effect": "deny"}
    assert {(rule["action"], rule["effect"]) for rule in rules[1:]} == {
        ("read", "allow"), ("glob", "allow"), ("grep", "allow")
    }


def test_other_adapters_still_inherit_environment_by_default(fake_popen, tmp_path):
    fake = fake_popen(stdout="report", returncode=0)
    CodexAdapter().run("review", workdir=tmp_path)
    assert "env" not in fake.call_kwargs


def test_json_events_extract_report_and_accumulate_usage(fake_popen, tmp_path):
    stdout = "\n".join([
        json.dumps({"type": "text", "part": {"text": "First"}}),
        json.dumps({"type": "step_finish", "part": {"tokens": {"input": 12, "output": 3}, "cost": 0.1}}),
        json.dumps({"type": "text", "part": {"text": "Second"}}),
        json.dumps({"type": "step_finish", "part": {"tokens": {"input": 8, "output": 2}, "cost": 0.2}}),
    ])
    fake_popen(stdout=stdout, returncode=0)
    result = OpenCodeAdapter().run("review", workdir=tmp_path)
    assert result.raw_report == "First\nSecond"
    assert (result.input_tokens, result.output_tokens) == (20, 5)
    assert abs(result.cost_usd - 0.3) < 1e-9


def test_unrecognized_output_is_preserved_and_usage_unknown():
    adapter = OpenCodeAdapter()
    assert adapter.extract_report("not json") == "not json"
    assert adapter.extract_usage("not json").input_tokens is None
