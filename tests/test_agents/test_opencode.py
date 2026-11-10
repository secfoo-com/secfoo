from __future__ import annotations

import json
import subprocess

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
    assert command == ["opencode", "run", "--pure", "--format", "json", "--dir", str(tmp_path)]
    assert "--auto" not in command


def test_run_sets_permissions_and_pipes_prompt(fake_popen, tmp_path, monkeypatch):
    monkeypatch.setenv("SECFOO_TEST_INHERITED", "present")
    monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", '{"permission":{"bash":"allow"}}')
    monkeypatch.setenv("OPENCODE_PERMISSION", '{"bash":"allow"}')
    fake = fake_popen(stdout='{"type":"text","part":{"text":"report"}}', returncode=0)
    result = OpenCodeAdapter().run("review\nfiles", workdir=tmp_path)
    assert result.raw_report == "report"
    assert fake.call_kwargs["stdin"] == subprocess.PIPE
    assert fake.stdin_input == "review\nfiles"
    env = fake.call_kwargs["env"]
    assert env["SECFOO_TEST_INHERITED"] == "present"
    assert json.loads(env["OPENCODE_CONFIG_CONTENT"]) == {
        "permission": {"bash": "deny", "edit": "deny", "webfetch": "deny"}
    }
    assert json.loads(env["OPENCODE_PERMISSION"]) == {"bash": "deny", "edit": "deny", "webfetch": "deny"}


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
