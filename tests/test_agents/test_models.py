"""Model selection stays per adapter and preserves execution boundaries."""
from __future__ import annotations

import pytest

from secfoo.agents.registry import ADAPTERS, get_adapter

MODEL_FLAGS = {
    "claude": "--model", "codex": "--model", "gemini": "--model",
    "copilot": "--model", "agent": "--model", "droid": "-m", "opencode": "-m",
}


@pytest.mark.parametrize("agent_id", ADAPTERS)
def test_model_selection_command_contract(agent_id, tmp_path):
    adapter = get_adapter(agent_id)
    baseline = adapter.build_command("review this\ncarefully", workdir=tmp_path)
    adapter.configure_model(None)
    assert adapter.build_command("review this\ncarefully", workdir=tmp_path) == baseline
    model = "custom-model;$(touch sentinel)"
    if agent_id in MODEL_FLAGS:
        adapter.configure_model(model)
        command = adapter.build_command("review this\ncarefully", workdir=tmp_path)
        i = command.index(MODEL_FLAGS[agent_id])
        assert command[i + 1] == model
        assert command[:i] + command[i + 2:] == baseline
        assert get_adapter(agent_id).model is None
    elif agent_id == "api":
        adapter.configure_model(model)
        assert adapter.model == model
        assert adapter.build_command("review", workdir=tmp_path) == []
    else:
        with pytest.warns(UserWarning, match="ignoring model"):
            adapter.configure_model(model)
        assert adapter.model is None
        assert adapter.build_command("review this\ncarefully", workdir=tmp_path) == baseline


@pytest.mark.parametrize("agent_id", MODEL_FLAGS)
def test_selected_model_preserves_stdin_and_process_options(agent_id, tmp_path, fake_popen):
    adapter = get_adapter(agent_id)
    adapter.configure_model("test-model")
    fake = fake_popen()
    adapter.run("multi\nline prompt", workdir=tmp_path, timeout=23)
    command = fake.call_args[0]
    assert command[command.index(MODEL_FLAGS[agent_id]) + 1] == "test-model"
    assert fake.call_kwargs["cwd"] == tmp_path
    assert fake.call_kwargs["start_new_session"] is True
    assert fake.stdin_input == ("multi\nline prompt" if adapter.prompt_via_stdin else None)
