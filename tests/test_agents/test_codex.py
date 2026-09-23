from __future__ import annotations

from secfoo.agents import ADAPTERS, get_adapter
from secfoo.agents.codex import CodexAdapter


def test_registered_under_codex_id():
    assert ADAPTERS["codex"] is CodexAdapter
    assert isinstance(get_adapter("codex"), CodexAdapter)


def test_build_command_is_non_interactive_exec(tmp_path):
    cmd = CodexAdapter().build_command("hello", workdir=tmp_path)
    assert cmd[:2] == ["codex", "exec"]


def test_build_command_is_read_only(tmp_path):
    cmd = CodexAdapter().build_command("hello", workdir=tmp_path)
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert "--dangerously-bypass-approvals-and-sandbox" not in cmd
    assert "--full-auto" not in cmd


def test_build_command_headless_flags(tmp_path):
    cmd = CodexAdapter().build_command("hello", workdir=tmp_path)
    assert "--skip-git-repo-check" in cmd
    assert "--ephemeral" in cmd
    assert cmd[cmd.index("--color") + 1] == "never"
    assert "--json" not in cmd  # report must stay plain text on stdout


def test_build_command_sets_working_root(tmp_path):
    cmd = CodexAdapter().build_command("hello", workdir=tmp_path)
    assert cmd[cmd.index("--cd") + 1] == str(tmp_path)


def test_prompt_is_last_arg_after_double_dash(tmp_path):
    cmd = CodexAdapter().build_command("--looks-like-a-flag", workdir=tmp_path)
    assert cmd[-2:] == ["--", "--looks-like-a-flag"]


def test_extract_report_is_stdout_passthrough():
    assert CodexAdapter().extract_report("final message") == "final message"
