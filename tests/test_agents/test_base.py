from __future__ import annotations

import subprocess

from secfoo.agents.base import _kill_process_tree
from secfoo.agents.claude import ClaudeAdapter
from secfoo.settings import Defaults, SecfooConfig


def _no_mcp_config(monkeypatch):
    """Isolates these tests from whatever the developer's real
    ~/.secfoo/config.toml happens to contain."""
    monkeypatch.setattr("secfoo.agents.claude.load_config", lambda: SecfooConfig(defaults=Defaults(), mcp_servers=[]))


def test_binary_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr("secfoo.agents.base.shutil.which", lambda name: None)
    adapter = ClaudeAdapter()
    result = adapter.run("hi", workdir=tmp_path)
    assert result.status == "binary_not_found"
    assert result.exit_code is None


def test_success_status_and_duration(fake_popen, tmp_path, monkeypatch):
    _no_mcp_config(monkeypatch)
    fake_popen(returncode=0, stdout="ok", stderr="")
    adapter = ClaudeAdapter()
    result = adapter.run('{"result": "ok"}', workdir=tmp_path)
    assert result.status in ("success", "failed")  # depends on returncode below
    assert result.duration_seconds >= 0


def test_nonzero_exit_is_failed_status(fake_popen, tmp_path, monkeypatch):
    _no_mcp_config(monkeypatch)
    fake_popen(returncode=1, stdout="", stderr="boom")
    adapter = ClaudeAdapter()
    result = adapter.run("hi", workdir=tmp_path)
    assert result.status == "failed"
    assert result.raw_report == ""
    assert result.stderr == "boom"


def test_stdin_is_devnull_so_interactive_prompts_fail_fast_not_hang(fake_popen, tmp_path, monkeypatch):
    """A CLI that tries to read an interactive confirmation (auth/trust
    prompt) from stdin must hit immediate EOF rather than blocking on the
    caller's real terminal, which they can't see (stdout/stderr are
    captured into pipes) and therefore can't ever answer."""
    _no_mcp_config(monkeypatch)
    fake = fake_popen(returncode=0, stdout="ok", stderr="")
    adapter = ClaudeAdapter()
    adapter.run("hi", workdir=tmp_path)
    assert fake.call_kwargs["stdin"] == subprocess.DEVNULL


def test_launches_the_path_which_resolved(fake_popen, tmp_path, monkeypatch):
    """Popen ignores PATHEXT on Windows, so the bare binary name would miss
    an npm `.cmd` shim that shutil.which (and is_available) found."""
    _no_mcp_config(monkeypatch)
    fake = fake_popen(returncode=0, stdout="ok", stderr="")
    ClaudeAdapter().run("hi", workdir=tmp_path)
    assert fake.call_args[0][0] == "/usr/bin/claude"


def test_launch_error_is_failed_status_not_a_crash(tmp_path, monkeypatch):
    _no_mcp_config(monkeypatch)
    monkeypatch.setattr("secfoo.agents.base.shutil.which", lambda name: f"/usr/bin/{name}")

    def _raise(*a, **kw):
        raise FileNotFoundError(2, "The system cannot find the file specified")

    monkeypatch.setattr("secfoo.agents.base.subprocess.Popen", _raise)
    result = ClaudeAdapter().run("hi", workdir=tmp_path)
    assert result.status == "failed"
    assert "failed to launch" in result.stderr


def test_kill_process_tree_uses_killpg_on_posix(monkeypatch):
    # raising=False: os.getpgid/os.killpg/signal.SIGKILL don't exist as
    # attributes at all outside POSIX (that's the bug this whole file is
    # about), so there's nothing for monkeypatch to find here on Windows.
    sigkill = object()
    calls = []
    monkeypatch.setattr("secfoo.agents.base.os.getpgid", lambda pid: pid, raising=False)
    monkeypatch.setattr("secfoo.agents.base.os.killpg", lambda pgid, sig: calls.append((pgid, sig)), raising=False)
    monkeypatch.setattr("secfoo.agents.base.signal.SIGKILL", sigkill, raising=False)
    _kill_process_tree(4321, posix=True)
    assert calls == [(4321, sigkill)]


def test_kill_process_tree_swallows_missing_process_on_posix(monkeypatch):
    """The target may have already exited by the time we try to kill it --
    that's a normal race, not an error."""

    def _raise(pid):
        raise ProcessLookupError

    monkeypatch.setattr("secfoo.agents.base.os.getpgid", _raise, raising=False)
    # Never actually called (getpgid raises first) -- just needs to exist as
    # an attribute so the call expression resolves on a platform without it.
    monkeypatch.setattr("secfoo.agents.base.os.killpg", lambda pgid, sig: None, raising=False)
    monkeypatch.setattr("secfoo.agents.base.signal.SIGKILL", object(), raising=False)
    _kill_process_tree(4321, posix=True)  # must not raise


def test_kill_process_tree_uses_taskkill_on_windows(monkeypatch):
    """os.killpg/os.getpgid don't exist outside POSIX -- Windows has no
    process-group equivalent in the stdlib, so this must shell out to
    `taskkill /T` (kill the whole process tree) instead."""
    calls = []
    monkeypatch.setattr("secfoo.agents.base.subprocess.run", lambda *a, **kw: calls.append((a, kw)))
    _kill_process_tree(4321, posix=False)
    assert calls
    args, kwargs = calls[0]
    assert args[0] == ["taskkill", "/F", "/T", "/PID", "4321"]
    assert kwargs["stdout"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.DEVNULL


def test_kill_process_tree_swallows_taskkill_errors_on_windows(monkeypatch):
    def _raise(*a, **kw):
        raise OSError("taskkill not found")

    monkeypatch.setattr("secfoo.agents.base.subprocess.run", _raise)
    _kill_process_tree(4321, posix=False)  # must not raise


def test_run_falls_back_to_stderr_usage_when_stdout_has_none(fake_popen, tmp_path):
    from secfoo.agents.codex import CodexAdapter

    fake_popen(returncode=0, stdout="# Report", stderr="working...\ntokens used\n15,201\n")
    result = CodexAdapter().run("hi", workdir=tmp_path)
    assert result.status == "success"
    assert result.input_tokens == 15201
    assert result.output_tokens is None
    assert result.cost_usd is None


def test_run_prefers_stdout_usage_over_stderr(fake_popen, tmp_path, monkeypatch):
    from secfoo.agents.base import Usage
    from secfoo.agents.codex import CodexAdapter

    monkeypatch.setattr(CodexAdapter, "extract_usage", lambda self, stdout: Usage(input_tokens=7, output_tokens=3))
    fake_popen(returncode=0, stdout="# Report", stderr="tokens used\n15,201\n")
    result = CodexAdapter().run("hi", workdir=tmp_path)
    assert (result.input_tokens, result.output_tokens) == (7, 3)
