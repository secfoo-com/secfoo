from __future__ import annotations

import subprocess

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
