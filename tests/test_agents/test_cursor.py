from __future__ import annotations

from secfoo.agents.cursor import CursorAdapter


def test_build_command(tmp_path):
    adapter = CursorAdapter()
    cmd = adapter.build_command("hi", workdir=tmp_path)
    assert cmd == ["agent", "-p", "hi"]


def test_shorter_default_timeout_than_other_agents():
    assert CursorAdapter.default_timeout_seconds < 1800


def test_timeout_status_does_not_raise(fake_popen, tmp_path):
    """Regression test for the documented `agent -p` hang bug: a hang must
    resolve to status="timeout" rather than blocking forever or raising."""
    fake_popen(raise_timeout=True, stdout="partial output", stderr="")
    adapter = CursorAdapter()
    result = adapter.run("hi", workdir=tmp_path, timeout=1)
    assert result.status == "timeout"
    assert result.timed_out is True
    assert result.exit_code is None
    assert result.raw_report == ""
