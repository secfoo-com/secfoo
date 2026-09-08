from __future__ import annotations

from secfoo.agents.antigravity import AntigravityAdapter


def test_build_command_uses_print_and_print_timeout(tmp_path):
    adapter = AntigravityAdapter()
    cmd = adapter.build_command("hi", workdir=tmp_path)
    assert cmd[0] == "agy"
    assert "--print" in cmd
    assert "hi" in cmd
    assert "--print-timeout" in cmd


def test_run_threads_effective_timeout_into_print_timeout_flag(fake_popen, tmp_path):
    fake_popen(returncode=0, stdout="# Report", stderr="")
    adapter = AntigravityAdapter()
    result = adapter.run("hi", workdir=tmp_path, timeout=42)
    assert result.status == "success"
    assert result.raw_report == "# Report"
    cmd = adapter.build_command("hi", workdir=tmp_path)
    assert "42s" in cmd


def test_no_dangerously_skip_permissions_flag(tmp_path):
    adapter = AntigravityAdapter()
    cmd = adapter.build_command("hi", workdir=tmp_path)
    assert "--dangerously-skip-permissions" not in cmd
