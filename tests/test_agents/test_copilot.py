from __future__ import annotations

from secfoo.agents.copilot import CopilotAdapter


def test_build_command(tmp_path):
    adapter = CopilotAdapter()
    cmd = adapter.build_command("hi", workdir=tmp_path)
    assert cmd == ["copilot", "-p", "hi", "-s", "--allow-all-tools"]


def test_build_command_never_grants_unrestricted_paths_or_urls(tmp_path):
    """--allow-all-tools is required for non-interactive mode, but the
    broader --allow-all/--yolo/--allow-all-paths/--allow-all-urls escape
    hatches are a materially bigger grant (arbitrary filesystem/network
    access) that a read-only security review never needs.
    """
    adapter = CopilotAdapter()
    cmd = adapter.build_command("hi", workdir=tmp_path)
    for forbidden in ("--allow-all", "--yolo", "--allow-all-paths", "--allow-all-urls"):
        assert forbidden not in cmd


def test_binary_and_name():
    assert CopilotAdapter.binary == "copilot"
    assert CopilotAdapter.name == "copilot"


def test_extract_report_defaults_to_raw_stdout():
    """Unlike claude.py/gemini.py, `copilot -s` prints the answer directly
    with no JSON envelope to unwrap -- confirmed against a real invocation.
    """
    adapter = CopilotAdapter()
    assert adapter.extract_report("# SAST Report\n...") == "# SAST Report\n..."


def test_is_available_uses_binary_name(monkeypatch):
    monkeypatch.setattr("secfoo.agents.base.shutil.which", lambda name: "/usr/bin/copilot" if name == "copilot" else None)
    assert CopilotAdapter().is_available() is True


def test_is_available_false_when_binary_missing(monkeypatch):
    monkeypatch.setattr("secfoo.agents.base.shutil.which", lambda name: None)
    assert CopilotAdapter().is_available() is False


def test_run_success(fake_popen, tmp_path):
    fake_popen(stdout="# SAST Report\n\nfindings...", stderr="", returncode=0)
    adapter = CopilotAdapter()
    result = adapter.run("hi", workdir=tmp_path)
    assert result.status == "success"
    assert result.raw_report == "# SAST Report\n\nfindings..."


def test_run_timeout_does_not_raise(fake_popen, tmp_path):
    fake_popen(raise_timeout=True, stdout="partial", stderr="")
    adapter = CopilotAdapter()
    result = adapter.run("hi", workdir=tmp_path, timeout=1)
    assert result.status == "timeout"
    assert result.timed_out is True
    assert result.exit_code is None
    assert result.raw_report == ""
