"""The runner's best-effort helpers degrade quietly but leave a debug trace."""

import logging
import subprocess

from secfoo import runner


def test_git_head_commit_is_none_without_a_git_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert runner._git_head_commit(tmp_path) is None


def test_git_head_commit_is_none_when_git_times_out(tmp_path, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert runner._git_head_commit(tmp_path) is None


def test_a_failed_cloud_sync_is_logged_and_does_not_raise(monkeypatch, caplog):
    def broken_config():
        raise RuntimeError("portal unreachable")

    monkeypatch.setattr(runner.cloud, "load_cloud_config", broken_config)
    with caplog.at_level(logging.DEBUG, logger="secfoo.runner"):
        runner._try_cloud_sync(repo=None, run_uuid="run-1")

    assert any("cloud sync skipped for run run-1" in r.getMessage() for r in caplog.records)
