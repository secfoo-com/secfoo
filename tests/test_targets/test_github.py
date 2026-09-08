from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from secfoo.targets.github import clone_shallow
from secfoo.targets.resolver import TargetResolutionError


def test_clone_shallow_cleans_up_on_success(monkeypatch):
    def fake_run(cmd, **kwargs):
        target_dir = Path(cmd[-1])
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "marker.txt").write_text("x")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("secfoo.targets.github.subprocess.run", fake_run)

    captured: dict[str, Path] = {}
    with clone_shallow("https://github.com/org/repo") as path:
        captured["dir"] = path
        assert path.exists()
        assert (path / "marker.txt").exists()

    assert not captured["dir"].exists()


def test_clone_shallow_cleans_up_when_body_raises(monkeypatch):
    def fake_run(cmd, **kwargs):
        Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("secfoo.targets.github.subprocess.run", fake_run)

    captured: dict[str, Path] = {}
    with pytest.raises(RuntimeError):
        with clone_shallow("https://github.com/org/repo") as path:
            captured["dir"] = path
            raise RuntimeError("boom")

    assert not captured["dir"].exists()


def test_clone_shallow_raises_target_resolution_error_on_git_failure(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(returncode=128, cmd=cmd, stderr="fatal: repo not found")

    monkeypatch.setattr("secfoo.targets.github.subprocess.run", fake_run)

    with pytest.raises(TargetResolutionError):
        with clone_shallow("https://github.com/org/nope"):
            pass


def test_clone_shallow_surfaces_disk_full_with_actionable_message(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=128,
            cmd=cmd,
            stderr="error: unable to create file foo.ts: No space left on device",
        )

    monkeypatch.setattr("secfoo.targets.github.subprocess.run", fake_run)

    with pytest.raises(TargetResolutionError, match="disk full"):
        with clone_shallow("https://github.com/org/repo"):
            pass
