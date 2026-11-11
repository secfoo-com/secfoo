from __future__ import annotations

import subprocess

import pytest


@pytest.fixture(autouse=True)
def _isolated_custom_skills(tmp_path_factory, monkeypatch):
    """Custom skills (#79) load from ~/.secfoo/skills, [skills] paths and
    SECFOO_SKILLS_PATH. Point all three at nothing so a developer's own
    skills never leak into the test run, and reset the loader's cache."""
    from secfoo.skills import loader

    empty_home = tmp_path_factory.mktemp("secfoo-home")
    monkeypatch.setattr("secfoo.config.STORE_DIR", empty_home)
    monkeypatch.setattr("secfoo.settings.CONFIG_PATH", empty_home / "config.toml")
    monkeypatch.delenv(loader.SKILLS_PATH_ENV, raising=False)
    loader._reset_for_tests()
    yield empty_home
    loader._reset_for_tests()


class FakePopen:
    """Stand-in for subprocess.Popen used by AgentAdapter.run()."""

    def __init__(self, *, returncode: int = 0, stdout: str = "", stderr: str = "", raise_timeout: bool = False):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._raise_timeout = raise_timeout
        self._raised = False
        self.pid = 999999
        self.stdin_input = None

    def communicate(self, input=None, timeout=None):
        if input is not None:
            self.stdin_input = input
        if self._raise_timeout and not self._raised:
            self._raised = True
            raise subprocess.TimeoutExpired(cmd=["fake"], timeout=timeout)
        return self._stdout, self._stderr


@pytest.fixture
def fake_popen(monkeypatch):
    """Configure the next `subprocess.Popen` call inside secfoo.agents.base
    to return a FakePopen with the given behavior, and pretend the agent's
    binary is on PATH. Records the call's kwargs on `fake.call_kwargs` so
    tests can assert on how Popen was invoked (e.g. stdin handling).
    """

    def _install(*, binary_available: bool = True, **kwargs):
        fake = FakePopen(**kwargs)

        def _fake_popen(*args, **kw):
            fake.call_args = args
            fake.call_kwargs = kw
            return fake

        monkeypatch.setattr("secfoo.agents.base.subprocess.Popen", _fake_popen)
        if binary_available:
            monkeypatch.setattr("secfoo.agents.base.shutil.which", lambda name: f"/usr/bin/{name}")
        return fake

    return _install


@pytest.fixture(autouse=True)
def _isolate_memory_config(tmp_path, monkeypatch):
    """A developer's real ~/.secfoo/memory.toml (or SECFOO_MEMORY in their
    shell) must never turn pattern-memory on inside an unrelated test --
    every test starts with no memory key configured. Tests that want
    memory on write a key to `secfoo.memory.MEMORY_CONFIG_PATH`."""
    monkeypatch.setattr("secfoo.memory.MEMORY_CONFIG_PATH", tmp_path / "memory.toml")
    monkeypatch.delenv("SECFOO_MEMORY", raising=False)
