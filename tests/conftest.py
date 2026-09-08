from __future__ import annotations

import subprocess

import pytest


class FakePopen:
    """Stand-in for subprocess.Popen used by AgentAdapter.run()."""

    def __init__(self, *, returncode: int = 0, stdout: str = "", stderr: str = "", raise_timeout: bool = False):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._raise_timeout = raise_timeout
        self._raised = False
        self.pid = 999999

    def communicate(self, timeout=None):
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
