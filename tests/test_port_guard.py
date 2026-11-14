"""secfoo.web.port_guard: detecting and safely replacing an existing
`secfoo serve` on the same host/port (never an unrelated process)."""
from __future__ import annotations

import socket
import subprocess

import pytest

from secfoo.web import port_guard
from secfoo.web.port_guard import PortOwner, find_owner, port_in_use, stop_gracefully

# ---------- port_in_use ----------


def test_port_in_use_detects_a_real_bound_socket():
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    holder.listen()
    port = holder.getsockname()[1]
    try:
        assert port_in_use("127.0.0.1", port) is True
    finally:
        holder.close()
    assert port_in_use("127.0.0.1", port) is False


# ---------- PortOwner.is_secfoo_serve ----------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/usr/bin/python3 /usr/local/bin/secfoo serve --port 8787", True),
        ("SECFOO_HOME=/tmp/x secfoo serve", True),
        ("/usr/bin/node /usr/local/bin/some-other-server", False),
        ("secfoo run --skill sast --target .", False),  # secfoo, but not "serve"
        ("", False),
    ],
)
def test_is_secfoo_serve(command, expected):
    assert PortOwner(pid=1, command=command).is_secfoo_serve is expected


# ---------- find_owner (POSIX path) ----------


def _fake_run(responses: dict[tuple, subprocess.CompletedProcess]):
    def _run(args, **kwargs):
        key = tuple(args)
        if key in responses:
            return responses[key]
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
    return _run


def test_find_owner_parses_lsof_and_ps(monkeypatch):
    monkeypatch.setattr(port_guard.sys, "platform", "darwin")
    monkeypatch.setattr(
        port_guard.subprocess, "run",
        _fake_run({
            ("lsof", "-iTCP:8787", "-sTCP:LISTEN", "-t"): subprocess.CompletedProcess(
                [], 0, stdout="4242\n", stderr=""
            ),
            ("ps", "-p", "4242", "-o", "command="): subprocess.CompletedProcess(
                [], 0, stdout="/usr/bin/python3 /usr/local/bin/secfoo serve\n", stderr=""
            ),
        }),
    )
    owner = find_owner(8787)
    assert owner == PortOwner(pid=4242, command="/usr/bin/python3 /usr/local/bin/secfoo serve")
    assert owner.is_secfoo_serve


def test_find_owner_returns_none_when_nothing_is_listening(monkeypatch):
    monkeypatch.setattr(port_guard.sys, "platform", "darwin")
    monkeypatch.setattr(
        port_guard.subprocess, "run",
        _fake_run({("lsof", "-iTCP:8787", "-sTCP:LISTEN", "-t"): subprocess.CompletedProcess([], 1, stdout="", stderr="")}),
    )
    assert find_owner(8787) is None


def test_find_owner_returns_none_when_lsof_is_missing(monkeypatch):
    monkeypatch.setattr(port_guard.sys, "platform", "darwin")

    def _raise(*args, **kwargs):
        raise OSError("lsof not found")

    monkeypatch.setattr(port_guard.subprocess, "run", _raise)
    assert find_owner(8787) is None


# ---------- stop_gracefully ----------


def test_stop_gracefully_succeeds_after_sigterm(monkeypatch):
    killed = []
    alive = {"value": True}

    def _fake_kill(pid, sig):
        killed.append(sig)
        alive["value"] = False  # the process "exits" once SIGTERM is sent

    monkeypatch.setattr(port_guard.os, "kill", lambda pid, sig: _fake_kill(pid, sig) if sig != 0 else None)
    monkeypatch.setattr(port_guard, "_process_alive", lambda pid: alive["value"])

    owner = PortOwner(pid=4242, command="secfoo serve")
    assert stop_gracefully(owner, timeout=1) is True
    assert killed == [port_guard.signal.SIGTERM]


def test_stop_gracefully_falls_back_to_sigkill_when_sigterm_is_ignored(monkeypatch):
    signals_sent = []
    alive = {"value": True}

    def _fake_kill(pid, sig):
        signals_sent.append(sig)
        if sig == port_guard.signal.SIGKILL:
            alive["value"] = False

    monkeypatch.setattr(port_guard.os, "kill", _fake_kill)
    monkeypatch.setattr(port_guard, "_process_alive", lambda pid: alive["value"])

    owner = PortOwner(pid=4242, command="secfoo serve")
    assert stop_gracefully(owner, timeout=1) is True
    assert signals_sent == [port_guard.signal.SIGTERM, port_guard.signal.SIGKILL]


def test_stop_gracefully_gives_up_if_the_process_never_dies(monkeypatch):
    monkeypatch.setattr(port_guard.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(port_guard, "_process_alive", lambda pid: True)

    owner = PortOwner(pid=4242, command="secfoo serve")
    assert stop_gracefully(owner, timeout=0.3) is False
