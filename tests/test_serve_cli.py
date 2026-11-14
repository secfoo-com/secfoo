"""`secfoo serve` refusing/replacing a busy port -- never touches an
unrelated or unidentified process, even with --replace."""
from __future__ import annotations

from typer.testing import CliRunner

from secfoo.cli import app
from secfoo.web.port_guard import PortOwner

runner = CliRunner(env={"COLUMNS": "300"})


def _out(result) -> str:
    return " ".join(result.output.split())


def test_serve_starts_when_the_port_is_free(monkeypatch):
    monkeypatch.setattr("secfoo.web.port_guard.port_in_use", lambda host, port: False)
    started = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.update(kw) or None)

    result = runner.invoke(app, ["serve", "--runtime-recheck-hours", "0"])
    assert result.exit_code == 0, result.output
    assert started.get("port") == 8787


def test_serve_refuses_and_explains_when_port_busy_with_a_known_owner(monkeypatch):
    monkeypatch.setattr("secfoo.web.port_guard.port_in_use", lambda host, port: True)
    monkeypatch.setattr(
        "secfoo.web.port_guard.find_owner", lambda port, **kw: PortOwner(pid=999, command="node server.js")
    )
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: pytest_fail_if_called())

    result = runner.invoke(app, ["serve"])
    assert result.exit_code == 1
    out = _out(result)
    assert "pid 999" in out and "node server.js" in out
    assert "lsof -i :8787" in out and "--replace" in out


def test_serve_refuses_and_explains_when_port_busy_with_an_unknown_owner(monkeypatch):
    monkeypatch.setattr("secfoo.web.port_guard.port_in_use", lambda host, port: True)
    monkeypatch.setattr("secfoo.web.port_guard.find_owner", lambda port, **kw: None)

    result = runner.invoke(app, ["serve"])
    assert result.exit_code == 1
    assert "another process" in _out(result)


def test_serve_replace_stops_a_recognized_secfoo_serve_and_starts(monkeypatch):
    state = {"freed": False}

    def _port_in_use(host, port):
        return not state["freed"]

    def _stop(owner, **kw):
        state["freed"] = True
        return True

    monkeypatch.setattr("secfoo.web.port_guard.port_in_use", _port_in_use)
    monkeypatch.setattr(
        "secfoo.web.port_guard.find_owner", lambda port, **kw: PortOwner(pid=777, command="secfoo serve --port 8787")
    )
    monkeypatch.setattr("secfoo.web.port_guard.stop_gracefully", _stop)
    started = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.update(kw) or None)

    result = runner.invoke(app, ["serve", "--replace", "--runtime-recheck-hours", "0"])
    assert result.exit_code == 0, result.output
    assert "stopping it" in _out(result)
    assert started.get("port") == 8787


def test_serve_replace_refuses_to_stop_an_unrelated_process(monkeypatch):
    monkeypatch.setattr("secfoo.web.port_guard.port_in_use", lambda host, port: True)
    monkeypatch.setattr(
        "secfoo.web.port_guard.find_owner", lambda port, **kw: PortOwner(pid=555, command="python manage.py runserver")
    )
    stopped = []
    monkeypatch.setattr("secfoo.web.port_guard.stop_gracefully", lambda owner, **kw: stopped.append(owner) or True)
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: pytest_fail_if_called())

    result = runner.invoke(app, ["serve", "--replace"])
    assert result.exit_code == 1
    assert "doesn't look like" in _out(result)
    assert stopped == []  # never touched


def test_serve_replace_reports_failure_if_the_old_process_wont_die(monkeypatch):
    monkeypatch.setattr("secfoo.web.port_guard.port_in_use", lambda host, port: True)
    monkeypatch.setattr(
        "secfoo.web.port_guard.find_owner", lambda port, **kw: PortOwner(pid=888, command="secfoo serve")
    )
    monkeypatch.setattr("secfoo.web.port_guard.stop_gracefully", lambda owner, **kw: False)
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: pytest_fail_if_called())

    result = runner.invoke(app, ["serve", "--replace"])
    assert result.exit_code == 1
    assert "couldn't stop pid 888" in _out(result)


def pytest_fail_if_called(*args, **kwargs):
    import pytest

    pytest.fail("uvicorn.run must not be called")
