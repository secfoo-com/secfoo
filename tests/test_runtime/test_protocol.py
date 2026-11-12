"""#73: probe <-> sensor protocol, schemas and the conformance kit."""
from __future__ import annotations

import json
import socket
import sys
import textwrap
import threading
from pathlib import Path

import pytest

import secfoo
from secfoo.runtime import protocol
from secfoo.runtime.conformance.kit import run_kit
from secfoo.runtime.protocol import (
    SENTINEL,
    ProtocolError,
    forbidden_data,
    validate_message,
)
from secfoo.sensor import transport as transport_mod

RUNTIME_DIR = Path(protocol.__file__).parent
REFERENCE = [sys.executable, "-m", "secfoo.sensor", "-m", "secfoo.runtime.conformance.sample_app"]


def _hello(**overrides):
    return {**transport_mod.hello(), **overrides}


# ---------- messages ----------


def test_the_reference_probe_hello_is_valid():
    validate_message(_hello())


@pytest.mark.parametrize("message, field", [
    (_hello(protocol=2), "protocol"),
    (_hello(runtime="cobol"), "runtime"),
    (_hello(pid=0), "pid"),
    ({"type": "welcome", "protocol": 1, "flush_interval": 0}, "flush_interval"),
    ({"type": "slow", "sample_every": 0}, "sample_every"),
    ({"type": "auth", "key": ""}, "key"),
    ({"type": "nonsense"}, "type"),
])
def test_invalid_control_messages_name_the_field(message, field):
    with pytest.raises(ProtocolError, match=field):
        validate_message(message)


def test_event_lines_are_validated_with_the_53_rules():
    validate_message({"type": "session", "id": "s", "language": "go", "source": "sensor",
                      "started_at": "2026-11-12T00:00:00Z"})
    with pytest.raises(ProtocolError, match="template"):
        validate_message({"type": "hit", "session": "s", "finding_fingerprint": "f", "symbol": "x.y",
                          "count": 1, "route": "GET /a?b=c"})


def test_forbidden_data_detection():
    clean = json.dumps({"type": "hit", "route": "GET /users/{id}", "symbol": "x.y", "count": 1})
    leaky = [json.dumps({"type": "hit", "arg": SENTINEL}),
             json.dumps({"type": "hit", "route": "/search?q=1"}),
             json.dumps({"type": "hit", "header": "Bearer abcdef123456"}),
             json.dumps({"type": "hit", "route": "GET /users/8675309"})]
    assert forbidden_data([clean]) == []
    assert len(forbidden_data(leaky)) == 4
    assert forbidden_data([json.dumps({"type": "auth", "key": "Bearer abcdefgh"})]) == []  # the one allowed secret


def test_json_schema_agrees_with_the_validator():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource

    schemas = {name: json.loads((RUNTIME_DIR / name).read_text(encoding="utf-8"))
               for name in ("protocol.schema.json", "evidence.schema.json")}
    registry = Registry().with_resources(
        (name, Resource.from_contents(body)) for name, body in schemas.items()
    ).with_resources((body["$id"], Resource.from_contents(body)) for body in schemas.values())
    jsonschema.Draft202012Validator.check_schema(schemas["protocol.schema.json"])
    validator = jsonschema.Draft202012Validator(schemas["protocol.schema.json"], registry=registry)
    good = [_hello(), {"type": "welcome", "protocol": 1, "flush_interval": 0.5},
            {"type": "slow", "sample_every": 4}, {"type": "auth", "key": "k"},
            {"type": "session", "id": "s", "language": "python", "source": "sensor", "started_at": "2026-11-12T00:00:00Z"}]
    for message in good:
        validate_message(message)
        assert validator.is_valid(message), list(validator.iter_errors(message))
    for message in (_hello(protocol=2), {"type": "slow", "sample_every": 0}, {"type": "welcome", "protocol": 1}):
        assert not validator.is_valid(message)
        with pytest.raises(ProtocolError):
            validate_message(message)


# ---------- the reference probe's transport follows the protocol ----------


def _listen():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    return server, server.getsockname()[1]


def test_hello_then_auth_then_events_and_welcome_is_honoured(monkeypatch):
    monkeypatch.setenv("SECFOO_SENSOR_KEY", "pod-shared-key")
    server, port = _listen()
    received = []

    def sensor():
        conn, _ = server.accept()
        data = b""
        while data.count(b"\n") < 3:
            data += conn.recv(65536)
        conn.sendall(b'{"type":"welcome","protocol":1,"flush_interval":0.25}\n{"type":"slow","sample_every":2}\n')
        received.extend(json.loads(line) for line in data.splitlines())
        threading.Event().wait(0.5)
        conn.close()
        server.close()

    thread = threading.Thread(target=sensor, daemon=True)
    thread.start()
    tcp = transport_mod.SocketTransport(f"tcp://127.0.0.1:{port}")
    assert tcp.send([{"type": "session", "id": "s"}])
    thread.join(0.3)
    tcp.send([{"type": "session", "id": "s"}])  # picks up the sensor's answers
    assert [m["type"] for m in received[:3]] == ["hello", "auth", "session"]
    assert received[1]["key"] == "pod-shared-key"
    assert tcp.flush_interval == 0.25 and tcp.slow


def test_probe_flush_interval_follows_welcome_and_slow():
    from secfoo.sensor.probe import Probe

    class Stub(transport_mod.NullTransport):
        flush_interval = 2.0
        slow = False

    probe = Probe(watchlist_path=None, transport=Stub(), flush_seconds=10)
    assert probe._interval() == 2.0
    probe.transport.slow = True
    assert probe._interval() == 4.0


# ---------- the kit ----------


def test_reference_python_probe_passes_the_kit():
    results = {r.name: r for r in run_kit(REFERENCE, loop_calls=50000)}
    failed = {name: r.detail for name, r in results.items() if not r.passed}
    assert not failed, failed
    assert set(results) == {"inert", "call", "nocall", "privacy", "fail-open", "overhead"}


def test_the_kit_catches_a_misbehaving_probe(tmp_path):
    """A 'probe' that ignores SECFOO_SENSOR, sends a concrete URL and leaks the
    request's secret must fail inert, call and privacy."""
    bad = tmp_path / "bad_probe.py"
    bad.write_text(textwrap.dedent("""\
        import json, os, socket, sys
        addr = os.environ["SECFOO_SENSOR_ADDR"].split("//")[1]
        host, port = addr.split(":")
        s = socket.create_connection((host, int(port)))
        hello = {"type": "hello", "protocol": 1, "runtime": "python", "runtime_version": "3", "probe_version": "0",
                  "pid": os.getpid(), "host": "h"}
        hit = {"type": "hit", "session": "s", "finding_fingerprint": "f", "symbol": "x.y", "count": 1,
               "route": "GET /users/8675309?token=" + os.environ.get("SECFOO_CONFORMANCE_SENTINEL", "")}
        s.sendall((json.dumps(hello) + "\\n" + json.dumps(hit) + "\\n").encode())
        s.close()
        print("ok")
        """), encoding="utf-8")
    results = {r.name: r for r in run_kit([sys.executable, str(bad)], loop_calls=1000)}
    assert not results["inert"].passed
    assert not results["call"].passed
    assert not results["privacy"].passed
    assert "template" in results["privacy"].detail or "forbidden" in results["privacy"].detail


def test_cli_reports_and_exits_nonzero_on_failure(tmp_path):
    from typer.testing import CliRunner

    from secfoo.cli import app

    noop = tmp_path / "noop.py"
    noop.write_text("print('ok')\n", encoding="utf-8")
    result = CliRunner(env={"COLUMNS": "200"}).invoke(app, ["sensor", "conformance", "--", sys.executable, str(noop)])
    assert result.exit_code == 1
    assert "PASS inert" in result.output and "FAIL call" in result.output


def test_sample_app_ships_with_the_package():
    package = Path(secfoo.__file__).parent / "runtime" / "conformance"
    assert {"sample_app.py", "vulnerable.py", "kit.py"} <= {p.name for p in package.iterdir()}
