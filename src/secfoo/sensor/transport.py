"""Where a probe's events go (#73 transports), chosen by one env var.

    SECFOO_SENSOR_ADDR=unix:///var/run/secfoo/sensor.sock   host daemon / sidecar sharing a volume
    SECFOO_SENSOR_ADDR=tcp://127.0.0.1:7461                 sidecar sharing a network namespace (loopback only)
    SECFOO_SENSOR_ADDR=npipe:////./pipe/secfoo-sensor       Windows
    SECFOO_SENSOR_ADDR=https://secfoo.internal              direct mode (serverless): POST to the #66 API
    SECFOO_SENSOR_ADDR=file:///path/events.ndjson           offline; read later with `secfoo runtime ingest`

With no SECFOO_SENSOR_ADDR, SECFOO_EVENTS_OUT (a file path) is used. Every
`send()` runs on the probe's flush thread, never on a request path, and
returns False instead of raising or retrying when the destination is gone.
The probe opens no connection other than the one named here.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import os
import socket
import sys
import urllib.parse
import urllib.request

PROTOCOL_VERSION = 1
DIRECT_TIMEOUT_SECONDS = 0.2  # #73: a cold start or shutdown never waits on the network
SOCKET_TIMEOUT_SECONDS = 1.0


class TransportError(ValueError):
    """The address is malformed or not allowed (e.g. a routable TCP host)."""


def _lines(events: list[dict]) -> bytes:
    return "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events).encode("utf-8")


def hello(runtime: str = "python") -> dict:
    return {
        "type": "hello", "protocol": PROTOCOL_VERSION, "runtime": runtime,
        "runtime_version": ".".join(map(str, sys.version_info[:3])),
        "probe_version": "0.1.0", "pid": os.getpid(),
        "host": os.environ.get("HOSTNAME") or socket.gethostname(),
    }


class FileTransport:
    def __init__(self, path: str) -> None:
        self.path = path.replace("{pid}", str(os.getpid()))
        self.template = path

    def send(self, events: list[dict]) -> bool:
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, _lines(events))  # one write per flush: lines from forked workers never interleave
            finally:
                os.close(fd)
            return True
        except OSError:
            return False

    def reopen(self) -> FileTransport:
        return FileTransport(self.template)

    def close(self) -> None:
        pass


class _StreamTransport:
    """unix / tcp / npipe: newline-framed #53 lines after a `hello`."""

    def __init__(self, address: str) -> None:
        self.address = address
        self._conn = None
        self.slow = False

    def _connect(self):
        raise NotImplementedError

    def _write(self, data: bytes) -> None:
        raise NotImplementedError

    def send(self, events: list[dict]) -> bool:
        try:
            if self._conn is None:
                self._connect()
                self._write(_lines([hello()]))
            self._write(_lines(events))
            return True
        except OSError:
            self.close()  # sensor gone: drop this batch, reconnect next flush
            return False

    def reopen(self):
        return type(self)(self.address)

    def close(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


class SocketTransport(_StreamTransport):
    def __init__(self, address: str) -> None:
        super().__init__(address)
        parsed = urllib.parse.urlsplit(address)
        self.scheme = parsed.scheme
        if parsed.scheme == "tcp":
            host = parsed.hostname or ""
            try:
                loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
            if not loopback or not parsed.port:
                raise TransportError("tcp:// sensor addresses must be loopback with a port, e.g. tcp://127.0.0.1:7461")
            self.target = (host, parsed.port)
        else:
            self.target = parsed.path

    def _connect(self):
        family = socket.AF_INET6 if self.scheme == "tcp" and ":" in self.target[0] else socket.AF_INET
        if self.scheme == "unix":
            family = socket.AF_UNIX
        conn = socket.socket(family, socket.SOCK_STREAM)
        conn.settimeout(SOCKET_TIMEOUT_SECONDS)
        try:
            conn.connect(self.target)
        except OSError:
            conn.close()
            raise
        self._conn = conn
        key = os.environ.get("SECFOO_SENSOR_KEY")
        if key and self.scheme == "tcp":
            self._write(_lines([{"type": "auth", "key": key}]))

    def _write(self, data: bytes) -> None:
        self._conn.sendall(data)


class PipeTransport(_StreamTransport):
    def __init__(self, address: str) -> None:
        super().__init__(address)
        # npipe:////./pipe/secfoo-sensor -> \\.\pipe\secfoo-sensor
        self.path = "\\\\" + address[len("npipe:////"):].replace("/", "\\")

    def _connect(self):
        self._conn = open(self.path, "wb", buffering=0)  # noqa: SIM115 -- kept open between flushes

    def _write(self, data: bytes) -> None:
        self._conn.write(data)


class DirectTransport:
    """Direct mode: POST gzip NDJSON to the #66 API with the sensor's key,
    capped at DIRECT_TIMEOUT_SECONDS so the app never waits on the network."""

    def __init__(self, address: str) -> None:
        from secfoo.runtime.client import load_sensor_config

        self.config = load_sensor_config({**os.environ, "SECFOO_SERVER": address})

    def send(self, events: list[dict]) -> bool:
        query = urllib.parse.urlencode({k: v for k, v in {
            "project": self.config.project, "app": self.config.app, "env": self.config.env}.items() if v})
        request = urllib.request.Request(  # nosec B310 -- https enforced by load_sensor_config
            self.config.url("events") + "?" + query, data=gzip.compress(_lines(events)), method="POST",
            headers={"Authorization": f"Bearer {self.config.api_key}", "Content-Encoding": "gzip",
                     "Content-Type": "application/x-ndjson"},
        )
        try:
            with urllib.request.urlopen(request, timeout=DIRECT_TIMEOUT_SECONDS) as response:  # nosec B310
                return 200 <= response.status < 300
        except OSError:
            return False

    def reopen(self):
        return self

    def close(self) -> None:
        pass


class NullTransport:
    def send(self, events: list[dict]) -> bool:
        return False

    def reopen(self):
        return self

    def close(self) -> None:
        pass


def from_env(environ: dict[str, str] | None = None):
    environ = os.environ if environ is None else environ
    address = environ.get("SECFOO_SENSOR_ADDR", "").strip()
    if not address:
        out = environ.get("SECFOO_EVENTS_OUT", "").strip()
        return FileTransport(out) if out else NullTransport()
    scheme = urllib.parse.urlsplit(address).scheme
    if scheme == "file":
        return FileTransport(urllib.request.url2pathname(urllib.parse.urlsplit(address).path))
    if scheme in ("unix", "tcp"):
        return SocketTransport(address)
    if scheme == "npipe":
        return PipeTransport(address)
    if scheme == "https":
        return DirectTransport(address)
    raise TransportError(f"unsupported SECFOO_SENSOR_ADDR {address!r}; use unix://, tcp://, npipe://, https:// or file://")
