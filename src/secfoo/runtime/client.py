"""Sensor-side configuration for the runtime ingest API (#66).

Set explicitly at deploy time, never guessed:

    SECFOO_API_KEY_FILE=/var/run/secrets/secfoo/api-key   # or SECFOO_API_KEY
    SECFOO_SERVER=https://app.secfoo.com                  # default: `secfoo cloud login`'s portal_url
    SECFOO_PROJECT=https://github.com/acme/payments-api   # exactly as `secfoo run` recorded it
    SECFOO_APP=payments-api
    SECFOO_ENV=prod

There is no fallback account: a missing key, server or project is an error.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class SensorConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class SensorConfig:
    api_key: str
    server: str
    project: str
    app: str | None = None
    env: str | None = None

    def __repr__(self) -> str:  # never print the key
        return f"SensorConfig(server={self.server!r}, project={self.project!r}, app={self.app!r}, env={self.env!r})"

    def url(self, endpoint: str) -> str:
        return f"{self.server.rstrip('/')}/api/runtime/v1/{endpoint.lstrip('/')}"


def _api_key(environ: dict[str, str]) -> str:
    key_file = environ.get("SECFOO_API_KEY_FILE", "").strip()
    if key_file:
        try:
            key = Path(key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SensorConfigError(f"can't read SECFOO_API_KEY_FILE ({key_file}): {exc.strerror}") from None
        if not key:
            raise SensorConfigError(f"SECFOO_API_KEY_FILE ({key_file}) is empty")
        return key
    key = environ.get("SECFOO_API_KEY", "").strip()
    if key:
        return key
    raise SensorConfigError("no API key: set SECFOO_API_KEY_FILE (recommended, from a mounted secret) or SECFOO_API_KEY")


def _server(environ: dict[str, str]) -> str:
    server = environ.get("SECFOO_SERVER", "").strip()
    if server:
        return server
    from secfoo.cloud import CloudError, load_cloud_config

    try:
        config = load_cloud_config()
    except CloudError:
        config = None
    if config is None:
        raise SensorConfigError("no server: set SECFOO_SERVER, or run `secfoo cloud login` so its portal URL is used")
    return config.portal_url


def load_sensor_config(environ: dict[str, str] | None = None) -> SensorConfig:
    environ = dict(os.environ if environ is None else environ)
    project = environ.get("SECFOO_PROJECT", "").strip()
    if not project:
        raise SensorConfigError("no project: set SECFOO_PROJECT to the identifier `secfoo run` recorded")
    server = _server(environ)
    if not server.startswith(("https://", "http://127.0.0.1", "http://localhost", "http://[::1]")):
        raise SensorConfigError(f"SECFOO_SERVER must be https:// (or a loopback http:// address), got {server!r}")
    return SensorConfig(
        api_key=_api_key(environ),
        server=server,
        project=project,
        app=environ.get("SECFOO_APP", "").strip() or None,
        env=environ.get("SECFOO_ENV", "").strip() or None,
    )
