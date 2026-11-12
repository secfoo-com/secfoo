"""#66: runtime ingest API on `secfoo serve`, authenticated with the user's API key."""
from __future__ import annotations

import gzip
import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from secfoo.cli import app as cli_app
from secfoo.runtime import api as runtime_api
from secfoo.runtime import keys
from secfoo.runtime.client import SensorConfigError, load_sensor_config
from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app

PROJECT = "https://github.com/acme/payments-api"
FP = "fp-yaml"
SESSION = {"type": "session", "id": "s-1", "language": "python", "source": "sensor",
           "started_at": "2026-11-12T10:00:00Z", "ended_at": "2026-11-12T11:00:00Z",
           "app_functions_total": 100, "app_functions_executed": 40}
HIT = {"type": "hit", "session": "s-1", "finding_fingerprint": FP, "symbol": "yaml.load",
       "route": "POST /upload", "auth": "anonymous", "count": 7}


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    runtime_api.rate_limiter.reset()
    with RunRepository() as repo:
        pid = repo.upsert_project(PROJECT, "payments-api", "github")
        other = repo.upsert_project("https://github.com/acme/other", "other", "github")
        run_id = repo.get_run(repo.create_run(project_id=pid, skill_id="sca-reachability", skill_name="SCA",
                                              agent_id="claude", confluence_urls=[])).id
        repo.upsert_sca_finding(project_id=pid, fingerprint=FP, run_id=run_id, current_ref="D1", package="pyyaml",
                                severity="High", version="5.3", ecosystem="PyPI", reachability="Not reachable")
        repo.upsert_osv_lookup(ecosystem="PyPI", package="pyyaml", version="5.3", vulns=[])
        key, _ = keys.create_key(repo.connection, name="all-projects")
        scoped, _ = keys.create_key(repo.connection, name="other-only", project_id=other, scope="runtime")
    return {"key": key, "scoped": scoped, "project_id": pid}


@pytest.fixture
def client(store):
    return TestClient(create_app())


def _auth(key):
    return {"Authorization": f"Bearer {key}"}


def _ndjson(*events) -> bytes:
    return ("\n".join(json.dumps(e) for e in events) + "\n").encode()


# ---------- events ----------


def test_valid_batch_is_stored(client, store):
    resp = client.post("/api/runtime/v1/events", params={"project": PROJECT, "app": "payments-api", "env": "prod"},
                       content=_ndjson(SESSION, HIT), headers=_auth(store["key"]))
    assert resp.status_code == 200, resp.text
    assert resp.json()["sessions"] == 1 and resp.json()["hits"] == 1
    with RunRepository() as repo:
        app, env = repo.connection.execute("SELECT app, env FROM runtime_sessions").fetchone()
    assert (app, env) == ("payments-api", "prod")  # filled from the sensor's SECFOO_APP / SECFOO_ENV


def test_replayed_batch_does_not_double_count(client, store):
    body = gzip.compress(_ndjson(SESSION, HIT))
    for _ in range(2):
        resp = client.post("/api/runtime/v1/events", params={"project": PROJECT}, content=body,
                           headers={**_auth(store["key"]), "Content-Encoding": "gzip"})
        assert resp.status_code == 200
    with RunRepository() as repo:
        assert [tuple(r) for r in repo.connection.execute("SELECT count FROM runtime_evidence")] == [(7,)]


def test_malformed_lines_are_reported_not_fatal(client, store):
    resp = client.post("/api/runtime/v1/events", params={"project": PROJECT},
                       content=_ndjson(SESSION) + b"{broken\n" + _ndjson(HIT), headers=_auth(store["key"]))
    assert resp.status_code == 200
    assert resp.json()["hits"] == 1 and resp.json()["skipped"][0]["line"] == 2


# ---------- auth and access ----------


def test_missing_or_invalid_key_is_rejected(client):
    assert client.get("/api/runtime/v1/watchlist", params={"project": PROJECT}).status_code == 401
    bad = client.get("/api/runtime/v1/watchlist", params={"project": PROJECT}, headers=_auth("sfk_nope"))
    assert bad.status_code == 401


def test_key_without_access_to_the_project_is_rejected(client, store):
    resp = client.post("/api/runtime/v1/events", params={"project": PROJECT}, content=_ndjson(SESSION),
                       headers=_auth(store["scoped"]))
    assert resp.status_code == 403 and "no access" in resp.json()["detail"]


def test_unknown_project_is_rejected_not_created(client, store):
    resp = client.post("/api/runtime/v1/events", params={"project": "https://github.com/acme/never-scanned"},
                       content=_ndjson(SESSION), headers=_auth(store["key"]))
    assert resp.status_code == 404 and "run `secfoo run`" in resp.json()["detail"]
    with RunRepository() as repo:
        assert repo.find_project_id("https://github.com/acme/never-scanned") is None


def test_revoked_key_is_rejected(client, store):
    with RunRepository() as repo:
        record = next(k for k in keys.list_keys(repo.connection) if k.name == "all-projects")
        assert keys.revoke_key(repo.connection, record.id)
    resp = client.get("/api/runtime/v1/evidence", params={"project": PROJECT}, headers=_auth(store["key"]))
    assert resp.status_code == 401


def test_errors_never_echo_the_key(client, store):
    resp = client.get("/api/runtime/v1/evidence", params={"project": "nope"}, headers=_auth(store["key"]))
    assert store["key"] not in resp.text


def test_keys_are_stored_hashed(store):
    with RunRepository() as repo:
        dump = json.dumps([list(r) for r in repo.connection.execute("SELECT * FROM runtime_api_keys")])
    assert store["key"] not in dump and keys.hash_key(store["key"]) in dump


# ---------- hardening ----------


def test_oversized_body_is_rejected(client, store, monkeypatch):
    monkeypatch.setattr(runtime_api, "MAX_BODY_BYTES", 1000)
    resp = client.post("/api/runtime/v1/events", params={"project": PROJECT}, content=b"x" * 2000,
                       headers=_auth(store["key"]))
    assert resp.status_code == 413


def test_gzip_bomb_is_rejected(client, store, monkeypatch):
    monkeypatch.setattr(runtime_api, "MAX_DECOMPRESSED_BYTES", 10_000)
    resp = client.post("/api/runtime/v1/events", params={"project": PROJECT},
                       content=gzip.compress(b"\n" * 100_000), headers={**_auth(store["key"]), "Content-Encoding": "gzip"})
    assert resp.status_code == 413


def test_too_many_lines_is_rejected(client, store, monkeypatch):
    monkeypatch.setattr(runtime_api, "MAX_BATCH_LINES", 3)
    resp = client.post("/api/runtime/v1/events", params={"project": PROJECT}, content=_ndjson(*[SESSION] * 5),
                       headers=_auth(store["key"]))
    assert resp.status_code == 413


def test_rate_limit_per_key(client, store, monkeypatch):
    monkeypatch.setattr(runtime_api, "RATE_LIMIT_REQUESTS", 2)
    codes = [client.get("/api/runtime/v1/evidence", params={"project": PROJECT}, headers=_auth(store["key"])).status_code
             for _ in range(3)]
    assert codes == [200, 200, 429]


def test_plain_http_on_a_non_loopback_bind_is_refused_unless_opted_in(store):
    exposed = TestClient(create_app(bind_host="0.0.0.0"))  # nosec B104 -- test of the guard itself
    resp = exposed.get("/api/runtime/v1/evidence", params={"project": PROJECT}, headers=_auth(store["key"]))
    assert resp.status_code == 403 and "plain HTTP" in resp.json()["detail"]
    over_tls = TestClient(create_app(bind_host="0.0.0.0"), base_url="https://testserver")  # nosec B104
    assert over_tls.get("/api/runtime/v1/evidence", params={"project": PROJECT},
                        headers=_auth(store["key"])).status_code == 200
    opted_in = TestClient(create_app(bind_host="0.0.0.0", allow_insecure_runtime=True))  # nosec B104
    assert opted_in.get("/api/runtime/v1/evidence", params={"project": PROJECT},
                        headers=_auth(store["key"])).status_code == 200


# ---------- watchlist, heartbeat, evidence ----------


def test_watchlist_with_etag(client, store):
    first = client.get("/api/runtime/v1/watchlist", params={"project": PROJECT}, headers=_auth(store["key"]))
    assert first.status_code == 200 and first.json()["entries"][0]["finding_fingerprint"] == FP
    etag = first.headers["ETag"]
    again = client.get("/api/runtime/v1/watchlist", params={"project": PROJECT},
                       headers={**_auth(store["key"]), "If-None-Match": etag})
    assert again.status_code == 304 and again.content == b""


def test_heartbeat_registers_the_sensor_and_sums_drops(client, store):
    for dropped in (3, 4):
        resp = client.post("/api/runtime/v1/heartbeat", params={"project": PROJECT}, headers=_auth(store["key"]),
                           json={"sensor_id": "sensor-a", "version": "0.4.0", "app": "payments-api", "env": "prod",
                                 "instances": 2, "dropped": dropped})
        assert resp.status_code == 200
    with RunRepository() as repo:
        row = repo.connection.execute("SELECT app, env, instances, dropped_total FROM runtime_sensors").fetchone()
    assert tuple(row) == ("payments-api", "prod", 2, 7)
    bad = client.post("/api/runtime/v1/heartbeat", params={"project": PROJECT}, headers=_auth(store["key"]),
                      json={"dropped": 1})
    assert bad.status_code == 422


def test_evidence_endpoint_reads_runtime_state_per_finding(client, store):
    client.post("/api/runtime/v1/events", params={"project": PROJECT}, content=_ndjson(SESSION, HIT),
                headers=_auth(store["key"]))
    resp = client.get("/api/runtime/v1/evidence", params={"project": PROJECT}, headers=_auth(store["key"]))
    assert resp.status_code == 200
    [finding] = resp.json()["findings"]
    assert finding["runtime_state"] == "reached" and finding["conflict"] is True
    assert finding["routes"] == [{"route": "POST /upload", "auth": "anonymous", "count": 7}]


# ---------- sensor-side config ----------


def test_sensor_reads_key_file_and_server(tmp_path):
    key_file = tmp_path / "api-key"
    key_file.write_text("sfk_secret\n", encoding="utf-8")
    config = load_sensor_config({"SECFOO_API_KEY_FILE": str(key_file), "SECFOO_SERVER": "https://secfoo.internal",
                                 "SECFOO_PROJECT": PROJECT, "SECFOO_APP": "payments-api", "SECFOO_ENV": "prod"})
    assert config.api_key == "sfk_secret" and config.server == "https://secfoo.internal"
    assert config.url("events") == "https://secfoo.internal/api/runtime/v1/events"
    assert "sfk_secret" not in repr(config)


def test_sensor_server_defaults_to_cloud_login(monkeypatch):
    from secfoo.cloud import CloudConfig

    monkeypatch.setattr("secfoo.cloud.load_cloud_config", lambda: CloudConfig(api_key="x", portal_url="https://app.secfoo.com"))
    config = load_sensor_config({"SECFOO_API_KEY": "sfk_k", "SECFOO_PROJECT": PROJECT})
    assert config.server == "https://app.secfoo.com"


@pytest.mark.parametrize("environ, message", [
    ({"SECFOO_SERVER": "https://s", "SECFOO_PROJECT": PROJECT}, "no API key"),
    ({"SECFOO_API_KEY": "k", "SECFOO_SERVER": "https://s"}, "no project"),
    ({"SECFOO_API_KEY": "k", "SECFOO_SERVER": "http://secfoo.example.com", "SECFOO_PROJECT": PROJECT}, "https://"),
    ({"SECFOO_API_KEY_FILE": "/does/not/exist", "SECFOO_SERVER": "https://s", "SECFOO_PROJECT": PROJECT}, "can't read"),
])
def test_sensor_refuses_to_start_without_explicit_config(environ, message, monkeypatch):
    monkeypatch.setattr("secfoo.cloud.load_cloud_config", lambda: None)
    with pytest.raises(SensorConfigError, match=message):
        load_sensor_config(environ)


# ---------- CLI ----------


def test_serve_key_create_list_revoke(store):
    runner = CliRunner()
    created = runner.invoke(cli_app, ["serve", "key", "create", "--name", "ci", "--project", "payments-api",
                                      "--runtime-only"])
    assert created.exit_code == 0, created.output
    key = created.stdout.strip().splitlines()[-1]
    assert key.startswith("sfk_")
    listed = runner.invoke(cli_app, ["serve", "key", "list"], env={"COLUMNS": "200"})
    assert "ci" in listed.output and key not in listed.output
    with RunRepository() as repo:
        record = next(k for k in keys.list_keys(repo.connection) if k.name == "ci")
    assert (record.scope, record.project_id) == ("runtime", store["project_id"])
    assert runner.invoke(cli_app, ["serve", "key", "revoke", str(record.id)]).exit_code == 0
    assert runner.invoke(cli_app, ["serve", "key", "revoke", str(record.id)]).exit_code == 1
