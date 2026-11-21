"""Runtime ingest API audit (#118): every route needs a key, keys compare in
constant time, and --allow-insecure-runtime only lifts the TLS check."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secfoo.runtime import api as runtime_api
from secfoo.runtime import keys
from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app

PROJECT = "https://github.com/acme/payments-api"


@pytest.fixture
def key(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    runtime_api.rate_limiter.reset()
    with RunRepository() as repo:
        repo.upsert_project(PROJECT, "payments-api", "github")
        plaintext, _ = keys.create_key(repo.connection, name="k")
    return plaintext


def _runtime_routes():
    for route in runtime_api.router.routes:
        for method in sorted(route.methods - {"HEAD"}):
            yield method, route.path


ROUTES = list(_runtime_routes())


def test_the_audit_covers_every_runtime_route():
    """A new runtime route shows up here, and so in the tests below."""
    assert {path.rsplit("/", 1)[-1] for _m, path in ROUTES} == {"watchlist", "events", "heartbeat", "evidence"}


@pytest.mark.parametrize(("method", "path"), ROUTES)
@pytest.mark.parametrize("authorization", [
    None, "", "Bearer", "Bearer ", "Basic Zm9vOmJhcg==", "Bearer sfk_wrong", "Bearer not-a-key",
    "Bearer sfk_" + "A" * 43,
])
def test_every_runtime_route_refuses_a_request_without_a_valid_key(key, method, path, authorization):
    client = TestClient(create_app())
    headers = {} if authorization is None else {"Authorization": authorization}
    resp = client.request(method, path, params={"project": PROJECT}, headers=headers, content=b"")
    assert resp.status_code == 401, resp.text
    assert key not in resp.text


@pytest.mark.parametrize(("method", "path"), [r for r in ROUTES if r[0] == "POST"])
def test_a_cross_site_page_cannot_write_runtime_data(key, method, path):
    """/api/runtime/ is exempt from the Origin check; what protects it is
    that a page on another site cannot attach the Authorization header
    without a CORS preflight, which the app never grants."""
    client = TestClient(create_app())
    resp = client.request(method, path, params={"project": PROJECT}, content=b'{"type":"session","id":"x"}\n',
                          headers={"Origin": "https://evil.example", "Content-Type": "text/plain"})
    assert resp.status_code == 401
    preflight = client.options(path, headers={"Origin": "https://evil.example",
                                              "Access-Control-Request-Method": "POST",
                                              "Access-Control-Request-Headers": "authorization"})
    assert "access-control-allow-origin" not in preflight.headers
    with RunRepository() as repo:
        assert repo.connection.execute("SELECT COUNT(*) FROM runtime_sessions").fetchone()[0] == 0


def test_a_valid_key_still_works(key):
    client = TestClient(create_app())
    resp = client.get("/api/runtime/v1/watchlist", params={"project": PROJECT},
                      headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 200


def test_verify_key_compares_the_stored_hash_in_constant_time(key, monkeypatch):
    calls = []
    real = keys.hmac.compare_digest
    monkeypatch.setattr(keys.hmac, "compare_digest", lambda a, b: calls.append((a, b)) or real(a, b))
    with RunRepository() as repo:
        assert keys.verify_key(repo.connection, key) is not None
    assert calls == [(keys.hash_key(key), keys.hash_key(key))]


@pytest.mark.parametrize("bind", ["127.0.0.1", "localhost", "LOCALHOST", "localhost.", "::1", "[::1]"])
def test_loopback_binds_need_no_tls(key, bind):
    client = TestClient(create_app(bind_host=bind), base_url="http://127.0.0.1")
    resp = client.get("/api/runtime/v1/watchlist", params={"project": PROJECT},
                      headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize("allow_insecure", [False, True])
def test_allow_insecure_runtime_lifts_only_the_tls_check(key, allow_insecure):
    """On a non-loopback bind a key over plain HTTP is refused unless the
    operator opted in. Opting in changes nothing else: a bad key is still
    a 401 and the Host check still applies."""
    app = create_app(bind_host="10.0.0.5", allow_insecure_runtime=allow_insecure)
    client = TestClient(app, base_url="http://10.0.0.5:8787")
    good = client.get("/api/runtime/v1/watchlist", params={"project": PROJECT},
                      headers={"Authorization": f"Bearer {key}"})
    assert good.status_code == (200 if allow_insecure else 403)
    bad = client.get("/api/runtime/v1/watchlist", params={"project": PROJECT},
                     headers={"Authorization": "Bearer sfk_wrong"})
    assert bad.status_code == (401 if allow_insecure else 403)
    rebound = client.get("/api/runtime/v1/watchlist", params={"project": PROJECT},
                         headers={"Authorization": f"Bearer {key}", "Host": "rebind.evil.example"})
    assert rebound.status_code == 400
