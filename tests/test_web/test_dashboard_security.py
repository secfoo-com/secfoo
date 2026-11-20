"""Cross-site writes, DNS rebinding and security headers on the local dashboard (#118)."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web import security
from secfoo.web.app import create_app

DASHBOARD = "http://127.0.0.1:8787"
EVIL = "https://evil.example"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.config.ATTACHMENTS_DIR", tmp_path / "attachments")
    monkeypatch.setattr("secfoo.web.security.EXTRA_ALLOWED_HOSTS", set())  # behave like `secfoo serve`
    return create_app(bind_host="127.0.0.1")


@pytest.fixture
def client(app, tmp_path):
    client = TestClient(app, base_url=DASHBOARD, follow_redirects=False)
    client.target = tmp_path / "project"
    client.target.mkdir()
    return client


def _assessment_count():
    with RunRepository() as repo:
        return len(repo.list_assessments())


def _create(client, **headers):
    return client.post("/assessments", data={"project_name": "p", "project": str(client.target),
                                             "assessment_type": "internal"}, headers=headers)


def _routes(routes):
    """Flatten FastAPI's included routers into (method, path) pairs."""
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _routes(inner.routes)
        else:
            for method in getattr(route, "methods", None) or ():
                yield method, route.path


# ---------- cross-site writes ----------

@pytest.mark.parametrize("headers", [
    {"Origin": EVIL},
    {"Origin": "null"},  # sandboxed iframe, data: URL, file://
    {"Origin": "http://127.0.0.1:9999"},  # another local server: same site, different origin
    {"Origin": "http://localhost:8787"},  # same port, but not the host this page was loaded from
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Referer": EVIL + "/attack.html"},  # no Origin/Sec-Fetch-Site: an old browser
])
def test_cross_site_form_post_is_refused_and_has_no_effect(client, headers):
    resp = _create(client, **headers)
    assert resp.status_code == 403
    assert _assessment_count() == 0


def test_same_origin_browser_post_is_accepted(client):
    resp = _create(client, Origin=DASHBOARD, **{"Sec-Fetch-Site": "same-origin", "Referer": DASHBOARD + "/assessments/new"})
    assert resp.status_code == 303
    assert _assessment_count() == 1


def test_non_browser_clients_without_origin_headers_still_work(client):
    """curl, scripts and the CLI send neither Origin nor Sec-Fetch-Site."""
    assert _create(client).status_code == 303


def test_every_state_changing_dashboard_route_is_covered(app, client):
    """Any POST/PUT/PATCH/DELETE route added later is protected too."""
    unsafe = [(method, path) for method, path in _routes(app.routes)
              if method not in security.SAFE_METHODS and not path.startswith(security.MACHINE_API_PREFIX)]
    assert len(unsafe) >= 6
    for method, path in unsafe:
        concrete = re.sub(r"\{[^}]+\}", "1", path)
        resp = client.request(method, concrete, headers={"Origin": EVIL})
        assert resp.status_code == 403, (method, path)


def test_runtime_api_is_exempt_from_the_origin_check_but_still_needs_its_key(client):
    resp = client.post("/api/runtime/v1/events", params={"project": "p"}, content="{}\n", headers={"Origin": EVIL})
    assert resp.status_code == 401


def test_reads_are_not_blocked_by_origin(client):
    assert client.get("/assessments", headers={"Origin": EVIL, "Sec-Fetch-Site": "cross-site"}).status_code == 200


# ---------- DNS rebinding ----------

@pytest.mark.parametrize("host", ["rebind.evil.example", "rebind.evil.example:8787", "127.0.0.1.evil.example",
                                  "localhost.evil.example", "", "8787"])
def test_foreign_host_header_is_refused(client, host):
    resp = client.get("/", headers={"Host": host})
    assert resp.status_code == 400


@pytest.mark.parametrize("host", ["127.0.0.1:8787", "localhost:8787", "LOCALHOST:8787", "localhost.:8787",
                                  "[::1]:8787", "127.0.0.1"])
def test_loopback_host_headers_are_served(client, host):
    assert client.get("/", headers={"Host": host}).status_code == 200


def test_the_bind_host_is_allowed_and_a_wildcard_bind_allows_any_host(monkeypatch, tmp_path):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.web.security.EXTRA_ALLOWED_HOSTS", set())
    lan = TestClient(create_app(bind_host="10.0.0.5"), base_url="http://10.0.0.5:8787")
    assert lan.get("/").status_code == 200
    assert lan.get("/", headers={"Host": "rebind.evil.example"}).status_code == 400
    anyhost = TestClient(create_app(bind_host="0.0.0.0"), base_url="http://secfoo.internal:8787")
    assert anyhost.get("/").status_code == 200
    # ...but cross-site writes are still refused on a wildcard bind.
    assert anyhost.post("/assessments", data={}, headers={"Origin": EVIL}).status_code == 403


def test_allow_host_adds_a_forwarded_name(monkeypatch, tmp_path):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.web.security.EXTRA_ALLOWED_HOSTS", set())
    app = create_app(bind_host="127.0.0.1", allow_hosts=["Dash.Example.Dev"])
    forwarded = TestClient(app, base_url="https://dash.example.dev")
    assert forwarded.get("/").status_code == 200
    refused = forwarded.get("/", headers={"Host": "other.example.dev"})
    assert refused.status_code == 400 and "--allow-host" in refused.text


# ---------- headers ----------

def test_security_headers_on_pages_static_files_and_rejections(client):
    for resp in (client.get("/"), client.get("/static/js/theme.js"), client.get("/", headers={"Host": "evil"})):
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        csp = resp.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "'unsafe-eval'" not in csp
        assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]


def test_serve_warns_when_bound_beyond_loopback():
    assert security.is_loopback("127.0.0.1") and security.is_loopback("[::1]") and security.is_loopback("localhost")
    assert not security.is_loopback("0.0.0.0") and not security.is_loopback("10.0.0.5")
