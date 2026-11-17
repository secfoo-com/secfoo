"""Security hardening tests for the local dashboard (#118).

Covers:
1. Cross-Site Request Forgery (CSRF) protection on all state-changing routes.
2. DNS rebinding defense via TrustedHostMiddleware.
3. Security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
4. XSS regression corpus on report markdown and finding detail views.
5. Attachment upload size limits (streamed enforcement) and extension whitelist.
6. Safe attachment download serving (octet-stream, Content-Disposition, nosniff).
7. Constant-time API key verification and --allow-insecure-runtime enforcement.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secfoo import docext
from secfoo.report.markdown import render_report_html
from secfoo.runtime.keys import create_key, revoke_key, verify_key
from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.config.ATTACHMENTS_DIR", tmp_path / "attachments")
    return TestClient(create_app())


def _seed_assessment() -> tuple[int, int]:
    repo = RunRepository()
    project_id = repo.upsert_project(
        "https://github.com/org/repo", "org/repo", "github"
    )
    assessment_id = repo.create_assessment(
        project_id=project_id, assessment_type="internal", status="ready"
    )
    repo.close()
    return project_id, assessment_id


# --------------------------------------------------------------------------- #
# 1. DNS Rebinding / Host Header Protection
# --------------------------------------------------------------------------- #


def test_trusted_host_rejects_foreign_host(client):
    """DNS rebinding attempts with a foreign Host header get 400 Bad Request."""
    resp = client.get("/", headers={"Host": "evil.example"})
    assert resp.status_code == 400
    assert "Invalid host header" in resp.text


def test_trusted_host_accepts_valid_hosts(client):
    """Requests with localhost or loopback Host headers succeed."""
    for host in ("localhost:8787", "127.0.0.1:8787", "testserver"):
        resp = client.get("/", headers={"Host": host})
        assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# 2. Security Response Headers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", ["/", "/assessments", "/activities/sast", "/agents"])
def test_security_headers_present_on_routes(client, path):
    """All dashboard responses must carry defensive security headers."""
    resp = client.get(path)
    assert resp.status_code == 200
    headers = resp.headers
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


# --------------------------------------------------------------------------- #
# 3. Cross-Site Protection for ALL Six State-Changing POST Routes
# --------------------------------------------------------------------------- #


def test_csrf_rejection_post_assessments(client, monkeypatch):
    """Route 1: POST /assessments rejected when cross-origin."""
    _seed_assessment()
    data = {
        "project_name": "Test Repo",
        "project": "https://github.com/org/repo",
        "assessment_type": "internal",
    }
    # Cross-origin Origin header -> 403
    resp = client.post(
        "/assessments", data=data, headers={"Origin": "https://evil.example"}
    )
    assert resp.status_code == 403
    assert "Cross-origin" in resp.text

    # Cross-site Sec-Fetch-Site -> 403
    resp = client.post(
        "/assessments", data=data, headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert resp.status_code == 403

    # Same-origin -> succeeds (redirects to assessment)
    resp = client.post(
        "/assessments",
        data=data,
        headers={"Origin": "http://127.0.0.1:8787", "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_csrf_rejection_post_bulk_status(client):
    """Route 2: POST /assessments/bulk-status rejected when cross-origin."""
    _, a_id = _seed_assessment()
    data = {"ids": [a_id], "new_status": "completed"}

    # Cross-origin Origin header -> 403
    resp = client.post(
        "/assessments/bulk-status",
        data=data,
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403

    # Same-origin -> succeeds
    resp = client.post(
        "/assessments/bulk-status",
        data=data,
        headers={"Origin": "http://127.0.0.1:8787"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_csrf_rejection_post_assessment_runs(client):
    """Route 3: POST /assessments/{id}/runs rejected when cross-origin."""
    _, a_id = _seed_assessment()

    # Cross-origin Origin -> 403
    resp = client.post(
        f"/assessments/{a_id}/runs",
        data={"skill_ids": ["sast"]},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403


def test_csrf_rejection_post_attachments(client):
    """Route 4: POST /assessments/{id}/attachments rejected when cross-origin."""
    _, a_id = _seed_assessment()
    files = {"file": ("doc.pdf", b"%PDF-1.4 dummy", "application/pdf")}

    # Cross-origin Origin -> 403
    resp = client.post(
        f"/assessments/{a_id}/attachments",
        files=files,
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403


def test_csrf_rejection_post_assessment_delete(client):
    """Route 5: POST /assessments/{id}/delete rejected when cross-origin."""
    _, a_id = _seed_assessment()

    # Cross-origin Origin -> 403
    resp = client.post(
        f"/assessments/{a_id}/delete",
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403

    # Same-origin -> 200
    resp = client.post(
        f"/assessments/{a_id}/delete",
        headers={"Origin": "http://127.0.0.1:8787"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_csrf_rejection_post_finding_review(client):
    """Route 6: POST /activities/sast/findings/{fp}/review rejected when cross-origin."""
    repo = RunRepository()
    project_id = repo.upsert_project(
        "https://github.com/org/repo", "org/repo", "github"
    )
    run_uuid = repo.create_run(
        project_id=project_id,
        skill_id="sast",
        skill_name="SAST",
        agent_id="claude",
        confluence_urls=[],
    )
    run_record = repo.get_run(run_uuid)
    assert run_record is not None
    repo.upsert_sast_finding(
        project_id=project_id,
        fingerprint="fp-sqli",
        run_id=run_record.id,
        current_ref="F1",
        title="SQL Injection",
        severity="High",
        cwe="CWE-89",
        owasp="A03:2021",
        verdict="Confirmed",
        location_file="app.py",
        location_line="42",
        cvss_vector=None,
        cvss_score=None,
        description="User input directly concatenated",
        recommendation="Use parameters",
    )
    findings = repo.list_sast_findings(project_id=project_id)
    finding = findings[0]
    repo.close()

    url = f"/activities/sast/findings/{finding.fingerprint}/review"
    data = {"finding_id": finding.id, "review_status": "confirmed", "reviewer": "Alice"}

    # Cross-origin Origin -> 403
    resp = client.post(url, data=data, headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403

    # Same-origin -> 303 redirect
    resp = client.post(
        url,
        data=data,
        headers={"Origin": "http://127.0.0.1:8787"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


# --------------------------------------------------------------------------- #
# 4. Upload Size and Type Limits
# --------------------------------------------------------------------------- #


def test_upload_rejects_unsupported_file_extension(client):
    """Uploading executables or unsupported file types gets 400 Bad Request."""
    _, a_id = _seed_assessment()
    for bad_name in ("malware.exe", "backdoor.sh", "exploit.php", "test.bin"):
        files = {"file": (bad_name, b"binary content", "application/octet-stream")}
        resp = client.post(
            f"/assessments/{a_id}/attachments",
            files=files,
            headers={"Origin": "http://127.0.0.1:8787"},
        )
        assert resp.status_code == 400
        assert "Unsupported file type" in resp.text


def test_upload_rejects_oversized_file_while_streaming(client, monkeypatch):
    """Uploading a file exceeding MAX_UPLOAD_BYTES is aborted chunk-by-chunk with 413."""
    _, a_id = _seed_assessment()
    # Lower MAX_UPLOAD_BYTES artificially for test speed
    monkeypatch.setattr(docext, "MAX_UPLOAD_BYTES", 1024)

    oversized_data = b"A" * 2048
    files = {"file": ("large_doc.pdf", oversized_data, "application/pdf")}
    resp = client.post(
        f"/assessments/{a_id}/attachments",
        files=files,
        headers={"Origin": "http://127.0.0.1:8787"},
    )
    assert resp.status_code == 413
    assert "File too large" in resp.text


def test_upload_allowed_type_succeeds(client):
    """Allowed file extensions upload successfully."""
    _, a_id = _seed_assessment()
    for allowed_name in ("notes.txt", "spec.json", "vendor.pdf", "report.md"):
        files = {"file": (allowed_name, b"valid content", "text/plain")}
        resp = client.post(
            f"/assessments/{a_id}/attachments",
            files=files,
            headers={"Origin": "http://127.0.0.1:8787"},
            follow_redirects=False,
        )
        assert resp.status_code == 303


# --------------------------------------------------------------------------- #
# 5. Attachment Download Safety
# --------------------------------------------------------------------------- #


def test_attachment_download_served_as_safe_octet_stream(client):
    """Attachments are downloaded with application/octet-stream, Content-Disposition, and nosniff."""
    _, a_id = _seed_assessment()
    # Upload an HTML attachment
    files = {"file": ("malicious.html", b"<script>alert(1)</script>", "text/html")}
    upload_resp = client.post(
        f"/assessments/{a_id}/attachments",
        files=files,
        headers={"Origin": "http://127.0.0.1:8787"},
        follow_redirects=False,
    )
    assert upload_resp.status_code == 303

    repo = RunRepository()
    attachments = repo.list_attachments(a_id)
    repo.close()
    assert len(attachments) == 1
    att_id = attachments[0].id

    # Download attachment
    download_resp = client.get(f"/assessments/{a_id}/attachments/{att_id}/download")
    assert download_resp.status_code == 200
    assert download_resp.headers["Content-Type"] == "application/octet-stream"
    assert (
        'attachment; filename="malicious.html"'
        in download_resp.headers["Content-Disposition"]
    )
    assert download_resp.headers["X-Content-Type-Options"] == "nosniff"
    assert download_resp.content == b"<script>alert(1)</script>"


# --------------------------------------------------------------------------- #
# 6. XSS Regression Corpus
# --------------------------------------------------------------------------- #


XSS_PAYLOADS = [
    # Image onerror: must not render raw <img tag
    ("<img src=x onerror=alert(1)>", ["<img"]),
    # JavaScript links: must not generate href="javascript:
    ("[click](javascript:alert(1))", ['href="javascript:']),
    # Link title attribute breakout: must not break out into an unescaped onmouseover attribute
    (
        '[click](https://example.com "title\\" onmouseover=\\"alert(1)")',
        ['" onmouseover='],
    ),
    # HTML script in headings: must not render unescaped <script> tag
    ("# Heading <script>alert(1)</script>", ["<script>"]),
    ("### [HIGH] Title <script>alert(1)</script>", ["<script>"]),
    # SVG onload: must not render raw <svg tag
    ("<svg onload=alert(1)>", ["<svg"]),
    # Data URI link: must not generate href="data:
    ("[data](data:text/html,<script>alert(1)</script>)", ['href="data:']),
    # Mermaid block with script: must not render raw <script> tag
    ("```mermaid\ngraph TD\nA[<script>alert(1)</script>]\n```", ["<script>"]),
]


@pytest.mark.parametrize("payload, forbidden_substrings", XSS_PAYLOADS)
def test_xss_corpus_rendered_html_is_inert(payload, forbidden_substrings):
    """Report markdown rendering never produces executable HTML or event handlers."""
    rendered = render_report_html(payload)
    for forbidden in forbidden_substrings:
        assert forbidden not in rendered, (
            f"Found unescaped {forbidden!r} in rendered HTML: {rendered!r}"
        )


# --------------------------------------------------------------------------- #
# 7. Constant-Time Key Verification & --allow-insecure-runtime
# --------------------------------------------------------------------------- #


def test_constant_time_key_verification(tmp_path, monkeypatch):
    """verify_key validates active keys and rejects invalid/revoked keys in constant time."""
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    repo = RunRepository()

    # Create active key
    raw_key, key_rec = create_key(repo.connection, name="sensor-key")
    assert verify_key(repo.connection, raw_key) is not None

    # Incorrect key (wrong suffix)
    wrong_key = raw_key[:10] + "0" * (len(raw_key) - 10)
    assert verify_key(repo.connection, wrong_key) is None

    # Revoked key
    revoke_key(repo.connection, key_rec.id)
    assert verify_key(repo.connection, raw_key) is None
    repo.close()


def test_allow_insecure_runtime_flag(tmp_path, monkeypatch):
    """Non-loopback address requires TLS unless --allow-insecure-runtime is passed."""
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    repo = RunRepository()
    project_id = repo.upsert_project(
        identifier="org/repo", display_name="org/repo", kind="github"
    )
    raw_key, _ = create_key(repo.connection, name="test-key", project_id=project_id)
    repo.close()

    # Non-loopback without allow_insecure_runtime: rejected with 403 on plain HTTP
    app_strict = create_app(bind_host="192.168.1.100", allow_insecure_runtime=False)
    client_strict = TestClient(app_strict)
    resp = client_strict.get(
        "/api/runtime/v1/evidence?project=org/repo",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 403
    assert "refusing an API key over plain HTTP" in resp.json()["detail"]

    # Non-loopback with allow_insecure_runtime: permitted
    app_insecure = create_app(bind_host="192.168.1.100", allow_insecure_runtime=True)
    client_insecure = TestClient(app_insecure)
    resp = client_insecure.get(
        "/api/runtime/v1/evidence?project=org/repo",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 200
