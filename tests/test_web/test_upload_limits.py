"""Attachment upload limits and type checks (#118)."""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from secfoo import docext
from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.config.ATTACHMENTS_DIR", tmp_path / "attachments")
    client = TestClient(create_app())
    client.attachments = tmp_path / "attachments"
    return client


@pytest.fixture
def assessment_id():
    with RunRepository() as repo:
        project_id = repo.upsert_project("p", "p", "local")
        return repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")


def _attachments(assessment_id):
    with RunRepository() as repo:
        return [a.original_name for a in repo.list_attachments(assessment_id)]


def _docx(text="hello") -> bytes:
    import docx

    document = docx.Document()
    document.add_paragraph(text)
    buf = io.BytesIO()
    document.save(buf)
    return buf.getvalue()


def _upload(client, assessment_id, name, data, **kwargs):
    return client.post(f"/assessments/{assessment_id}/attachments", files={"file": (name, data)},
                       follow_redirects=False, **kwargs)


# ---------- size ----------

@pytest.mark.parametrize("name", ["notes.txt", "sbom.cdx.json", "report.md", "big.pdf"])
def test_every_kind_of_attachment_is_size_capped(client, assessment_id, monkeypatch, name):
    """Before #118 only PDF/DOCX/PPTX were capped, and only after the whole
    file had been written to disk."""
    monkeypatch.setattr("secfoo.docext.MAX_UPLOAD_BYTES", 1000)
    monkeypatch.setattr("secfoo.web.security.MULTIPART_OVERHEAD_BYTES", 10_000)
    resp = _upload(client, assessment_id, name, b"%PDF-1.4\n" + b"x" * 2000)
    assert resp.status_code == 413
    assert _attachments(assessment_id) == []
    assert not any(client.attachments.rglob(name))


def test_a_request_declaring_too_large_a_body_is_refused_before_it_is_read(client, assessment_id, monkeypatch):
    monkeypatch.setattr("secfoo.docext.MAX_UPLOAD_BYTES", 1000)
    resp = client.post(f"/assessments/{assessment_id}/attachments", content=b"x" * 10,
                       headers={"Content-Type": "multipart/form-data; boundary=b", "Content-Length": str(10**9)})
    assert resp.status_code == 413
    assert "max" in resp.text


@pytest.mark.parametrize("length", ["abc", "-1", "1" * 40])
def test_a_malformed_content_length_is_refused(assessment_id, length):
    from secfoo.web.security import check_request

    refused = check_request("POST", f"/assessments/{assessment_id}/attachments",
                            {"host": "127.0.0.1:8787", "content-length": length}, None)
    assert refused is not None and refused.status_code == 413


def test_a_chunked_upload_without_a_length_is_refused(assessment_id):
    from secfoo.web.security import check_request

    refused = check_request("POST", f"/assessments/{assessment_id}/attachments", {"host": "127.0.0.1:8787"}, None)
    assert refused is not None and refused.status_code == 411


def test_upload_at_the_limit_is_accepted(client, assessment_id, monkeypatch):
    monkeypatch.setattr("secfoo.docext.MAX_UPLOAD_BYTES", 1000)
    assert _upload(client, assessment_id, "notes.txt", b"x" * 1000).status_code == 303
    assert _attachments(assessment_id) == ["notes.txt"]


def test_other_routes_need_no_content_length(client):
    """Only the upload route is size-gated; a form POST elsewhere is unaffected."""
    from secfoo.web.security import check_request

    assert check_request("POST", "/assessments", {"host": "127.0.0.1:8787"}, None) is None


# ---------- type ----------

@pytest.mark.parametrize(("name", "data"), [
    ("soc2.pdf", b"MZ\x90\x00 this is an executable"),
    ("soc2.pdf", b"<html><script>alert(1)</script></html>"),
    ("soc2.docx", b"%PDF-1.4\nnot a docx"),
    ("deck.pptx", b"plain text"),
])
def test_vendor_document_whose_content_does_not_match_its_extension_is_refused(client, assessment_id, name, data):
    resp = _upload(client, assessment_id, name, data)
    assert resp.status_code == 415
    assert _attachments(assessment_id) == []
    assert not any(client.attachments.rglob(name))


def test_docx_renamed_to_pptx_is_refused(client, assessment_id):
    assert _upload(client, assessment_id, "deck.pptx", _docx()).status_code == 415


def test_real_documents_are_accepted(client, assessment_id):
    assert _upload(client, assessment_id, "soc2.docx", _docx("SOC 2")).status_code == 303
    assert _upload(client, assessment_id, "cert.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n").status_code == 303
    assert sorted(_attachments(assessment_id)) == ["cert.pdf", "soc2.docx"]


def test_pdf_header_may_follow_leading_junk(tmp_path):
    path = tmp_path / "x.pdf"
    path.write_bytes(b"\xef\xbb\xbf\r\n" + b"%PDF-1.4\n")
    assert docext.content_matches_extension(path)


def test_other_extensions_are_not_content_checked(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_bytes(b"\x00\x01anything")
    assert docext.content_matches_extension(path)


# ---------- archive bounds (zip bombs) ----------

def _bomb(tmp_path, *, members=1, member_bytes=0, suffix=".docx"):
    path = tmp_path / f"bomb{suffix}"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml" if suffix == ".docx" else "ppt/presentation.xml", "<x/>")
        for i in range(members):
            archive.writestr(f"word/media/{i}.bin", b"\0" * member_bytes)
    return path


@pytest.mark.parametrize("suffix", [".docx", ".pptx"])
def test_archive_expanding_past_the_bound_is_not_parsed(tmp_path, monkeypatch, suffix):
    monkeypatch.setattr("secfoo.docext.MAX_EXPANDED_BYTES", 1_000_000)
    path = _bomb(tmp_path, member_bytes=2_000_000, suffix=suffix)
    assert path.stat().st_size < 10_000  # small on disk, as a bomb is
    with pytest.raises(docext.UnsafeArchiveError):
        docext.check_archive_bounds(path)
    assert docext.extract_text(path) == ""


def test_archive_with_too_many_members_is_not_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.docext.MAX_ARCHIVE_MEMBERS", 50)
    path = _bomb(tmp_path, members=60)
    with pytest.raises(docext.UnsafeArchiveError):
        docext.check_archive_bounds(path)
    assert docext.extract_text(path) == ""


def test_a_real_docx_is_within_the_bounds(tmp_path):
    path = tmp_path / "real.docx"
    path.write_bytes(_docx("Vendor SOC 2 excerpt"))
    docext.check_archive_bounds(path)
    assert "Vendor SOC 2 excerpt" in docext.extract_text(path)


def test_an_unsupported_zip_version_is_refused_not_a_server_error(client, assessment_id):
    """Found by fuzz/fuzz_docext.py: zipfile raises NotImplementedError,
    not BadZipFile, for a version it cannot read."""
    from pathlib import Path

    corpus = Path(__file__).parents[2] / "fuzz" / "corpus" / "docext" / "crash-zip-unsupported-version.docx.bin"
    resp = _upload(client, assessment_id, "vendor.docx", corpus.read_bytes()[1:])
    assert resp.status_code == 415
