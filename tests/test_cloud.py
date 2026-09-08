from __future__ import annotations

import json
import urllib.error

import pytest

from secfoo import cloud
from secfoo.storage.repository import RunRepository


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def fake_urlopen(monkeypatch):
    """Configures the next `urllib.request.urlopen` call inside
    secfoo.cloud to either return a fake JSON response or raise, and
    records the Request object it was called with so tests can assert on
    the URL/headers/body actually sent.
    """
    calls = []

    def _install(*, response: dict | None = None, raises: Exception | None = None):
        def _fake_urlopen(request, timeout=None):
            calls.append(request)
            if raises is not None:
                raise raises
            return _FakeResponse(response or {})

        monkeypatch.setattr("secfoo.cloud.urllib.request.urlopen", _fake_urlopen)
        return calls

    return _install


# ---------------------------------------------------------------------------
# cloud.toml load/save
# ---------------------------------------------------------------------------


def test_load_cloud_config_returns_none_when_absent(tmp_path):
    assert cloud.load_cloud_config(tmp_path / "cloud.toml") is None


def test_save_and_load_cloud_config_roundtrip(tmp_path):
    path = tmp_path / "cloud.toml"
    config = cloud.CloudConfig(api_key="sfc_ingest_abc123", portal_url="https://portal.example.com")
    cloud.save_cloud_config(config, path)

    loaded = cloud.load_cloud_config(path)
    assert loaded == config


def test_save_cloud_config_sets_restrictive_permissions(tmp_path):
    path = tmp_path / "cloud.toml"
    cloud.save_cloud_config(cloud.CloudConfig(api_key="sfc_ingest_abc123"), path)
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


def test_load_cloud_config_missing_api_key_raises(tmp_path):
    path = tmp_path / "cloud.toml"
    path.write_text('portal_url = "https://portal.example.com"\n')
    with pytest.raises(cloud.CloudError):
        cloud.load_cloud_config(path)


def test_delete_cloud_config_is_safe_when_absent(tmp_path):
    cloud.delete_cloud_config(tmp_path / "cloud.toml")  # must not raise


def test_delete_cloud_config_removes_file(tmp_path):
    path = tmp_path / "cloud.toml"
    cloud.save_cloud_config(cloud.CloudConfig(api_key="k"), path)
    cloud.delete_cloud_config(path)
    assert not path.exists()


def test_save_cloud_config_rejects_newline_in_value(tmp_path):
    with pytest.raises(cloud.CloudError):
        cloud.save_cloud_config(cloud.CloudConfig(api_key="bad\nkey"), tmp_path / "cloud.toml")


# ---------------------------------------------------------------------------
# whoami / push_run -- network layer
# ---------------------------------------------------------------------------


def test_whoami_returns_parsed_response(fake_urlopen):
    fake_urlopen(response={"tenant_slug": "acme", "scope": "ingest"})
    config = cloud.CloudConfig(api_key="k", portal_url="https://portal.example.com")
    result = cloud.whoami(config)
    assert result == {"tenant_slug": "acme", "scope": "ingest"}


def test_whoami_sends_bearer_authorization_header(fake_urlopen):
    calls = fake_urlopen(response={"tenant_slug": "acme", "scope": "ingest"})
    config = cloud.CloudConfig(api_key="sfc_ingest_xyz", portal_url="https://portal.example.com")
    cloud.whoami(config)
    assert calls[0].get_header("Authorization") == "Bearer sfc_ingest_xyz"
    assert calls[0].full_url == "https://portal.example.com/api/v1/whoami"


def test_whoami_wraps_http_error(fake_urlopen):
    fake_urlopen(raises=urllib.error.HTTPError("url", 401, "Unauthorized", {}, None))
    config = cloud.CloudConfig(api_key="bad-key")
    with pytest.raises(cloud.CloudError):
        cloud.whoami(config)


def test_whoami_wraps_url_error_on_unreachable_portal(fake_urlopen):
    fake_urlopen(raises=urllib.error.URLError("Connection refused"))
    config = cloud.CloudConfig(api_key="k", portal_url="https://unreachable.example.com")
    with pytest.raises(cloud.CloudError):
        cloud.whoami(config)


def test_push_run_posts_expected_payload_shape(fake_urlopen):
    calls = fake_urlopen(response={"server_run_id": "u1", "status": "recorded"})
    config = cloud.CloudConfig(api_key="k", portal_url="https://portal.example.com")

    from secfoo.storage.models import RunRecord

    run = RunRecord(
        id=1, run_uuid="u1", project_id=1, skill_id="sast", skill_name="SAST", agent_id="claude",
        confluence_urls=[], status="success", exit_code=0, started_at="t1", finished_at="t2",
        duration_seconds=1.0, report_path=None, prompt_path=None, stderr_excerpt=None,
        project_display_name="acme/app",
    )

    cloud.push_run(
        config, run=run, project_identifier="https://github.com/acme/app",
        project_kind="github", report_markdown="# Report\n",
    )

    assert len(calls) == 1
    request = calls[0]
    assert request.full_url == "https://portal.example.com/api/v1/runs"
    assert request.get_header("Authorization") == "Bearer k"
    body = json.loads(request.data.decode("utf-8"))
    assert body["client_run_uuid"] == "u1"
    assert body["project"]["identifier"] == "https://github.com/acme/app"
    assert body["project"]["kind"] == "github"
    assert body["run"]["skill_id"] == "sast"
    assert body["report_markdown"] == "# Report\n"


def test_push_run_omits_assessment_when_not_given(fake_urlopen):
    calls = fake_urlopen(response={"server_run_id": "u1", "status": "recorded"})
    config = cloud.CloudConfig(api_key="k", portal_url="https://portal.example.com")
    from secfoo.storage.models import RunRecord

    run = RunRecord(
        id=1, run_uuid="u1", project_id=1, skill_id="sast", skill_name="SAST", agent_id="claude",
        confluence_urls=[], status="success", exit_code=0, started_at="t1", finished_at="t2",
        duration_seconds=1.0, report_path=None, prompt_path=None, stderr_excerpt=None,
    )
    cloud.push_run(config, run=run, project_identifier="id", project_kind="local", report_markdown="")
    body = json.loads(calls[0].data.decode("utf-8"))
    assert "assessment" not in body


def test_push_run_includes_assessment_when_given(fake_urlopen):
    """This is the payload that makes a synced run land in the portal's
    Assessments register instead of only ever showing up as a bare run
    under its Activity page -- see ingest.py's find-or-create handling.
    """
    calls = fake_urlopen(response={"server_run_id": "u1", "status": "recorded"})
    config = cloud.CloudConfig(api_key="k", portal_url="https://portal.example.com")
    from secfoo.storage.models import AssessmentRecord, RunRecord

    run = RunRecord(
        id=1, run_uuid="u1", project_id=1, skill_id="sast", skill_name="SAST", agent_id="claude",
        confluence_urls=[], status="success", exit_code=0, started_at="t1", finished_at="t2",
        duration_seconds=1.0, report_path=None, prompt_path=None, stderr_excerpt=None,
    )
    assessment = AssessmentRecord(
        id=1, project_id=1, assessment_type="internal", status="in_progress",
        application_id="APP-42", sar_number=None, reviewer=None, review_date=None, notes=None,
        created_at="t0", updated_at="t0", assessment_uuid="uuid-1",
    )
    cloud.push_run(
        config, run=run, project_identifier="id", project_kind="local", report_markdown="",
        assessment=assessment,
    )
    body = json.loads(calls[0].data.decode("utf-8"))
    assert body["assessment"] == {
        "assessment_uuid": "uuid-1",
        "assessment_type": "internal",
        "status": "in_progress",
        "application_id": "APP-42",
        "sar_number": None,
        "reviewer": None,
        "review_date": None,
        "notes": None,
    }


def test_push_run_raises_cloud_error_on_failure(fake_urlopen):
    fake_urlopen(raises=urllib.error.URLError("Connection refused"))
    config = cloud.CloudConfig(api_key="k", portal_url="https://unreachable.example.com")
    from secfoo.storage.models import RunRecord

    run = RunRecord(
        id=1, run_uuid="u1", project_id=1, skill_id="sast", skill_name="SAST", agent_id="claude",
        confluence_urls=[], status="success", exit_code=0, started_at="t1", finished_at="t2",
        duration_seconds=1.0, report_path=None, prompt_path=None, stderr_excerpt=None,
    )
    with pytest.raises(cloud.CloudError):
        cloud.push_run(config, run=run, project_identifier="id", project_kind="local", report_markdown="")


# ---------------------------------------------------------------------------
# sync_run -- orchestration against a real local RunRepository
# ---------------------------------------------------------------------------


def test_sync_run_marks_run_synced_on_success(tmp_path, fake_urlopen):
    fake_urlopen(response={"server_run_id": "u1", "status": "recorded"})
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
    )
    report_path = tmp_path / "report.md"
    report_path.write_text("# Report\n")
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )

    config = cloud.CloudConfig(api_key="k", portal_url="https://portal.example.com")
    cloud.sync_run(repo, run_uuid, config)

    assert repo.get_run(run_uuid).cloud_synced_at is not None
    repo.close()


def test_sync_run_includes_assessment_data_when_run_has_one(tmp_path, fake_urlopen):
    calls = fake_urlopen(response={"server_run_id": "u1", "status": "recorded"})
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    assessment_id = repo.create_assessment(
        project_id=project_id, assessment_type="internal", application_id="APP-42"
    )
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
        assessment_id=assessment_id,
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )

    config = cloud.CloudConfig(api_key="k", portal_url="https://portal.example.com")
    cloud.sync_run(repo, run_uuid, config)

    body = json.loads(calls[0].data.decode("utf-8"))
    expected_uuid = repo.get_assessment(assessment_id).assessment_uuid
    assert body["assessment"]["assessment_uuid"] == expected_uuid
    assert body["assessment"]["application_id"] == "APP-42"
    repo.close()


def test_sync_run_raises_for_unknown_run(tmp_path, fake_urlopen):
    fake_urlopen(response={})
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    config = cloud.CloudConfig(api_key="k")
    with pytest.raises(ValueError):
        cloud.sync_run(repo, "not-a-real-uuid", config)
    repo.close()


def test_sync_run_does_not_mark_synced_on_push_failure(tmp_path, fake_urlopen):
    fake_urlopen(raises=urllib.error.URLError("Connection refused"))
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )

    config = cloud.CloudConfig(api_key="k", portal_url="https://unreachable.example.com")
    with pytest.raises(cloud.CloudError):
        cloud.sync_run(repo, run_uuid, config)

    assert repo.get_run(run_uuid).cloud_synced_at is None
    repo.close()
