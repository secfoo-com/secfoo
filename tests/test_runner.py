from __future__ import annotations

import threading
import time

from secfoo.agents.base import AgentAdapter, AgentResult
from secfoo.runner import execute_runs
from secfoo.storage.repository import RunRepository


class _SleepyAdapter(AgentAdapter):
    """Fake adapter standing in for a real agent CLI: sleeps briefly instead
    of shelling out, so tests can prove skills genuinely run concurrently
    rather than one after another.
    """

    name = "fake"
    binary = "fake-binary"
    default_timeout_seconds = 30

    def build_command(self, prompt, *, workdir):
        return ["fake-binary"]

    def is_available(self) -> bool:
        return True

    def run(self, prompt, *, workdir, timeout=None):
        time.sleep(0.15)
        return AgentResult(
            agent=self.name,
            exit_code=0,
            stdout="ok",
            stderr="",
            duration_seconds=0.15,
            timed_out=False,
            status="success",
            raw_report=f"# Report\n{prompt[:20]}",
        )


def _patch_runner(monkeypatch, tmp_path):
    monkeypatch.setattr("secfoo.runner.run_dir", lambda run_uuid: tmp_path / "reports" / run_uuid)
    monkeypatch.setattr("secfoo.runner.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _SleepyAdapter())


def test_execute_runs_runs_skills_concurrently(tmp_path, monkeypatch):
    """Proves real concurrency with a barrier rather than a wall-clock
    threshold -- a timing assert (e.g. "elapsed < 0.4s") flakes under
    ordinary system load with no code regression at all. If the 3 skills
    ran one after another instead, only one thread would ever reach
    barrier.wait() at a time and it would time out and raise, which still
    fails the test, just deterministically instead of by chance.
    """
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    barrier = threading.Barrier(3, timeout=5)

    class _BarrierAdapter(AgentAdapter):
        name = "fake"
        binary = "fake-binary"
        default_timeout_seconds = 30

        def build_command(self, prompt, *, workdir):
            return ["fake-binary"]

        def is_available(self) -> bool:
            return True

        def run(self, prompt, *, workdir, timeout=None):
            barrier.wait()
            return AgentResult(
                agent=self.name,
                exit_code=0,
                stdout="ok",
                stderr="",
                duration_seconds=0.0,
                timed_out=False,
                status="success",
                raw_report="# Report",
            )

    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _BarrierAdapter())

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review", "prompt-review", "deployment-readiness"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
    )
    repo.close()

    assert len(outcomes) == 3
    assert all(o.status == "success" for o in outcomes)


def test_execute_runs_attaches_to_an_explicit_project_id_instead_of_the_targets_own(tmp_path, monkeypatch):
    """Third-Party Risk Assessment's auto-trigger scans a synthetic temp
    directory of extracted vendor-document text, but the run must attach
    to the assessment's REAL, pre-existing project -- not a bogus new
    project derived from the temp directory's own path.
    """
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "vendor-docs-temp"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    real_project_id = repo.upsert_project("https://vendor.example/acme", "Acme Vendor", "github")
    projects_before = len(repo.list_projects())

    outcomes = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        project_id=real_project_id,
    )
    run_record = repo.get_run(outcomes[0].run_uuid)
    projects_after = len(repo.list_projects())
    repo.close()

    assert run_record.project_id == real_project_id
    # No new project row was created for the synthetic target directory.
    assert projects_after == projects_before


def test_execute_runs_auto_creates_an_assessment_when_none_is_given(tmp_path, monkeypatch):
    """`secfoo run` with no `--assessment` flag must still produce a real
    case file -- otherwise skills like responsible-ai-compliance silently
    never show up on their dashboard, and the run has no case-file context.
    """
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review", "prompt-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
    )
    run_records = [repo.get_run(o.run_uuid) for o in outcomes]
    repo.close()

    assessment_ids = {r.assessment_id for r in run_records}
    assert len(assessment_ids) == 1
    assert None not in assessment_ids


def test_execute_runs_does_not_create_an_assessment_when_one_is_given(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project("https://example/existing", "Existing Project", "github")
    existing_assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal")
    assessments_before = len(repo.list_assessments())

    outcomes = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        assessment_id=existing_assessment_id,
    )
    run_record = repo.get_run(outcomes[0].run_uuid)
    assessments_after = len(repo.list_assessments())
    repo.close()

    assert run_record.assessment_id == existing_assessment_id
    assert assessments_after == assessments_before


def test_execute_runs_applies_explicit_project_name_and_application_id(tmp_path, monkeypatch):
    """The CLI prompts an interactive user for these two fields precisely
    because the auto-derived project name and a blank application ID make
    an auto-created case file hard to find later -- both must actually
    land on the project/assessment, not just get accepted and dropped.
    """
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        project_display_name="Checkout Service",
        assessment_application_id="APP-42",
    )
    run_record = repo.get_run(outcomes[0].run_uuid)
    project = repo.get_project(run_record.project_id)
    assessment = repo.get_assessment(run_record.assessment_id)
    repo.close()

    assert project.display_name == "Checkout Service"
    assert assessment.application_id == "APP-42"


def test_execute_runs_reuses_the_assessment_for_a_repeat_application_id(tmp_path, monkeypatch):
    """A second `secfoo run` against the same target with the same
    --app-id must attach to the SAME assessment as the first, not mint a
    fresh one every time -- otherwise every rescan of one real system
    fragments into its own separate, mostly-empty case file.
    """
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    repo = RunRepository(db_path=tmp_path / "db.sqlite")

    first = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        assessment_application_id="APP-42",
    )
    second = execute_runs(
        skill_ids=["prompt-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        assessment_application_id="APP-42",
    )

    run1 = repo.get_run(first[0].run_uuid)
    run2 = repo.get_run(second[0].run_uuid)
    assessments_count = len(repo.list_assessments())
    repo.close()

    assert run1.assessment_id == run2.assessment_id
    assert assessments_count == 1


def test_execute_runs_does_not_reuse_an_application_id_from_a_different_project(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    target_a = tmp_path / "target-a"
    target_a.mkdir()
    target_b = tmp_path / "target-b"
    target_b.mkdir()
    repo = RunRepository(db_path=tmp_path / "db.sqlite")

    first = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_a),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        assessment_application_id="APP-42",
    )
    second = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_b),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        assessment_application_id="APP-42",
    )

    run1 = repo.get_run(first[0].run_uuid)
    run2 = repo.get_run(second[0].run_uuid)
    repo.close()

    assert run1.assessment_id != run2.assessment_id


def test_execute_runs_leaves_an_existing_projects_name_alone(tmp_path, monkeypatch):
    """project_display_name only applies when execute_runs() is the one
    creating the project (project_id left unset) -- it must never rename a
    project a caller already identified by id.
    """
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project("https://example/existing", "Existing Project", "github")

    execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        project_id=project_id,
        project_display_name="Should Not Apply",
    )
    project = repo.get_project(project_id)
    repo.close()

    assert project.display_name == "Existing Project"


def test_execute_runs_preserves_requested_skill_order_in_results(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    requested = ["deployment-readiness", "security-architecture-review", "prompt-review"]
    outcomes = execute_runs(
        skill_ids=requested,
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
    )
    repo.close()
    assert [o.skill_id for o in outcomes] == requested


def test_execute_runs_invokes_progress_callbacks(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    started_names: list[str] = []
    completed: list[tuple[str, str]] = []

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
        on_skill_start=lambda name: started_names.append(name),
        on_skill_complete=lambda name, status: completed.append((name, status)),
    )
    repo.close()

    assert started_names == ["Security Architecture Review"]
    assert completed == [("Security Architecture Review", "success")]


def test_execute_runs_persists_report_files(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
    )
    repo.close()

    outcome = outcomes[0]
    from pathlib import Path

    report_path = Path(outcome.report_path)
    assert report_path.exists()
    assert report_path.read_text().startswith("# Report")

    run_record = None
    repo2 = RunRepository(db_path=tmp_path / "db.sqlite")
    run_record = repo2.get_run(outcome.run_uuid)
    repo2.close()
    assert run_record is not None
    assert run_record.status == "success"


def test_execute_runs_strips_preamble_from_persisted_report(tmp_path, monkeypatch):
    class _ChattyAdapter(_SleepyAdapter):
        def run(self, prompt, *, workdir, timeout=None):
            result = super().run(prompt, workdir=workdir, timeout=timeout)
            result.raw_report = "Sounds good, here's the report:\n\n" + result.raw_report
            return result

    monkeypatch.setattr("secfoo.runner.run_dir", lambda run_uuid: tmp_path / "reports" / run_uuid)
    monkeypatch.setattr("secfoo.runner.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _ChattyAdapter())

    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
    )
    repo.close()

    from pathlib import Path

    report_text = Path(outcomes[0].report_path).read_text()
    assert report_text.startswith("# Report")
    assert "Sounds good" not in report_text


def test_execute_runs_threads_depth_into_the_rendered_prompt(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        depth="standard",
        repo=repo,
    )
    repo.close()

    prompt_path = (tmp_path / "reports" / outcomes[0].run_uuid / "prompt.md")
    assert "Scan depth: STANDARD" in prompt_path.read_text()


# ---------------------------------------------------------------------------
# Enterprise portal auto-push (secfoo cloud) -- best-effort, never fails a
# local run.
# ---------------------------------------------------------------------------


def test_execute_runs_pushes_to_portal_when_cloud_configured(tmp_path, monkeypatch):
    import json

    from secfoo import cloud

    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    cloud_config = cloud.CloudConfig(api_key="k", portal_url="https://portal.example.com")
    monkeypatch.setattr("secfoo.cloud.load_cloud_config", lambda: cloud_config)

    class _FakeResponse:
        def __init__(self, payload):
            self._body = json.dumps(payload).encode("utf-8")

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "secfoo.cloud.urllib.request.urlopen",
        lambda request, timeout=None: _FakeResponse({"server_run_id": "x", "status": "recorded"}),
    )

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
    )
    run_record = repo.get_run(outcomes[0].run_uuid)
    repo.close()

    assert run_record.cloud_synced_at is not None


def test_execute_runs_still_succeeds_when_portal_unreachable(tmp_path, monkeypatch):
    import urllib.error

    from secfoo import cloud

    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    cloud_config = cloud.CloudConfig(api_key="k", portal_url="https://unreachable.example.com")
    monkeypatch.setattr("secfoo.cloud.load_cloud_config", lambda: cloud_config)

    def _fake_urlopen(request, timeout=None):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr("secfoo.cloud.urllib.request.urlopen", _fake_urlopen)

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review"],
        target=str(target_dir),
        confluence_urls=[],
        agent_id="claude",
        repo=repo,
    )
    run_record = repo.get_run(outcomes[0].run_uuid)
    repo.close()

    # A portal outage must never fail the local run.
    assert outcomes[0].status == "success"
    assert run_record.status == "success"
    assert run_record.cloud_synced_at is None


# ---------------------------------------------------------------------------
# OSV.dev enrichment hook (sca-reachability only) -- best-effort, never
# fails a local run.
# ---------------------------------------------------------------------------

_SCA_REPORT = """\
# SCA Report — Reachability & Upgrade Triage

## 2. Dependency Inventory

| Package | Version | Direct/Transitive | Ecosystem | Source manifest |
|---------|---------|--------------------|-----------|------------------|
| aiohttp | 3.8.0 | Direct | Python | requirements.txt |

## 4. Risk Register

| ID | Package | Version | Issue | Severity | Reachability | Fixed in |
|----|---------|---------|-------|----------|---------------|----------|
| D1 | aiohttp | 3.8.0 | Invalid IPv6 URL DoS class issue | High | Reachable | 3.8.1 |
"""


class _ScaAdapter(AgentAdapter):
    """Fake adapter returning a real SCA-shaped report, so the runner's
    post-run OSV enrichment hook has an actual Risk Register row to act
    on -- _SleepyAdapter's generic report has no Dependency
    Inventory/Risk Register tables, so osv_keys_for_report would always
    be empty against it.
    """

    name = "fake"
    binary = "fake-binary"
    default_timeout_seconds = 30

    def build_command(self, prompt, *, workdir):
        return ["fake-binary"]

    def is_available(self) -> bool:
        return True

    def run(self, prompt, *, workdir, timeout=None):
        return AgentResult(
            agent=self.name, exit_code=0, stdout="ok", stderr="", duration_seconds=0.1,
            timed_out=False, status="success", raw_report=_SCA_REPORT,
        )


class _FakeUrlopenResponse:
    def __init__(self, payload):
        import json

        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_execute_runs_enriches_osv_cache_for_sca_reachability_runs(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _ScaAdapter())
    monkeypatch.setattr(
        "secfoo.osv.urllib.request.urlopen",
        lambda request, timeout=None: _FakeUrlopenResponse({"vulns": [{"id": "CVE-2022-33124"}]}),
    )
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    execute_runs(
        skill_ids=["sca-reachability"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo,
    )
    lookup_map = repo.osv_lookup_map()
    repo.close()

    assert lookup_map[("PyPI", "aiohttp", "3.8.0")].vulns == [{"id": "CVE-2022-33124"}]


def test_execute_runs_does_not_enrich_osv_for_non_sca_skills(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        "secfoo.osv.urllib.request.urlopen",
        lambda request, timeout=None: (_ for _ in ()).throw(AssertionError("must not call OSV for non-SCA skills")),
    )
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["security-architecture-review"], target=str(target_dir), confluence_urls=[],
        agent_id="claude", repo=repo,
    )
    repo.close()
    assert outcomes[0].status == "success"


def test_execute_runs_still_succeeds_when_osv_unreachable(tmp_path, monkeypatch):
    import urllib.error

    _patch_runner(monkeypatch, tmp_path)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _ScaAdapter())

    def _raise(request, timeout=None):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr("secfoo.osv.urllib.request.urlopen", _raise)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["sca-reachability"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo,
    )
    run_record = repo.get_run(outcomes[0].run_uuid)
    repo.close()

    # An OSV outage must never fail the local run.
    assert outcomes[0].status == "success"
    assert run_record.status == "success"


# ---------------------------------------------------------------------------
# SAST finding lifecycle hook (open/closed tracking across two real runs)
# ---------------------------------------------------------------------------

_SAST_REPORT_V1 = """\
# SAST Report

## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | SQL Injection via raw query | High | CWE-89 | A03:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | `app/db.py:42` | Confirmed |
"""

# Simulates a rescan after F1 (SQL injection) was fixed: that fingerprint
# (CWE-89 + app/db.py) is entirely absent, and a new, unrelated finding
# appeared elsewhere.
_SAST_REPORT_V2 = """\
# SAST Report

## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | Reflected XSS in search page | Medium | CWE-79 | A03:2021 | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | `app/views.py:8` | Confirmed |
"""

_SAST_REPORT_MALFORMED_VECTOR = """\
# SAST Report

## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | Weak crypto | Low | CWE-327 | unverified | not-a-real-vector | `app/crypto.py:5` | Latent |
"""


class _SastAdapter(AgentAdapter):
    """Fake adapter returning a real SAST-shaped report with a CVSS
    vector, so the runner's post-run finding-lifecycle hook has an actual
    Findings Register row to act on.
    """

    name = "fake"
    binary = "fake-binary"
    default_timeout_seconds = 30

    def __init__(self, report: str) -> None:
        self._report = report

    def build_command(self, prompt, *, workdir):
        return ["fake-binary"]

    def is_available(self) -> bool:
        return True

    def run(self, prompt, *, workdir, timeout=None):
        return AgentResult(
            agent=self.name, exit_code=0, stdout="ok", stderr="", duration_seconds=0.1,
            timed_out=False, status="success", raw_report=self._report,
        )


def test_execute_runs_records_a_new_open_sast_finding_with_a_real_cvss_score(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _SastAdapter(_SAST_REPORT_V1))
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    execute_runs(skill_ids=["sast"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo)

    findings = repo.list_sast_findings(status="open")
    repo.close()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe == "CWE-89"
    assert finding.location_file == "app/db.py"
    assert finding.cvss_vector == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    assert finding.cvss_score == 9.1  # computed by secfoo, never asserted by the fake LLM report


def test_execute_runs_closes_a_fixed_finding_and_opens_a_new_one_on_rescan(tmp_path, monkeypatch):
    """The real end-to-end path this whole feature exists for: two
    completed runs of the same project, a finding genuinely gone from the
    second report, and a genuinely new one in its place.
    """
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    repo = RunRepository(db_path=tmp_path / "db.sqlite")

    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _SastAdapter(_SAST_REPORT_V1))
    execute_runs(skill_ids=["sast"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo)

    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _SastAdapter(_SAST_REPORT_V2))
    execute_runs(skill_ids=["sast"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo)

    open_findings = repo.list_sast_findings(status="open")
    closed_findings = repo.list_sast_findings(status="closed")
    repo.close()

    assert len(open_findings) == 1
    assert open_findings[0].cwe == "CWE-79"
    assert open_findings[0].location_file == "app/views.py"

    assert len(closed_findings) == 1
    assert closed_findings[0].cwe == "CWE-89"
    assert closed_findings[0].closed_in_run_id is not None
    assert closed_findings[0].closed_at is not None


def test_execute_runs_reopens_a_finding_that_reappears_on_a_third_run(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    repo = RunRepository(db_path=tmp_path / "db.sqlite")

    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _SastAdapter(_SAST_REPORT_V1))
    execute_runs(skill_ids=["sast"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo)
    first_seen_at = repo.list_sast_findings(status="open")[0].first_seen_at

    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _SastAdapter(_SAST_REPORT_V2))
    execute_runs(skill_ids=["sast"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo)
    assert len(repo.list_sast_findings(status="closed")) == 1

    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _SastAdapter(_SAST_REPORT_V1))
    execute_runs(skill_ids=["sast"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo)

    open_findings = repo.list_sast_findings(status="open")
    repo.close()
    assert len(open_findings) == 1
    assert open_findings[0].cwe == "CWE-89"
    assert open_findings[0].closed_in_run_id is None
    assert open_findings[0].first_seen_at == first_seen_at  # reopen keeps the original first-seen date


def test_execute_runs_never_cross_matches_findings_across_projects(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _SastAdapter(_SAST_REPORT_V1))
    repo = RunRepository(db_path=tmp_path / "db.sqlite")

    target_a = tmp_path / "target-a"
    target_a.mkdir()
    target_b = tmp_path / "target-b"
    target_b.mkdir()
    execute_runs(skill_ids=["sast"], target=str(target_a), confluence_urls=[], agent_id="claude", repo=repo)
    execute_runs(skill_ids=["sast"], target=str(target_b), confluence_urls=[], agent_id="claude", repo=repo)

    findings = repo.list_sast_findings(status="open")
    repo.close()

    # Same fingerprint (identical report content), but two distinct
    # projects -- two rows, not deduplicated into one.
    assert len(findings) == 2
    assert {f.project_id for f in findings} == {f.project_id for f in findings if f.project_id}
    assert len({f.project_id for f in findings}) == 2


def test_execute_runs_tracks_a_finding_with_a_malformed_cvss_vector_without_failing_the_run(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "secfoo.runner.get_adapter", lambda agent_id: _SastAdapter(_SAST_REPORT_MALFORMED_VECTOR)
    )
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["sast"], target=str(target_dir), confluence_urls=[], agent_id="claude", repo=repo
    )
    findings = repo.list_sast_findings(status="open")
    repo.close()

    # A malformed vector must never fail the run or be silently dropped --
    # the finding is still tracked, just without a computed score.
    assert outcomes[0].status == "success"
    assert len(findings) == 1
    assert findings[0].cvss_vector == "not-a-real-vector"
    assert findings[0].cvss_score is None


def test_execute_runs_does_not_touch_sast_findings_for_non_sast_skills(tmp_path, monkeypatch):
    _patch_runner(monkeypatch, tmp_path)
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    execute_runs(
        skill_ids=["security-architecture-review"], target=str(target_dir), confluence_urls=[],
        agent_id="claude", repo=repo,
    )
    findings = repo.list_sast_findings()
    repo.close()
    assert findings == []
