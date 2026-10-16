"""Memory Bank incremental scanning (PR #22 review cases).

The end-to-end tests use a real git repository, the real api adapter and
LangGraph graph, and a fake LiteLLM that reports a finding only for a file
it was actually shown -- so they exercise exactly what an incremental scan
sends the model and what the findings lifecycle does with the result.
"""

from __future__ import annotations

import subprocess
import sys
import types

import pytest
from typer.testing import CliRunner

from secfoo.agents import api
from secfoo.agents.api import ApiAdapter, _git_changed_files
from secfoo.cli import app
from secfoo.runner import RunOutcome, already_scanned_skills, execute_runs
from secfoo.storage.repository import RunRepository

_HEADER = """\
# SAST Report

## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
"""
_ROWS = {
    "app/db.py": "| F1 | SQL Injection | High | CWE-89 | A03:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | `app/db.py:2` | Confirmed |\n",
    "app/views.py": "| F2 | Reflected XSS | Medium | CWE-79 | A03:2021 | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | `app/views.py:2` | Confirmed |\n",
}


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        check=True, capture_output=True, text=True,
    )


def _commit_all(repo, message):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def target(tmp_path):
    repo = tmp_path / "target"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("import sqlite3\ncur.execute('SELECT * FROM u WHERE id=' + uid)\n")
    (repo / "app" / "views.py").write_text("from flask import request\nreturn '<p>' + request.args['q']\n")
    _git(repo, "init", "-q")
    _commit_all(repo, "initial")
    return repo


@pytest.fixture
def model(monkeypatch, tmp_path):
    """Fake LiteLLM: records every prompt, and reports a finding for a file
    only if that file's source was in the prompt."""
    module = types.SimpleNamespace(prompts=[])

    def _completion(**kwargs):
        content = kwargs["messages"][-1]["content"]
        module.prompts.append(content)
        rows = "".join(row for path, row in _ROWS.items() if f"===== FILE: {path} =====" in content)
        report = _HEADER + rows + "\n**Overall risk rating:** High.\n"
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(content=report))],
            usage=types.SimpleNamespace(prompt_tokens=len(content), completion_tokens=10),
        )

    module.completion = _completion
    module.completion_cost = lambda completion_response: 0.0
    monkeypatch.setitem(sys.modules, "litellm", module)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("secfoo.runner.run_dir", lambda run_uuid: tmp_path / "reports" / run_uuid)
    monkeypatch.setattr("secfoo.runner.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: ApiAdapter())
    return module


@pytest.fixture
def repo(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    yield repo
    repo.close()


def _scan(repo, target):
    return execute_runs(skill_ids=["sast"], target=str(target), confluence_urls=[], agent_id="api", repo=repo)


def _status(repo):
    """Per file: "open" if the file has an open finding, else "closed". (Editing
    a file can re-key its finding -- the fingerprint includes a hash of the
    surrounding code -- so one file may have a closed row and an open one.)"""
    status: dict[str, str] = {}
    for f in repo.list_sast_findings():
        if f.status == "open" or f.location_file not in status:
            status[f.location_file] = f.status
    return status


# -- Review item 1 -----------------------------------------------------------


def test_incremental_scan_keeps_findings_in_unchanged_files_open(repo, target, model):
    _scan(repo, target)
    assert _status(repo) == {"app/db.py": "open", "app/views.py": "open"}

    (target / "app" / "views.py").write_text(
        "from flask import request\nreturn '<p>' + request.args['q']\n# touched\n"
    )
    _commit_all(target, "touch views only")
    _scan(repo, target)

    assert "===== FILE: app/views.py" in model.prompts[-1]
    assert "===== FILE: app/db.py" not in model.prompts[-1]  # really incremental
    # db.py was neither changed nor scanned, so its finding must stay open.
    assert _status(repo) == {"app/db.py": "open", "app/views.py": "open"}
    last_run = repo.list_runs()[0]
    assert last_run.scan_scope == ["app/views.py"]


def test_incremental_scan_still_closes_a_finding_fixed_in_a_changed_file(repo, target, model):
    _scan(repo, target)
    (target / "app" / "views.py").write_text("from flask import request\nfrom markupsafe import escape\n")
    _commit_all(target, "fix xss")
    # The model no longer reports the XSS for the fixed file.
    original = model.completion

    def _completion(**kwargs):
        response = original(**kwargs)
        message = response.choices[0].message
        message.content = message.content.replace(_ROWS["app/views.py"], "")
        return response

    model.completion = _completion
    _scan(repo, target)

    assert _status(repo) == {"app/db.py": "open", "app/views.py": "closed"}


def test_findings_in_a_deleted_file_are_closed(repo, target, model):
    (target / "app" / "util.py").write_text("x = 1\n")
    _commit_all(target, "add util")
    _scan(repo, target)

    _git(target, "rm", "-q", "app/views.py")
    (target / "app" / "util.py").write_text("x = 2\n")
    _commit_all(target, "delete views, touch util")
    _scan(repo, target)

    assert _status(repo) == {"app/db.py": "open", "app/views.py": "closed"}


# -- Review item 2 -----------------------------------------------------------


def test_commit_with_no_scannable_files_falls_back_to_a_full_scan(repo, target, model):
    _scan(repo, target)

    (target / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\xff\xfe")
    _commit_all(target, "add logo")
    _scan(repo, target)

    assert "incremental scan" not in model.prompts[-1]
    assert "===== FILE: app/db.py" in model.prompts[-1]
    assert _status(repo) == {"app/db.py": "open", "app/views.py": "open"}
    assert repo.list_runs()[0].scan_scope is None


# -- Review item 3 -----------------------------------------------------------


def test_uncommitted_and_untracked_changes_are_sent(repo, target, model):
    _scan(repo, target)

    (target / "app" / "views.py").write_text("changed but not committed\n")
    (target / "app" / "new.py").write_text("untracked\n")
    _scan(repo, target)

    prompt = model.prompts[-1]
    assert "===== FILE: app/views.py" in prompt
    assert "===== FILE: app/new.py" in prompt
    assert "===== FILE: app/db.py" not in prompt


def test_git_changed_files_covers_commits_working_tree_and_untracked(target):
    head = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (target / "app" / "db.py").write_text("committed change\n")
    _commit_all(target, "change db")
    (target / "app" / "views.py").write_text("unstaged change\n")
    (target / "notes.txt").write_text("untracked\n")

    changed, deleted = _git_changed_files(target, head)

    assert changed == ["app/db.py", "app/views.py", "notes.txt"]
    assert deleted == []


# -- Review item 6: renames and missing commits -------------------------------


def test_a_rename_reports_the_old_path_as_deleted(target):
    head = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    _git(target, "mv", "app/views.py", "app/pages.py")
    _commit_all(target, "rename")

    changed, deleted = _git_changed_files(target, head)

    assert changed == ["app/pages.py"]
    assert deleted == ["app/views.py"]


def test_an_unreachable_previous_commit_means_a_full_scan(target):
    assert _git_changed_files(target, "0" * 40) is None


def test_diff_paths_are_relative_to_a_subdirectory_target(target):
    head = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (target / "app" / "db.py").write_text("changed\n")
    (target / "README.md").write_text("outside the target\n")

    changed, _deleted = _git_changed_files(target / "app", head)

    assert changed == ["db.py"]  # what collect_files calls it, relative to the target


# -- Review item 4: no prompt in execute_runs ----------------------------------


def test_execute_runs_never_reads_stdin_even_for_an_already_scanned_commit(repo, target, model, monkeypatch):
    def _no_stdin(*args, **kwargs):
        raise AssertionError("execute_runs must not prompt: it also runs under the dashboard and CI")

    monkeypatch.setattr("builtins.input", _no_stdin)
    _scan(repo, target)
    outcomes = _scan(repo, target)  # same commit again

    assert [o.status for o in outcomes] == ["success"]


def test_already_scanned_skills_reports_only_repeats_of_a_clean_head(repo, target, model):
    _scan(repo, target)

    head, repeats = already_scanned_skills(skill_ids=["sast", "secret-scanning"], target=str(target), repo=repo)
    assert head is not None
    assert repeats == ["sast"]

    (target / "app" / "db.py").write_text("dirty\n")
    assert already_scanned_skills(skill_ids=["sast"], target=str(target), repo=repo)[1] == []


def _outcome() -> RunOutcome:
    return RunOutcome(
        run_uuid="u1", skill_id="sast", skill_name="SAST", agent_id="api", status="success",
        exit_code=0, duration_seconds=1.0, report_path="/tmp/r.md",
    )


def test_cli_asks_on_a_terminal_and_skips_only_the_repeated_skills(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kw: captured.update(kw) or [_outcome()])
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: True)
    monkeypatch.setattr("secfoo.cli.Prompt.ask", lambda *a, **k: "")
    monkeypatch.setattr("secfoo.cli.already_scanned_skills", lambda **kw: ("abcdef1234", ["sast"]))
    monkeypatch.setattr("secfoo.cli.Confirm.ask", lambda *a, **k: False)

    result = CliRunner().invoke(app, ["run", "-s", "sast", "-s", "secret-scanning", "-a", "api"])

    assert result.exit_code == 0, result.output
    assert captured["skill_ids"] == ["secret-scanning"]


def test_cli_rescan_flag_and_non_terminal_runs_never_ask(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kw: captured.update(kw) or [_outcome()])
    monkeypatch.setattr("secfoo.cli.already_scanned_skills", lambda **kw: ("abcdef1234", ["sast"]))

    def _no_prompt(*a, **k):
        raise AssertionError("must not ask")

    monkeypatch.setattr("secfoo.cli.Confirm.ask", _no_prompt)
    monkeypatch.setattr("secfoo.cli.Prompt.ask", lambda *a, **k: "")

    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: True)
    assert CliRunner().invoke(app, ["run", "-s", "sast", "-a", "api", "--rescan"]).exit_code == 0
    assert captured["skill_ids"] == ["sast"]

    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: False)
    assert CliRunner().invoke(app, ["run", "-s", "sast", "-a", "api"]).exit_code == 0
    assert captured["skill_ids"] == ["sast"]


def test_cli_exits_cleanly_when_every_skill_was_already_scanned(monkeypatch):
    def _no_run(**kw):
        raise AssertionError("nothing should run")

    monkeypatch.setattr("secfoo.cli.execute_runs", _no_run)
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: True)
    monkeypatch.setattr("secfoo.cli.Prompt.ask", lambda *a, **k: "")
    monkeypatch.setattr("secfoo.cli.already_scanned_skills", lambda **kw: ("abcdef1234", ["sast"]))
    monkeypatch.setattr("secfoo.cli.Confirm.ask", lambda *a, **k: False)

    result = CliRunner().invoke(app, ["run", "-s", "sast", "-a", "api"])

    assert result.exit_code == 0
    assert "--rescan" in result.output


# -- Storage -------------------------------------------------------------------


def _finding_run(repo, project_id):
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="api", confluence_urls=[]
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None, target_commit="abc", scan_scope=["app/db.py"],
    )
    return repo.get_run(run_uuid)


def test_scan_scope_round_trips_and_get_last_commit_reads_it(repo):
    project_id = repo.upsert_project("p", "P", "local")
    run = _finding_run(repo, project_id)

    assert run.scan_scope == ["app/db.py"]
    assert repo.get_last_commit(project_id=project_id, skill_id="sast") == "abc"
    assert repo.find_project_id("p") == project_id
    assert repo.find_project_id("missing") is None


def test_close_stale_findings_with_a_scope_only_closes_inside_it(repo):
    project_id = repo.upsert_project("p", "P", "local")
    run_id = _finding_run(repo, project_id).id
    for fingerprint, path in [("in-scope", "./App/DB.py"), ("out-of-scope", "app/views.py")]:
        repo.upsert_sast_finding(
            project_id=project_id, fingerprint=fingerprint, run_id=run_id, current_ref="F1", title="t",
            severity="High", cwe="CWE-89", owasp=None, verdict=None, location_file=path,
            location_line="1", cvss_vector=None, cvss_score=None,
        )

    repo.close_stale_sast_findings(
        project_id=project_id, run_id=run_id, seen_fingerprints=[], closed_at="now", only_files=["app/db.py"]
    )

    status = {f.fingerprint: f.status for f in repo.list_sast_findings(project_id=project_id)}
    assert status == {"in-scope": "closed", "out-of-scope": "open"}


def test_an_incremental_run_never_closes_sca_findings(repo):
    project_id = repo.upsert_project("p", "P", "local")
    before = repo._conn.total_changes
    repo.close_stale_findings(
        "sca-reachability", project_id=project_id, run_id=1, seen_fingerprints=[], closed_at="now",
        only_files=["requirements.txt"],
    )
    assert repo._conn.total_changes == before


def test_collect_files_is_unchanged_for_callers(tmp_path):
    (tmp_path / "a.py").write_text("print(1)\n")
    assert "===== FILE: a.py =====" in api.collect_files(tmp_path)
