"""Enterprise portal sync client: reads/writes ~/.secfoo/cloud.toml
(`secfoo cloud login/logout`) and pushes completed runs to the portal's
ingestion API (`secfoo cloud sync`, and the best-effort auto-push hook in
runner.py).

Uses stdlib `urllib.request` rather than adding an HTTP client dependency
-- same precedent as `secfoo vendor mermaid` in cli.py. Reading
`cloud.toml` reuses the same `tomllib`/`tomli` shim settings.py already
uses; there's no TOML *writer* dependency anywhere in the codebase, so
writing is a small hand-rolled serializer -- safe here because this file
only ever holds two plain strings (an API key, a URL), never arbitrary
user-authored TOML.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from secfoo.config import CLOUD_CONFIG_PATH
from secfoo.storage.models import AssessmentRecord, RunRecord
from secfoo.storage.repository import RunRepository

DEFAULT_PORTAL_URL = "https://app.secfoo.com"
REQUEST_TIMEOUT_SECONDS = 15


class CloudError(RuntimeError):
    pass


@dataclass(frozen=True)
class CloudConfig:
    api_key: str
    portal_url: str = DEFAULT_PORTAL_URL


def _toml_escape(value: str) -> str:
    if "\n" in value or "\r" in value:
        raise CloudError("cloud config values must not contain newlines")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def load_cloud_config(path: Path | None = None) -> CloudConfig | None:
    """Returns None if no cloud config exists yet (cloud sync is entirely
    optional/additive) -- callers treat that as "not logged in", not an
    error.
    """
    path = path or CLOUD_CONFIG_PATH
    if not path.exists():
        return None
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise CloudError(f"{path}: invalid TOML: {exc}") from exc
    api_key = data.get("api_key")
    if not api_key:
        raise CloudError(f"{path}: missing api_key")
    return CloudConfig(api_key=api_key, portal_url=data.get("portal_url") or DEFAULT_PORTAL_URL)


def save_cloud_config(config: CloudConfig, path: Path | None = None) -> None:
    path = path or CLOUD_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'api_key = "{_toml_escape(config.api_key)}"\n'
        f'portal_url = "{_toml_escape(config.portal_url)}"\n'
    )
    path.chmod(0o600)


def delete_cloud_config(path: Path | None = None) -> None:
    (path or CLOUD_CONFIG_PATH).unlink(missing_ok=True)


def _request(url: str, *, api_key: str, payload: dict | None = None) -> dict:
    headers = {"Authorization": f"Bearer {api_key}"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310 -- portal_url is user-configured, same trust model as MCP server URLs in settings.py
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise CloudError(f"Portal returned {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise CloudError(f"Could not reach the portal: {exc.reason}") from exc


def whoami(config: CloudConfig) -> dict:
    """Validates a key against the portal -- used interactively by
    `secfoo cloud login`/`status`, where a failure should be reported to
    the user, unlike push_run's silent-failure contract.
    """
    return _request(f"{config.portal_url.rstrip('/')}/api/v1/whoami", api_key=config.api_key)


def push_run(
    config: CloudConfig,
    *,
    run: RunRecord,
    project_identifier: str,
    project_kind: str,
    report_markdown: str,
    assessment: AssessmentRecord | None = None,
) -> None:
    """Pushes one completed run to the portal. Raises CloudError on any
    failure -- callers that must never fail the local run over this
    (runner.py's auto-push hook) catch it; `secfoo cloud sync`, run
    interactively, lets it surface per-run instead.

    `assessment`, when given, is the case file this run is attached to
    locally -- included so the portal's Assessments register actually
    gets populated instead of only ever seeing bare runs (the gap that
    made every synced run show up under its Activity page but never as
    an assessment). Keyed by `assessment.assessment_uuid`, not the local
    autoincrement id, since that id only means something within this
    one machine's SQLite file -- see schema.sql's comment on that column.
    """
    payload = {
        "client_run_uuid": run.run_uuid,
        "project": {
            "identifier": project_identifier,
            "display_name": run.project_display_name or project_identifier,
            "kind": project_kind,
        },
        "run": {
            "skill_id": run.skill_id,
            "skill_name": run.skill_name,
            "agent_id": run.agent_id,
            "status": run.status,
            "exit_code": run.exit_code,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "duration_seconds": run.duration_seconds,
            "confluence_urls": run.confluence_urls,
        },
        "report_markdown": report_markdown,
        "cli_version": _cli_version(),
    }
    if assessment is not None:
        payload["assessment"] = {
            "assessment_uuid": assessment.assessment_uuid,
            "assessment_type": assessment.assessment_type,
            "status": assessment.status,
            "application_id": assessment.application_id,
            "sar_number": assessment.sar_number,
            "reviewer": assessment.reviewer,
            "review_date": assessment.review_date,
            "notes": assessment.notes,
        }
    _request(f"{config.portal_url.rstrip('/')}/api/v1/runs", api_key=config.api_key, payload=payload)


def _cli_version() -> str:
    from secfoo.__about__ import __version__

    return __version__


def sync_run(repo: RunRepository, run_uuid: str, config: CloudConfig) -> None:
    """Pushes one already-completed local run to the portal and marks it
    synced on success. Raises CloudError (from push_run) or ValueError (if
    the run/project can't be found locally) -- never swallows anything
    itself; callers decide what "best-effort" means for them (runner.py's
    hook catches broadly, `secfoo cloud sync` reports failures per-run).
    """
    run = repo.get_run(run_uuid)
    if run is None:
        raise ValueError(f"No local run with id {run_uuid}")
    project = repo.get_project(run.project_id)
    if project is None:
        raise ValueError(f"No local project for run {run_uuid}")

    report_markdown = ""
    if run.report_path and Path(run.report_path).is_file():
        report_markdown = Path(run.report_path).read_text()

    assessment = repo.get_assessment(run.assessment_id) if run.assessment_id else None

    push_run(
        config,
        run=run,
        project_identifier=project.identifier,
        project_kind=project.kind,
        report_markdown=report_markdown,
        assessment=assessment,
    )
    repo.mark_run_synced(run_uuid)
