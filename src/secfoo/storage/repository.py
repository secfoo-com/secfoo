from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secfoo.config import DB_PATH, ensure_store_dirs

# Lets a host process that serves multiple SQLite files (the multi-tenant
# portal, one file per tenant) select which file `RunRepository()` opens
# without a caller having to pass db_path explicitly -- every route in
# web/routes/*.py calls `RunRepository()` with no arguments, so a portal
# request handler sets this once via `use_db_path()` before the route runs
# and every unmodified route/dashboard-builder call picks it up. A plain
# module-level variable would NOT be safe here: concurrent requests for
# different tenants would race on the same mutable global. A ContextVar is
# scoped per request/task, not per process.
_default_db_path: ContextVar[Path | None] = ContextVar("secfoo_default_db_path", default=None)


@contextmanager
def use_db_path(path: Path):
    """Makes `RunRepository()` (no explicit db_path) resolve to `path` for
    the duration of this context -- for a multi-tenant host to scope an
    incoming request to one tenant's database file. Local single-tenant use
    (the CLI, `secfoo serve`) never calls this; `RunRepository()` falls
    back to the process-wide `DB_PATH` exactly as before.
    """
    token = _default_db_path.set(path)
    try:
        yield
    finally:
        _default_db_path.reset(token)
from secfoo.report.severity import SeverityCounts, extract_overall_risk_rating
from secfoo.storage.models import (
    AssessmentRecord,
    AttachmentRecord,
    ExceptionRecord,
    OsvLookupRecord,
    PostBuildFindingRecord,
    ProjectRecord,
    RunRecord,
    SastFindingRecord,
    ThreatAcceptanceRecord,
)

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
SCHEMA_INDEXES_PATH = Path(__file__).parent / "schema_indexes.sql"

# Columns added to `runs` after its original release. schema.sql's
# `CREATE TABLE IF NOT EXISTS` already includes these for a fresh install,
# but does nothing for a pre-existing ~/.secfoo/secfoo.db -- this migration
# adds them there too, idempotently, so upgrading never requires wiping a
# user's local store.
_RUNS_MIGRATIONS = {
    "assessment_id": "ALTER TABLE runs ADD COLUMN assessment_id INTEGER REFERENCES assessments(id)",
    "critical_count": "ALTER TABLE runs ADD COLUMN critical_count INTEGER NOT NULL DEFAULT 0",
    "high_count": "ALTER TABLE runs ADD COLUMN high_count INTEGER NOT NULL DEFAULT 0",
    "medium_count": "ALTER TABLE runs ADD COLUMN medium_count INTEGER NOT NULL DEFAULT 0",
    "low_count": "ALTER TABLE runs ADD COLUMN low_count INTEGER NOT NULL DEFAULT 0",
    "info_count": "ALTER TABLE runs ADD COLUMN info_count INTEGER NOT NULL DEFAULT 0",
    # Set once this run has been pushed to the enterprise portal (secfoo
    # cloud) -- NULL means never synced, or synced before this column
    # existed on an upgraded local store (re-synced harmlessly by `secfoo
    # cloud sync`, since ingestion is idempotent on the server side).
    "cloud_synced_at": "ALTER TABLE runs ADD COLUMN cloud_synced_at TEXT",
}

_ASSESSMENTS_MIGRATIONS = {
    "assessment_uuid": "ALTER TABLE assessments ADD COLUMN assessment_uuid TEXT",
}

_ASSESSMENT_UPDATE_FIELDS = {
    "assessment_type", "status", "application_id", "sar_number", "reviewer", "review_date", "notes",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunRepository:
    def __init__(self, db_path: Path | None = None) -> None:
        ensure_store_dirs()
        self.db_path = db_path or _default_db_path.get() or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        # Skills run concurrently in separate threads, each with its own
        # connection to this same file; a busy_timeout makes a writer wait
        # for a lock instead of immediately raising "database is locked".
        self._conn.execute("PRAGMA busy_timeout = 5000")
        # WAL lets readers (secfoo serve, or the portal serving a tenant's
        # dashboard) proceed without blocking on a concurrent writer (a
        # run in progress) -- readers otherwise wait behind the default
        # rollback-journal's writer lock. Requires local disk, not
        # NFS/EFS-backed storage, for the portal host.
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(SCHEMA_PATH.read_text())
        self._conn.commit()
        self._migrate()
        self._conn.executescript(SCHEMA_INDEXES_PATH.read_text())
        self._conn.commit()

    def _migrate(self) -> None:
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(runs)").fetchall()}
        for column, ddl in _RUNS_MIGRATIONS.items():
            if column not in existing:
                self._conn.execute(ddl)
        existing_assessment_cols = {
            row["name"] for row in self._conn.execute("PRAGMA table_info(assessments)").fetchall()
        }
        for column, ddl in _ASSESSMENTS_MIGRATIONS.items():
            if column not in existing_assessment_cols:
                self._conn.execute(ddl)
        self._conn.commit()
        self._migrate_attachment_kind_check()

    def _migrate_attachment_kind_check(self) -> None:
        """Widens assessment_attachments.attachment_kind's CHECK constraint
        to allow 'vendor_doc' on a pre-existing database. Unlike a plain
        column addition (_RUNS_MIGRATIONS' ALTER TABLE ADD COLUMN idiom),
        SQLite has no ALTER TABLE for changing a CHECK constraint -- the
        only way is the documented "12-step" table-rebuild: create the new
        table under a temp name, copy every row across, drop the old one,
        rename the new one into place. A no-op (checked via
        sqlite_master.sql, not a trial insert) on any DB that already has
        the widened constraint, including every fresh install.
        """
        row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'assessment_attachments'"
        ).fetchone()
        if row is None or "vendor_doc" in row["sql"]:
            return
        self._conn.executescript(
            """
            CREATE TABLE assessment_attachments_new (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id    INTEGER NOT NULL REFERENCES assessments(id),
                file_path        TEXT NOT NULL,
                original_name    TEXT NOT NULL,
                attachment_kind  TEXT NOT NULL CHECK (attachment_kind IN ('ai_bom','report','other','vendor_doc')),
                uploaded_at      TEXT NOT NULL
            );
            INSERT INTO assessment_attachments_new
                SELECT id, assessment_id, file_path, original_name, attachment_kind, uploaded_at
                FROM assessment_attachments;
            DROP TABLE assessment_attachments;
            ALTER TABLE assessment_attachments_new RENAME TO assessment_attachments;
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "RunRepository":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------- projects ----------

    def upsert_project(self, identifier: str, display_name: str, kind: str) -> int:
        now = _now()
        cur = self._conn.execute("SELECT id FROM projects WHERE identifier = ?", (identifier,))
        row = cur.fetchone()
        if row is not None:
            self._conn.execute(
                "UPDATE projects SET last_run_at = ? WHERE id = ?", (now, row["id"])
            )
            self._conn.commit()
            return row["id"]

        cur = self._conn.execute(
            "INSERT INTO projects (identifier, display_name, kind, first_seen_at, last_run_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (identifier, display_name, kind, now, now),
        )
        self._conn.commit()
        return cur.lastrowid

    def rename_project(self, project_id: int, display_name: str) -> None:
        """Overrides a project's auto-derived display name with a
        user-supplied one (e.g. the "Project Name" field on the New
        Assessment form). Deliberately a separate call from
        `upsert_project` -- that method never touches display_name on an
        existing row precisely so a name set here isn't silently reverted
        by a later plain `secfoo run` against the same target, which always
        re-derives the auto name from the path/URL.
        """
        self._conn.execute("UPDATE projects SET display_name = ? WHERE id = ?", (display_name, project_id))
        self._conn.commit()

    def list_projects(self) -> list[ProjectRecord]:
        rows = self._conn.execute("SELECT * FROM projects ORDER BY last_run_at DESC").fetchall()
        return [ProjectRecord(**dict(row)) for row in rows]

    def get_project(self, project_id: int) -> ProjectRecord | None:
        row = self._conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return ProjectRecord(**dict(row)) if row else None

    # ---------- runs ----------

    def create_run(
        self,
        *,
        project_id: int,
        skill_id: str,
        skill_name: str,
        agent_id: str,
        confluence_urls: list[str],
        assessment_id: int | None = None,
    ) -> str:
        run_uuid = str(uuid.uuid4())
        self._conn.execute(
            "INSERT INTO runs (run_uuid, project_id, assessment_id, skill_id, skill_name, agent_id, "
            "confluence_urls, status, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?)",
            (run_uuid, project_id, assessment_id, skill_id, skill_name, agent_id, json.dumps(confluence_urls), _now()),
        )
        self._conn.commit()
        return run_uuid

    def create_completed_run(
        self,
        *,
        run_uuid: str,
        project_id: int,
        skill_id: str,
        skill_name: str,
        agent_id: str,
        confluence_urls: list[str],
        status: str,
        exit_code: int | None,
        started_at: str,
        finished_at: str | None,
        duration_seconds: float | None,
        report_path: str | None,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
        info_count: int = 0,
        assessment_id: int | None = None,
    ) -> None:
        """Inserts a run that already fully happened elsewhere, in one
        step, keyed by a caller-supplied `run_uuid` rather than minting a
        new one. Used by the enterprise portal's ingestion API to
        replicate a run the CLI already ran and completed locally --
        unlike `create_run()` + `complete_run()`, which model a run
        actually starting and finishing in this process.
        """
        self._conn.execute(
            "INSERT INTO runs (run_uuid, project_id, skill_id, skill_name, agent_id, confluence_urls, "
            "status, exit_code, started_at, finished_at, duration_seconds, report_path, "
            "critical_count, high_count, medium_count, low_count, info_count, assessment_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_uuid, project_id, skill_id, skill_name, agent_id, json.dumps(confluence_urls),
                status, exit_code, started_at, finished_at, duration_seconds, report_path,
                critical_count, high_count, medium_count, low_count, info_count, assessment_id,
            ),
        )
        self._conn.commit()

    def complete_run(
        self,
        run_uuid: str,
        *,
        status: str,
        exit_code: int | None,
        duration_seconds: float | None,
        report_path: str | None,
        prompt_path: str | None,
        stderr_excerpt: str | None,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
        info_count: int = 0,
    ) -> None:
        self._conn.execute(
            "UPDATE runs SET status = ?, exit_code = ?, finished_at = ?, duration_seconds = ?, "
            "report_path = ?, prompt_path = ?, stderr_excerpt = ?, critical_count = ?, high_count = ?, "
            "medium_count = ?, low_count = ?, info_count = ? WHERE run_uuid = ?",
            (
                status,
                exit_code,
                _now(),
                duration_seconds,
                report_path,
                prompt_path,
                stderr_excerpt,
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count,
                run_uuid,
            ),
        )
        self._conn.commit()

    def mark_run_synced(self, run_uuid: str) -> None:
        """Records that this run has been pushed to the enterprise portal.
        Called by `secfoo cloud` after a successful `push_run()` -- see
        cloud.py. Idempotent: syncing an already-synced run just updates
        the timestamp.
        """
        self._conn.execute(
            "UPDATE runs SET cloud_synced_at = ? WHERE run_uuid = ?", (_now(), run_uuid)
        )
        self._conn.commit()

    def list_unsynced_runs(self, limit: int = 500) -> list[RunRecord]:
        """Successful runs never pushed to the portal -- what `secfoo cloud
        sync` catches up after a run happened while offline or before
        `cloud login` was ever run.
        """
        rows = self._conn.execute(
            "SELECT runs.*, projects.display_name FROM runs "
            "JOIN projects ON projects.id = runs.project_id "
            "WHERE runs.status = 'success' AND runs.cloud_synced_at IS NULL "
            "ORDER BY runs.started_at ASC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_run(row) for row in rows]

    def _row_to_run(self, row: sqlite3.Row) -> RunRecord:
        data = dict(row)
        confluence_urls = json.loads(data.pop("confluence_urls") or "[]")
        project_display_name = data.pop("display_name", None)
        return RunRecord(confluence_urls=confluence_urls, project_display_name=project_display_name, **data)

    def list_runs(
        self,
        *,
        project_id: int | None = None,
        assessment_id: int | None = None,
        skill_id: str | None = None,
        limit: int = 200,
        status: str | None = None,
    ) -> list[RunRecord]:
        query = (
            "SELECT runs.*, projects.display_name FROM runs "
            "JOIN projects ON projects.id = runs.project_id WHERE 1=1"
        )
        params: list[object] = []
        if project_id is not None:
            query += " AND runs.project_id = ?"
            params.append(project_id)
        if assessment_id is not None:
            query += " AND runs.assessment_id = ?"
            params.append(assessment_id)
        if skill_id is not None:
            query += " AND runs.skill_id = ?"
            params.append(skill_id)
        if status is not None:
            query += " AND runs.status = ?"
            params.append(status)
        query += " ORDER BY runs.started_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_run(row) for row in rows]

    def get_run(self, run_uuid: str) -> RunRecord | None:
        row = self._conn.execute(
            "SELECT runs.*, projects.display_name FROM runs "
            "JOIN projects ON projects.id = runs.project_id WHERE runs.run_uuid = ?",
            (run_uuid,),
        ).fetchone()
        return self._row_to_run(row) if row else None

    def severity_totals(self, *, project_id: int | None = None) -> SeverityCounts:
        query = (
            "SELECT COALESCE(SUM(critical_count),0) c, COALESCE(SUM(high_count),0) h, "
            "COALESCE(SUM(medium_count),0) m, COALESCE(SUM(low_count),0) l, "
            "COALESCE(SUM(info_count),0) i FROM runs WHERE 1=1"
        )
        params: list[object] = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        row = self._conn.execute(query, params).fetchone()
        return SeverityCounts(critical=row["c"], high=row["h"], medium=row["m"], low=row["l"], info=row["i"])

    def assessment_severity_totals(self, assessment_id: int) -> SeverityCounts:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(critical_count),0) c, COALESCE(SUM(high_count),0) h, "
            "COALESCE(SUM(medium_count),0) m, COALESCE(SUM(low_count),0) l, "
            "COALESCE(SUM(info_count),0) i FROM runs WHERE assessment_id = ?",
            (assessment_id,),
        ).fetchone()
        return SeverityCounts(critical=row["c"], high=row["h"], medium=row["m"], low=row["l"], info=row["i"])

    def activity_summary_by_project(self, skill_id: str) -> list[dict]:
        """Per-project rollup of one activity (skill), newest first.

        Backs the per-activity dashboard pages: for each project ever
        scanned with this skill, its latest run, that run's status, and the
        severity totals across *all* of this skill's runs for the project.
        """
        rows = self._conn.execute(
            """
            SELECT
                projects.id            AS project_id,
                projects.display_name  AS project_display_name,
                projects.kind          AS project_kind,
                COUNT(runs.id)         AS run_count,
                MAX(runs.started_at)   AS latest_started_at,
                COALESCE(SUM(runs.critical_count), 0) AS critical_count,
                COALESCE(SUM(runs.high_count), 0)     AS high_count,
                COALESCE(SUM(runs.medium_count), 0)   AS medium_count,
                COALESCE(SUM(runs.low_count), 0)      AS low_count,
                COALESCE(SUM(runs.info_count), 0)     AS info_count
            FROM runs
            JOIN projects ON projects.id = runs.project_id
            WHERE runs.skill_id = ?
            GROUP BY projects.id
            ORDER BY latest_started_at DESC
            """,
            (skill_id,),
        ).fetchall()

        summary = []
        for row in rows:
            data = dict(row)
            # The run row backing `latest_started_at`, for status + deep link.
            latest = self._conn.execute(
                "SELECT run_uuid, status, assessment_id FROM runs "
                "WHERE skill_id = ? AND project_id = ? ORDER BY started_at DESC LIMIT 1",
                (skill_id, data["project_id"]),
            ).fetchone()
            data["latest_run_uuid"] = latest["run_uuid"] if latest else None
            data["latest_status"] = latest["status"] if latest else None
            data["latest_assessment_id"] = latest["assessment_id"] if latest else None

            # Separate from `latest` above: the most recent *successful*
            # run's report, specifically for dashboard content extraction
            # (diagram, design verdict) -- a failed/timeout run has no
            # report to read, but shouldn't hide an earlier successful one.
            latest_success = self._conn.execute(
                "SELECT report_path FROM runs WHERE skill_id = ? AND project_id = ? "
                "AND status = 'success' AND report_path IS NOT NULL "
                "ORDER BY started_at DESC LIMIT 1",
                (skill_id, data["project_id"]),
            ).fetchone()
            data["latest_success_report_path"] = latest_success["report_path"] if latest_success else None

            summary.append(data)
        return summary

    def project_activity_coverage(self, project_id: int) -> dict[str, dict]:
        """Per-activity rollup for ONE project, keyed by skill_id -- the
        mirror image of activity_summary_by_project. Backs the project
        page's "which analyses has this project actually had" breakdown.
        """
        rows = self._conn.execute(
            """
            SELECT
                skill_id,
                COUNT(*)             AS run_count,
                MAX(started_at)      AS latest_started_at,
                COALESCE(SUM(critical_count), 0) AS critical_count,
                COALESCE(SUM(high_count), 0)     AS high_count,
                COALESCE(SUM(medium_count), 0)   AS medium_count,
                COALESCE(SUM(low_count), 0)      AS low_count,
                COALESCE(SUM(info_count), 0)     AS info_count
            FROM runs
            WHERE project_id = ?
            GROUP BY skill_id
            """,
            (project_id,),
        ).fetchall()
        return {row["skill_id"]: dict(row) for row in rows}

    def activity_severity_totals(self, skill_id: str) -> SeverityCounts:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(critical_count),0) c, COALESCE(SUM(high_count),0) h, "
            "COALESCE(SUM(medium_count),0) m, COALESCE(SUM(low_count),0) l, "
            "COALESCE(SUM(info_count),0) i FROM runs WHERE skill_id = ?",
            (skill_id,),
        ).fetchone()
        return SeverityCounts(critical=row["c"], high=row["h"], medium=row["m"], low=row["l"], info=row["i"])

    def skill_coverage(self) -> dict[str, int]:
        """Number of distinct PROJECTS with at least one successful run of
        each skill -- backs the dashboard's activity-coverage panel.

        Deliberately project-scoped, not assessment-scoped. Assessments are
        an optional case-file wrapper: a plain `secfoo run` (and every run
        predating the assessment feature) has assessment_id NULL, so
        counting distinct assessments reported 0% coverage for activities
        that had genuinely been run many times. "Which of our applications
        have had this analysis?" is the question this panel answers.
        """
        rows = self._conn.execute(
            "SELECT skill_id, COUNT(DISTINCT project_id) c FROM runs "
            "WHERE status = 'success' GROUP BY skill_id"
        ).fetchall()
        return {row["skill_id"]: row["c"] for row in rows}

    # ---------- assessments ----------

    def _responsible_ai_badges(self, assessment_id: int, status: str) -> tuple[str | None, str | None]:
        """Derived from the most recent successful Responsible AI Compliance
        run attached to this assessment, per the plan's decision: no
        separate manually-set risk field. Returns (risk, provisional-status),
        both None if no such run (or no parsable rating) exists yet.
        """
        row = self._conn.execute(
            "SELECT report_path FROM runs WHERE assessment_id = ? AND skill_id = 'responsible-ai-compliance' "
            "AND status = 'success' AND report_path IS NOT NULL ORDER BY started_at DESC LIMIT 1",
            (assessment_id,),
        ).fetchone()
        if row is None or not row["report_path"]:
            return None, None
        path = Path(row["report_path"])
        if not path.exists():
            return None, None
        rating = extract_overall_risk_rating(path.read_text())
        if rating is None:
            return None, None
        risk = "high-risk" if rating == "high" else "moderate"
        ra_status = "confirmed" if status == "completed" else "provisional"
        return risk, ra_status

    def _row_to_assessment(self, row: sqlite3.Row) -> AssessmentRecord:
        data = dict(row)
        project_display_name = data.pop("display_name", None)
        severity = self.assessment_severity_totals(data["id"])
        responsible_ai_risk, responsible_ai_status = self._responsible_ai_badges(data["id"], data["status"])
        return AssessmentRecord(
            project_display_name=project_display_name,
            critical_count=severity.critical,
            high_count=severity.high,
            medium_count=severity.medium,
            low_count=severity.low,
            info_count=severity.info,
            responsible_ai_risk=responsible_ai_risk,
            responsible_ai_status=responsible_ai_status,
            **data,
        )

    def create_assessment(
        self,
        *,
        project_id: int,
        assessment_type: str,
        status: str = "ready",
        application_id: str | None = None,
        sar_number: str | None = None,
        reviewer: str | None = None,
        review_date: str | None = None,
        notes: str | None = None,
        assessment_uuid: str | None = None,
    ) -> int:
        now = _now()
        # A stable cross-machine identity, distinct from the local
        # autoincrement id -- see schema.sql's comment on this column.
        # `assessment_uuid` is only ever passed explicitly by the portal's
        # ingest handler, which needs to create the row with a uuid it
        # already received from the CLI rather than minting a new one.
        assessment_uuid = assessment_uuid or str(uuid.uuid4())
        cur = self._conn.execute(
            "INSERT INTO assessments (project_id, assessment_type, status, application_id, sar_number, "
            "reviewer, review_date, notes, created_at, updated_at, assessment_uuid) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                project_id, assessment_type, status, application_id, sar_number, reviewer, review_date, notes,
                now, now, assessment_uuid,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_assessment_by_uuid(self, assessment_uuid: str) -> AssessmentRecord | None:
        row = self._conn.execute(
            "SELECT assessments.*, projects.display_name FROM assessments "
            "JOIN projects ON projects.id = assessments.project_id WHERE assessments.assessment_uuid = ?",
            (assessment_uuid,),
        ).fetchone()
        return self._row_to_assessment(row) if row else None

    def update_assessment(self, assessment_id: int, **fields: object) -> None:
        if not fields:
            return
        unknown = set(fields) - _ASSESSMENT_UPDATE_FIELDS
        if unknown:
            raise ValueError(f"Unknown assessment field(s): {sorted(unknown)}")
        set_clause = ", ".join(f"{k} = ?" for k in fields) + ", updated_at = ?"
        params = [*fields.values(), _now(), assessment_id]
        self._conn.execute(f"UPDATE assessments SET {set_clause} WHERE id = ?", params)  # nosec B608 -- column names from _ASSESSMENT_UPDATE_FIELDS whitelist above
        self._conn.commit()

    def get_assessment(self, assessment_id: int) -> AssessmentRecord | None:
        row = self._conn.execute(
            "SELECT assessments.*, projects.display_name FROM assessments "
            "JOIN projects ON projects.id = assessments.project_id WHERE assessments.id = ?",
            (assessment_id,),
        ).fetchone()
        return self._row_to_assessment(row) if row else None

    def find_assessment_by_application_id(self, *, project_id: int, application_id: str) -> AssessmentRecord | None:
        """The most-recently-updated assessment for this project carrying
        this application ID -- used by execute_runs()'s auto-creation
        (and the portal's ingest handler) to consolidate repeat runs
        against the same real-world system under one case file instead
        of minting a new assessment every single `secfoo run`. Scoped to
        project_id, not just application_id alone, so a typo'd/reused ID
        against an unrelated target can't silently attach to the wrong
        system's case file.
        """
        row = self._conn.execute(
            "SELECT assessments.*, projects.display_name FROM assessments "
            "JOIN projects ON projects.id = assessments.project_id "
            "WHERE assessments.project_id = ? AND assessments.application_id = ? "
            "ORDER BY assessments.updated_at DESC LIMIT 1",
            (project_id, application_id),
        ).fetchone()
        return self._row_to_assessment(row) if row else None

    def list_assessments(
        self,
        *,
        assessment_type: str | None = None,
        status: str | None = None,
        search: str | None = None,
        limit: int = 200,
    ) -> list[AssessmentRecord]:
        query = (
            "SELECT assessments.*, projects.display_name FROM assessments "
            "JOIN projects ON projects.id = assessments.project_id WHERE 1=1"
        )
        params: list[object] = []
        if assessment_type is not None:
            query += " AND assessments.assessment_type = ?"
            params.append(assessment_type)
        if status is not None:
            query += " AND assessments.status = ?"
            params.append(status)
        if search:
            query += (
                " AND (projects.display_name LIKE ? OR assessments.application_id LIKE ? "
                "OR assessments.sar_number LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like])
        query += " ORDER BY assessments.updated_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_assessment(row) for row in rows]

    def count_assessments(self, *, assessment_type: str | None = None) -> int:
        query = "SELECT COUNT(*) c FROM assessments WHERE 1=1"
        params: list[object] = []
        if assessment_type is not None:
            query += " AND assessment_type = ?"
            params.append(assessment_type)
        return self._conn.execute(query, params).fetchone()["c"]

    def count_assessments_with_responsible_ai_risk(self) -> int:
        rows = self._conn.execute("SELECT id, status FROM assessments").fetchall()
        return sum(1 for row in rows if self._responsible_ai_badges(row["id"], row["status"])[0] is not None)

    def delete_assessment(self, assessment_id: int) -> None:
        self._conn.execute("UPDATE runs SET assessment_id = NULL WHERE assessment_id = ?", (assessment_id,))
        attachments = self._conn.execute(
            "SELECT id, file_path FROM assessment_attachments WHERE assessment_id = ?", (assessment_id,)
        ).fetchall()
        for attachment in attachments:
            self._conn.execute("DELETE FROM ai_bom_items WHERE attachment_id = ?", (attachment["id"],))
            path = Path(attachment["file_path"])
            if path.exists():
                path.unlink()
        self._conn.execute("DELETE FROM assessment_attachments WHERE assessment_id = ?", (assessment_id,))
        self._conn.execute("DELETE FROM assessments WHERE id = ?", (assessment_id,))
        self._conn.commit()

    # ---------- attachments / AI-BOM ----------

    def add_attachment(
        self, *, assessment_id: int, file_path: str, original_name: str, attachment_kind: str
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO assessment_attachments (assessment_id, file_path, original_name, attachment_kind, "
            "uploaded_at) VALUES (?, ?, ?, ?, ?)",
            (assessment_id, file_path, original_name, attachment_kind, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_attachments(self, assessment_id: int) -> list[AttachmentRecord]:
        rows = self._conn.execute(
            "SELECT * FROM assessment_attachments WHERE assessment_id = ? ORDER BY uploaded_at DESC",
            (assessment_id,),
        ).fetchall()
        return [AttachmentRecord(**dict(row)) for row in rows]

    def add_ai_bom_items(self, attachment_id: int, items: list[dict[str, str | None]]) -> None:
        if not items:
            return
        self._conn.executemany(
            "INSERT INTO ai_bom_items (attachment_id, kind, name, provider_or_type, version, purpose) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    attachment_id,
                    item["kind"],
                    item["name"],
                    item.get("provider_or_type"),
                    item.get("version"),
                    item.get("purpose"),
                )
                for item in items
            ],
        )
        self._conn.commit()

    def ai_bom_counts(self, assessment_id: int) -> tuple[int, int]:
        row = self._conn.execute(
            "SELECT SUM(CASE WHEN ai_bom_items.kind = 'model' THEN 1 ELSE 0 END) models, "
            "SUM(CASE WHEN ai_bom_items.kind = 'tool' THEN 1 ELSE 0 END) tools FROM ai_bom_items "
            "JOIN assessment_attachments ON assessment_attachments.id = ai_bom_items.attachment_id "
            "WHERE assessment_attachments.assessment_id = ?",
            (assessment_id,),
        ).fetchone()
        return (row["models"] or 0, row["tools"] or 0)

    def ai_bom_counts_total(self) -> tuple[int, int]:
        row = self._conn.execute(
            "SELECT SUM(CASE WHEN kind = 'model' THEN 1 ELSE 0 END) models, "
            "SUM(CASE WHEN kind = 'tool' THEN 1 ELSE 0 END) tools FROM ai_bom_items"
        ).fetchone()
        return (row["models"] or 0, row["tools"] or 0)

    # ---------- exceptions ----------

    def _row_to_exception(self, row: sqlite3.Row) -> ExceptionRecord:
        data = dict(row)
        project_display_name = data.pop("display_name", None)
        return ExceptionRecord(project_display_name=project_display_name, **data)

    def create_exception(
        self,
        *,
        project_id: int,
        title: str,
        justification: str,
        granted_by: str,
        expires_at: str,
        assessment_id: int | None = None,
        standard_or_control: str | None = None,
        status: str = "active",
    ) -> int:
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO exceptions (project_id, assessment_id, title, standard_or_control, justification, "
            "granted_by, status, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                project_id, assessment_id, title, standard_or_control, justification,
                granted_by, status, now, now, expires_at,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def update_exception(self, exception_id: int, **fields: object) -> None:
        if not fields:
            return
        allowed = {
            "title", "standard_or_control", "justification", "granted_by", "status", "expires_at",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"Unknown exception field(s): {sorted(unknown)}")
        set_clause = ", ".join(f"{k} = ?" for k in fields) + ", updated_at = ?"
        params = [*fields.values(), _now(), exception_id]
        self._conn.execute(f"UPDATE exceptions SET {set_clause} WHERE id = ?", params)  # nosec B608 -- column names from allowed whitelist above
        self._conn.commit()

    def get_exception(self, exception_id: int) -> ExceptionRecord | None:
        row = self._conn.execute(
            "SELECT exceptions.*, projects.display_name FROM exceptions "
            "JOIN projects ON projects.id = exceptions.project_id WHERE exceptions.id = ?",
            (exception_id,),
        ).fetchone()
        return self._row_to_exception(row) if row else None

    def list_exceptions(
        self, *, project_id: int | None = None, status: str | None = None, limit: int = 500
    ) -> list[ExceptionRecord]:
        query = (
            "SELECT exceptions.*, projects.display_name FROM exceptions "
            "JOIN projects ON projects.id = exceptions.project_id WHERE 1=1"
        )
        params: list[object] = []
        if project_id is not None:
            query += " AND exceptions.project_id = ?"
            params.append(project_id)
        if status is not None:
            query += " AND exceptions.status = ?"
            params.append(status)
        query += " ORDER BY exceptions.expires_at ASC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_exception(row) for row in rows]

    def delete_exception(self, exception_id: int) -> None:
        self._conn.execute("DELETE FROM exceptions WHERE id = ?", (exception_id,))
        self._conn.commit()

    def exceptions_past_expiry_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) c FROM exceptions WHERE status = 'active' AND expires_at < ?", (_now(),)
        ).fetchone()
        return row["c"]

    def exceptions_aging_buckets(self) -> dict[str, int]:
        """Active exceptions bucketed by days until expiry. Only exceptions
        already past expiry or expiring within 90 days are counted --
        matching the dashboard's "aging toward expiry" framing rather than
        every exception regardless of how far off it is.
        """
        now = datetime.now(timezone.utc)
        rows = self._conn.execute(
            "SELECT expires_at FROM exceptions WHERE status = 'active'"
        ).fetchall()
        buckets = {"past_expiry": 0, "due_0_30": 0, "due_31_60": 0, "due_61_90": 0}
        for row in rows:
            try:
                expires = datetime.fromisoformat(row["expires_at"])
            except ValueError:
                continue
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            days = (expires - now).total_seconds() / 86400
            if days < 0:
                buckets["past_expiry"] += 1
            elif days <= 30:
                buckets["due_0_30"] += 1
            elif days <= 60:
                buckets["due_31_60"] += 1
            elif days <= 90:
                buckets["due_61_90"] += 1
        return buckets

    # ---------- cross-project dashboard queries ----------

    def assessment_cycle_times_days(self) -> list[float]:
        """Days from an assessment's creation to its last update, for every
        assessment currently marked Completed -- an approximation of
        review cycle time (created_at -> completed) using the timestamps
        already tracked, on the assumption a completed assessment isn't
        edited again after completion.
        """
        rows = self._conn.execute(
            "SELECT created_at, updated_at FROM assessments WHERE status = 'completed'"
        ).fetchall()
        durations = []
        for row in rows:
            try:
                created = datetime.fromisoformat(row["created_at"])
                updated = datetime.fromisoformat(row["updated_at"])
            except ValueError:
                continue
            durations.append((updated - created).total_seconds() / 86400)
        return durations

    def architecture_coverage(self, skill_id: str) -> tuple[int, int]:
        """(reviewed, in_scope) project counts for the coverage KPI.
        "In scope" is every project with at least one assessment (per the
        product decision: no separate system registry); "reviewed" is the
        subset of those with at least one successful run of `skill_id`.
        """
        in_scope = self._conn.execute(
            "SELECT COUNT(DISTINCT project_id) c FROM assessments"
        ).fetchone()["c"]
        reviewed = self._conn.execute(
            "SELECT COUNT(DISTINCT runs.project_id) c FROM runs "
            "JOIN assessments ON assessments.project_id = runs.project_id "
            "WHERE runs.skill_id = ? AND runs.status = 'success'",
            (skill_id,),
        ).fetchone()["c"]
        return (reviewed, in_scope)

    def unreviewed_and_stale_projects(self, skill_id: str, *, stale_days: int = 365) -> list[dict]:
        """Projects with an assessment (i.e. in scope) that either have
        never had a successful run of `skill_id`, or whose most recent one
        is older than `stale_days`. One row per project, most urgent
        (never reviewed, then oldest) first.
        """
        projects = self._conn.execute(
            "SELECT DISTINCT projects.id, projects.display_name, projects.kind "
            "FROM projects JOIN assessments ON assessments.project_id = projects.id"
        ).fetchall()

        now = datetime.now(timezone.utc)
        results = []
        for project in projects:
            latest = self._conn.execute(
                "SELECT started_at FROM runs WHERE project_id = ? AND skill_id = ? AND status = 'success' "
                "ORDER BY started_at DESC LIMIT 1",
                (project["id"], skill_id),
            ).fetchone()
            if latest is None:
                results.append(
                    {
                        "project_id": project["id"],
                        "project_display_name": project["display_name"],
                        "project_kind": project["kind"],
                        "state": "never_reviewed",
                        "last_reviewed_at": None,
                        "days_since_review": None,
                    }
                )
                continue
            try:
                started = datetime.fromisoformat(latest["started_at"])
            except ValueError:
                continue
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            days_since = (now - started).total_seconds() / 86400
            if days_since > stale_days:
                results.append(
                    {
                        "project_id": project["id"],
                        "project_display_name": project["display_name"],
                        "project_kind": project["kind"],
                        "state": "stale",
                        "last_reviewed_at": latest["started_at"],
                        "days_since_review": round(days_since),
                    }
                )

        results.sort(
            key=lambda r: (r["state"] != "never_reviewed", -(r["days_since_review"] or 10**9))
        )
        return results

    # ---------- post-build findings (threats a model missed) ----------

    def _row_to_post_build_finding(self, row: sqlite3.Row) -> PostBuildFindingRecord:
        data = dict(row)
        project_display_name = data.pop("display_name", None)
        return PostBuildFindingRecord(project_display_name=project_display_name, **data)

    def create_post_build_finding(
        self,
        *,
        project_id: int,
        title: str,
        discovered_at: str,
        run_id: int | None = None,
        description: str | None = None,
        discovered_by: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO post_build_findings (project_id, run_id, title, description, discovered_by, "
            "discovered_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (project_id, run_id, title, description, discovered_by, discovered_at, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_post_build_finding(self, finding_id: int) -> PostBuildFindingRecord | None:
        row = self._conn.execute(
            "SELECT post_build_findings.*, projects.display_name FROM post_build_findings "
            "JOIN projects ON projects.id = post_build_findings.project_id WHERE post_build_findings.id = ?",
            (finding_id,),
        ).fetchone()
        return self._row_to_post_build_finding(row) if row else None

    def list_post_build_findings(
        self, *, project_id: int | None = None, limit: int = 500
    ) -> list[PostBuildFindingRecord]:
        query = (
            "SELECT post_build_findings.*, projects.display_name FROM post_build_findings "
            "JOIN projects ON projects.id = post_build_findings.project_id WHERE 1=1"
        )
        params: list[object] = []
        if project_id is not None:
            query += " AND post_build_findings.project_id = ?"
            params.append(project_id)
        query += " ORDER BY post_build_findings.discovered_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_post_build_finding(row) for row in rows]

    def delete_post_build_finding(self, finding_id: int) -> None:
        self._conn.execute("DELETE FROM post_build_findings WHERE id = ?", (finding_id,))
        self._conn.commit()

    def post_build_findings_count(self, *, since_days: int | None = None) -> int:
        if since_days is None:
            return self._conn.execute("SELECT COUNT(*) c FROM post_build_findings").fetchone()["c"]
        cutoff = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
        return self._conn.execute(
            "SELECT COUNT(*) c FROM post_build_findings WHERE discovered_at >= ?", (cutoff,)
        ).fetchone()["c"]

    # ---------- threat acceptances (the human loop-back on a threat's disposition) ----------

    def _row_to_threat_acceptance(self, row: sqlite3.Row) -> ThreatAcceptanceRecord:
        data = dict(row)
        project_display_name = data.pop("display_name", None)
        return ThreatAcceptanceRecord(project_display_name=project_display_name, **data)

    def create_threat_acceptance(
        self,
        *,
        project_id: int,
        threat_ref: str,
        title: str,
        justification: str,
        accepted_by: str,
        run_id: int | None = None,
        expires_at: str | None = None,
        status: str = "active",
    ) -> int:
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO threat_acceptances (project_id, run_id, threat_ref, title, justification, "
            "accepted_by, status, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (project_id, run_id, threat_ref, title, justification, accepted_by, status, expires_at, now, now),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_threat_acceptance(self, acceptance_id: int) -> ThreatAcceptanceRecord | None:
        row = self._conn.execute(
            "SELECT threat_acceptances.*, projects.display_name FROM threat_acceptances "
            "JOIN projects ON projects.id = threat_acceptances.project_id WHERE threat_acceptances.id = ?",
            (acceptance_id,),
        ).fetchone()
        return self._row_to_threat_acceptance(row) if row else None

    def list_threat_acceptances(
        self, *, project_id: int | None = None, status: str | None = None, limit: int = 500
    ) -> list[ThreatAcceptanceRecord]:
        query = (
            "SELECT threat_acceptances.*, projects.display_name FROM threat_acceptances "
            "JOIN projects ON projects.id = threat_acceptances.project_id WHERE 1=1"
        )
        params: list[object] = []
        if project_id is not None:
            query += " AND threat_acceptances.project_id = ?"
            params.append(project_id)
        if status is not None:
            query += " AND threat_acceptances.status = ?"
            params.append(status)
        query += " ORDER BY threat_acceptances.created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_threat_acceptance(row) for row in rows]

    def update_threat_acceptance(self, acceptance_id: int, **fields: object) -> None:
        if not fields:
            return
        allowed = {"title", "justification", "accepted_by", "status", "expires_at"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"Unknown threat acceptance field(s): {sorted(unknown)}")
        set_clause = ", ".join(f"{k} = ?" for k in fields) + ", updated_at = ?"
        params = [*fields.values(), _now(), acceptance_id]
        self._conn.execute(f"UPDATE threat_acceptances SET {set_clause} WHERE id = ?", params)  # nosec B608 -- column names from allowed whitelist above
        self._conn.commit()

    def delete_threat_acceptance(self, acceptance_id: int) -> None:
        self._conn.execute("DELETE FROM threat_acceptances WHERE id = ?", (acceptance_id,))
        self._conn.commit()

    # ---------- OSV.dev vulnerability lookups (cache) ----------

    def upsert_osv_lookup(self, *, ecosystem: str, package: str, version: str, vulns: list[dict]) -> None:
        """Caches (or refreshes) one OSV.dev lookup result. `vulns == []` is
        a real, cacheable "queried this and it's clean" result, not a
        missing entry -- see osv.py for the TTL that eventually re-checks
        it rather than trusting "clean" forever.
        """
        now = _now()
        self._conn.execute(
            "INSERT INTO osv_lookups (ecosystem, package, version, vulns_json, queried_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(ecosystem, package, version) DO UPDATE SET vulns_json = excluded.vulns_json, "
            "queried_at = excluded.queried_at",
            (ecosystem, package, version, json.dumps(vulns), now),
        )
        self._conn.commit()

    def osv_lookup_map(self) -> dict[tuple[str, str, str], OsvLookupRecord]:
        """Every cached OSV lookup, keyed by (ecosystem, package, version).
        One full-table read rather than N per-row queries -- this table
        stays small (bounded by distinct dependency triples ever flagged,
        not by run count), matching the "recompute fresh every request"
        philosophy the other dashboards already use for report parsing.
        """
        rows = self._conn.execute("SELECT * FROM osv_lookups").fetchall()
        result = {}
        for row in rows:
            data = dict(row)
            vulns = json.loads(data.pop("vulns_json"))
            data.pop("id", None)
            record = OsvLookupRecord(vulns=vulns, **data)
            result[(record.ecosystem, record.package, record.version)] = record
        return result

    # ---------- SAST findings (persistent per-finding open/closed lifecycle) ----------

    def _row_to_sast_finding(self, row: sqlite3.Row) -> SastFindingRecord:
        data = dict(row)
        project_display_name = data.pop("display_name", None)
        return SastFindingRecord(project_display_name=project_display_name, **data)

    def upsert_sast_finding(
        self,
        *,
        project_id: int,
        fingerprint: str,
        current_ref: str,
        title: str,
        severity: str,
        cwe: str | None,
        owasp: str | None,
        verdict: str | None,
        location_file: str,
        location_line: str | None,
        cvss_vector: str | None,
        cvss_score: float | None,
        run_id: int,
        description: str | None = None,
        recommendation: str | None = None,
    ) -> None:
        """Inserts a newly-seen finding as open, or -- on a conflicting
        (project_id, fingerprint) -- refreshes it from this run's report
        and reopens it if it had been closed. `first_seen_run_id`/
        `first_seen_at` are only ever set on the initial insert: a
        fingerprint that reappears after being closed keeps its original
        first-seen date rather than looking like a brand-new finding.
        """
        now = _now()
        self._conn.execute(
            "INSERT INTO sast_findings (project_id, fingerprint, current_ref, title, severity, cwe, "
            "owasp, verdict, location_file, location_line, cvss_vector, cvss_score, description, "
            "recommendation, status, first_seen_run_id, first_seen_at, last_seen_run_id, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?) "
            "ON CONFLICT(project_id, fingerprint) DO UPDATE SET "
            "current_ref = excluded.current_ref, title = excluded.title, severity = excluded.severity, "
            "cwe = excluded.cwe, owasp = excluded.owasp, verdict = excluded.verdict, "
            "location_file = excluded.location_file, location_line = excluded.location_line, "
            "cvss_vector = excluded.cvss_vector, cvss_score = excluded.cvss_score, "
            "description = excluded.description, recommendation = excluded.recommendation, status = 'open', "
            "last_seen_run_id = excluded.last_seen_run_id, last_seen_at = excluded.last_seen_at, "
            "closed_in_run_id = NULL, closed_at = NULL",
            (
                project_id, fingerprint, current_ref, title, severity, cwe, owasp, verdict,
                location_file, location_line, cvss_vector, cvss_score, description, recommendation,
                run_id, now, run_id, now,
            ),
        )
        self._conn.commit()

    def close_stale_sast_findings(
        self, *, project_id: int, run_id: int, seen_fingerprints: list[str], closed_at: str
    ) -> None:
        """Closes every currently-open finding for this project NOT among
        `seen_fingerprints` -- i.e. whatever this run's Findings Register
        didn't re-report. Called once per successful sast run, after every
        row from that run has been upserted via upsert_sast_finding.
        """
        if seen_fingerprints:
            placeholders = ",".join("?" * len(seen_fingerprints))
            query = (
                "UPDATE sast_findings SET status = 'closed', closed_in_run_id = ?, closed_at = ? "
                f"WHERE project_id = ? AND status = 'open' AND fingerprint NOT IN ({placeholders})"  # nosec B608 -- placeholders are ? binds, not user SQL
            )
            params: list[object] = [run_id, closed_at, project_id, *seen_fingerprints]
        else:
            query = (
                "UPDATE sast_findings SET status = 'closed', closed_in_run_id = ?, closed_at = ? "
                "WHERE project_id = ? AND status = 'open'"
            )
            params = [run_id, closed_at, project_id]
        self._conn.execute(query, params)
        self._conn.commit()

    def list_sast_findings(
        self,
        *,
        project_id: int | None = None,
        status: str | None = None,
        search: str | None = None,
        limit: int = 1000,
    ) -> list[SastFindingRecord]:
        """Backs the SAST dashboard's Open/Closed tabs + search directly
        against this persistent table -- deliberately NOT re-parsing report
        text at read time, unlike every other activity dashboard in this
        app. See sast_findings' schema.sql comment for why this one
        feature needs real state instead of fresh-derived-every-request.
        """
        query = (
            "SELECT sast_findings.*, projects.display_name FROM sast_findings "
            "JOIN projects ON projects.id = sast_findings.project_id WHERE 1=1"
        )
        params: list[object] = []
        if project_id is not None:
            query += " AND sast_findings.project_id = ?"
            params.append(project_id)
        if status is not None:
            query += " AND sast_findings.status = ?"
            params.append(status)
        if search:
            query += (
                " AND (sast_findings.title LIKE ? OR sast_findings.cwe LIKE ? "
                "OR sast_findings.location_file LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like])
        query += " ORDER BY sast_findings.cvss_score DESC, sast_findings.last_seen_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_sast_finding(row) for row in rows]
