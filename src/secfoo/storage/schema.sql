CREATE TABLE IF NOT EXISTS projects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier    TEXT NOT NULL UNIQUE,      -- resolved local path OR github URL
    display_name  TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('local','github')),
    first_seen_at TEXT NOT NULL,
    last_run_at   TEXT NOT NULL
);

-- A case-file container that one or more runs (and/or manually uploaded
-- files) attach to. Independent of runs: an assessment can exist before any
-- skill has been run against it.
CREATE TABLE IF NOT EXISTS assessments (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id       INTEGER NOT NULL REFERENCES projects(id),
    assessment_type  TEXT NOT NULL CHECK (assessment_type IN ('internal','third_party')),
    status           TEXT NOT NULL CHECK (status IN ('ready','in_progress','completed','blocked')),
    application_id   TEXT,
    sar_number       TEXT,   -- Security Assessment Request number
    reviewer         TEXT,
    review_date      TEXT,
    notes            TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    -- Stable cross-machine identity: the local autoincrement `id` only
    -- means something within this one SQLite file, so it can't be the
    -- correlation key when a run pushes to a shared portal tenant DB.
    -- Generated once at creation (see RunRepository.create_assessment)
    -- and carried in the cloud sync payload -- see cloud.py's docstring.
    -- Not declared UNIQUE here: SQLite's ALTER TABLE ADD COLUMN can't add
    -- a UNIQUE constraint for existing installs migrating in this column,
    -- so uniqueness is enforced by a separate index instead (see
    -- schema_indexes.sql), consistently for both a fresh CREATE TABLE and
    -- a migrated one.
    assessment_uuid  TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uuid          TEXT NOT NULL UNIQUE,
    project_id        INTEGER NOT NULL REFERENCES projects(id),
    assessment_id     INTEGER REFERENCES assessments(id),
    skill_id          TEXT NOT NULL,
    skill_name        TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    confluence_urls   TEXT NOT NULL DEFAULT '[]',
    status            TEXT NOT NULL CHECK (status IN
                          ('pending','running','success','failed','timeout','binary_not_found')),
    exit_code         INTEGER,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    duration_seconds  REAL,
    report_path       TEXT,
    prompt_path       TEXT,
    stderr_excerpt    TEXT,
    -- Parsed from the report's `### [SEVERITY] ...` finding headings right
    -- after a run completes (secfoo/report/severity.py). secfoo's own
    -- skills only ever emit high/medium/low; critical/info stay 0 for
    -- secfoo-generated runs but exist so the dashboard's 5-tier severity
    -- scale isn't artificially limited by the skill layer.
    critical_count    INTEGER NOT NULL DEFAULT 0,
    high_count        INTEGER NOT NULL DEFAULT 0,
    medium_count      INTEGER NOT NULL DEFAULT 0,
    low_count         INTEGER NOT NULL DEFAULT 0,
    info_count        INTEGER NOT NULL DEFAULT 0,
    -- Set once `secfoo cloud` has pushed this run to the enterprise
    -- portal. NULL means never synced (offline, or no `cloud login` yet).
    cloud_synced_at   TEXT
);

-- Files manually uploaded to an assessment (AI-BOM inventories, or other
-- reference material). AI-BOM uploads additionally get parsed into
-- ai_bom_items below.
CREATE TABLE IF NOT EXISTS assessment_attachments (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id    INTEGER NOT NULL REFERENCES assessments(id),
    file_path        TEXT NOT NULL,        -- ~/.secfoo/attachments/<assessment_id>/<filename>
    original_name    TEXT NOT NULL,
    attachment_kind  TEXT NOT NULL CHECK (attachment_kind IN ('ai_bom','report','other','vendor_doc')),
    uploaded_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_bom_items (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    attachment_id    INTEGER NOT NULL REFERENCES assessment_attachments(id),
    kind             TEXT NOT NULL CHECK (kind IN ('model','tool')),
    name             TEXT NOT NULL,
    provider_or_type TEXT,
    version          TEXT,
    purpose          TEXT
);

-- A risk acceptance / waiver granted against a project (optionally scoped
-- to a specific assessment and/or CCM domain). Distinct from a finding's
-- report-time Verdict: an exception is a human decision made outside any
-- single review, with its own expiry the dashboard tracks independently.
CREATE TABLE IF NOT EXISTS exceptions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id          INTEGER NOT NULL REFERENCES projects(id),
    assessment_id       INTEGER REFERENCES assessments(id),
    title               TEXT NOT NULL,
    standard_or_control TEXT,   -- free text, e.g. a CCM domain code or internal standard name
    justification       TEXT NOT NULL,
    granted_by          TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('active','revoked')) DEFAULT 'active',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exceptions_project_id ON exceptions(project_id);
CREATE INDEX IF NOT EXISTS idx_exceptions_expires_at ON exceptions(expires_at);

-- A threat discovered post-build (incident, pen test, later scan) that an
-- earlier threat model should have caught but didn't. Inherently not
-- derivable from any report -- a model can't know what it missed, so this
-- is recorded by hand, same rationale as exceptions.
CREATE TABLE IF NOT EXISTS post_build_findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL REFERENCES projects(id),
    run_id         INTEGER REFERENCES runs(id),   -- the threat-modeling run that missed it, if known
    title          TEXT NOT NULL,
    description    TEXT,
    discovered_by  TEXT,
    discovered_at  TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_post_build_findings_project_id ON post_build_findings(project_id);
CREATE INDEX IF NOT EXISTS idx_post_build_findings_discovered_at ON post_build_findings(discovered_at);

-- A human-recorded risk acceptance for one specific threat in a threat
-- model's Threat Register -- the loop-back a person actually uses to
-- accept a threat, with a named owner and justification, independently of
-- whatever Disposition the LLM wrote into the report text. Same rationale
-- as `exceptions` for Security Architecture Review findings: report text
-- alone can't carry a human accountability trail.
CREATE TABLE IF NOT EXISTS threat_acceptances (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL REFERENCES projects(id),
    run_id         INTEGER REFERENCES runs(id),   -- the run whose Threat Register this threat came from, if known
    threat_ref     TEXT NOT NULL,   -- the Threat Register row ID from the report, e.g. "T4"
    title          TEXT NOT NULL,
    justification  TEXT NOT NULL,
    accepted_by    TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('active','revoked')) DEFAULT 'active',
    expires_at     TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_acceptances_project_id ON threat_acceptances(project_id);
CREATE INDEX IF NOT EXISTS idx_threat_acceptances_status ON threat_acceptances(status);

-- Cached OSV.dev vulnerability lookups keyed by the exact (ecosystem,
-- package, version) triple an SCA report's Dependency Inventory / Risk
-- Register rows carry, once translated to OSV's own ecosystem vocabulary.
-- Populated best-effort right after a sca-reachability run completes
-- (runner.py's _try_osv_enrich) and topped up, capped and best-effort, by
-- the SCA dashboard builder for whatever's still missing. This is real
-- external data (OSV's public, free, no-auth database) enriching what the
-- LLM report identified -- never a substitute for the LLM inventing a CVE
-- ID itself, which the SCA skill's prompt contract explicitly forbids.
CREATE TABLE IF NOT EXISTS osv_lookups (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem     TEXT NOT NULL,   -- OSV's own identifier (PyPI, npm, Maven, ...), never the report's free-text value
    package       TEXT NOT NULL,
    version       TEXT NOT NULL,
    vulns_json    TEXT NOT NULL,   -- raw OSV `vulns` array, json-encoded; "[]" is a real cached "queried, clean" result
    queried_at    TEXT NOT NULL,
    UNIQUE (ecosystem, package, version)
);

CREATE INDEX IF NOT EXISTS idx_osv_lookups_eco_pkg_ver ON osv_lookups(ecosystem, package, version);

-- Persistent per-finding SAST lifecycle -- deliberately NOT re-derived
-- fresh from report text on every request, unlike every other dashboard in
-- this app. "Is this specific finding still there, or did it get fixed" is
-- a cross-run question a single report can't answer in isolation, so it
-- needs real state. Matched across runs by `fingerprint`
-- (report/sast.py:fingerprint_for_row) -- CWE + file path, deliberately NOT
-- title or line number, both of which drift between runs even when the
-- underlying bug hasn't changed. See report/sast.py's module docstring for
-- the known failure modes of this approximation.
CREATE TABLE IF NOT EXISTS sast_findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id),
    fingerprint       TEXT NOT NULL,
    current_ref       TEXT NOT NULL,   -- this run's Fn id, display only, not identity
    title             TEXT NOT NULL,
    severity          TEXT NOT NULL,
    cwe               TEXT,
    owasp             TEXT,
    verdict           TEXT,
    location_file     TEXT NOT NULL,
    location_line     TEXT,
    cvss_vector       TEXT,
    cvss_score        REAL,
    description       TEXT,   -- the report's own Detailed Findings narrative, refreshed each run
    recommendation    TEXT,
    status            TEXT NOT NULL CHECK (status IN ('open','closed')),
    first_seen_run_id INTEGER NOT NULL REFERENCES runs(id),
    first_seen_at     TEXT NOT NULL,
    last_seen_run_id  INTEGER NOT NULL REFERENCES runs(id),
    last_seen_at      TEXT NOT NULL,
    closed_in_run_id  INTEGER REFERENCES runs(id),
    closed_at         TEXT,
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_sast_findings_project_status ON sast_findings(project_id, status);

