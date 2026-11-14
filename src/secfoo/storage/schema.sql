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
    model             TEXT,                  -- requested model; NULL = CLI default/unknown
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
    -- AI spend reported by the agent (see AgentAdapter.extract_usage).
    -- NULL means the agent doesn't report it, not zero.
    input_tokens      INTEGER,
    output_tokens     INTEGER,
    cost_usd          REAL,
    -- Set once `secfoo cloud` has pushed this run to the enterprise
    -- portal. NULL means never synced (offline, or no `cloud login` yet).
    cloud_synced_at   TEXT,
    -- Memory Bank: git HEAD SHA at scan time; enables future incremental diff-based rescans.
    target_commit     TEXT,
    -- 1 if the agent had the secfoo-memory pattern tools wired in for this
    -- run, 0 if not, NULL for runs from before this column existed. Lets
    -- evaluation compare memory-on vs memory-off runs of the same target.
    memory_enabled    INTEGER,
    -- Memory Bank: JSON list of the paths an incremental scan covered (files
    -- sent plus files deleted). NULL means a full scan. Findings lifecycle
    -- only closes findings inside this set for an incremental run.
    scan_scope        TEXT,
    -- #79: which definition text produced this report. Custom skills change
    -- over time, so version alone isn't enough: sha256 is a hash of the
    -- skill's Markdown file. NULL for runs from before these existed.
    skill_version     INTEGER,
    skill_source      TEXT,   -- builtin / user
    skill_sha256      TEXT
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
-- (report/sast.py:fingerprint_for_row): skill + CWE + path + optional
-- code-region hash from the repo at scan time. See report/sast.py.
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
    code_region_hash  TEXT,
    -- Stack + code-free construct description (see stack.py and the
    -- `**Construct:**` contract field): the fields that make a finding
    -- comparable across repos, for `secfoo findings export`.
    language          TEXT,
    framework         TEXT,
    construct         TEXT,
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
    review_status     TEXT,   -- reviewer sign-off: confirmed / false_positive / accepted_risk, NULL = awaiting
    review_note       TEXT,
    reviewed_by       TEXT,
    reviewed_at       TEXT,
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_sast_findings_project_status ON sast_findings(project_id, status);


-- SCA (sca-reachability) per-finding lifecycle -- same open/closed model
-- as sast_findings, keyed by report/sca.py:fingerprint_for_row (ecosystem
-- + package [+ advisory ID]), never by the model's issue prose.
CREATE TABLE IF NOT EXISTS sca_findings (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id            INTEGER NOT NULL REFERENCES projects(id),
    fingerprint           TEXT NOT NULL,
    current_ref           TEXT NOT NULL,   -- this run's Dn id, display only
    package               TEXT NOT NULL,
    version               TEXT,
    ecosystem             TEXT,
    issue                 TEXT,
    severity              TEXT NOT NULL,
    reachability          TEXT,
    fixed_in              TEXT,
    cve                   TEXT,            -- as the report wrote it ("unverified" or an ID)
    reachability_evidence TEXT,
    recommendation        TEXT,
    language              TEXT,
    framework             TEXT,
    construct             TEXT,
    status                TEXT NOT NULL CHECK (status IN ('open','closed')),
    first_seen_run_id     INTEGER NOT NULL REFERENCES runs(id),
    first_seen_at         TEXT NOT NULL,
    last_seen_run_id      INTEGER NOT NULL REFERENCES runs(id),
    last_seen_at          TEXT NOT NULL,
    closed_in_run_id      INTEGER REFERENCES runs(id),
    closed_at             TEXT,
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_sca_findings_project_status ON sca_findings(project_id, status);

-- Secret-scanning per-finding lifecycle. `evidence` is re-redacted to a
-- few leading characters before it is stored (report/secret_scanning.py:
-- redact_evidence) -- this table must never become a copy of the secrets
-- it tracks.
CREATE TABLE IF NOT EXISTS secret_findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id),
    fingerprint       TEXT NOT NULL,
    current_ref       TEXT NOT NULL,   -- this run's Sn id, display only
    secret_type       TEXT NOT NULL,
    location_file     TEXT NOT NULL,
    location_line     TEXT,
    code_region_hash  TEXT,
    source            TEXT,            -- code / config / history / docs
    validity          TEXT,            -- Looks live / Unclear / Placeholder
    severity          TEXT NOT NULL,
    evidence          TEXT,
    exposure          TEXT,
    remediation       TEXT,
    language          TEXT,
    framework         TEXT,
    construct         TEXT,
    status            TEXT NOT NULL CHECK (status IN ('open','closed')),
    first_seen_run_id INTEGER NOT NULL REFERENCES runs(id),
    first_seen_at     TEXT NOT NULL,
    last_seen_run_id  INTEGER NOT NULL REFERENCES runs(id),
    last_seen_at      TEXT NOT NULL,
    closed_in_run_id  INTEGER REFERENCES runs(id),
    closed_at         TEXT,
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_secret_findings_project_status ON secret_findings(project_id, status);

-- Runtime evidence for SCA findings (#51 / #53): what a probe, sensor or
-- imported coverage file observed in a running app. Written only by
-- runtime/evidence.py (`secfoo runtime ingest`, later the live API in #66),
-- which validates every line first. Never holds argument values, request
-- bodies, concrete URLs or user identity -- see the design rules in #51.
--
-- One row per observation session (a process run, a coverage file).
-- `session_uuid` is the producer's own id, so re-ingesting the same file
-- updates rows instead of adding duplicates.
CREATE TABLE IF NOT EXISTS runtime_sessions (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id             INTEGER NOT NULL REFERENCES projects(id),
    session_uuid           TEXT NOT NULL,
    language               TEXT NOT NULL,   -- python / node / jvm / dotnet / go / rust / ruby / php / native
    runtime                TEXT,            -- runtime version, e.g. "3.12.4"
    source                 TEXT NOT NULL CHECK (source IN ('sensor','coverage')),
    app                    TEXT,
    env                    TEXT,
    instance               TEXT,
    sensor_version         TEXT,
    started_at             TEXT NOT NULL,
    ended_at               TEXT,
    app_functions_total    INTEGER,         -- with _executed, the coverage behind any "not observed"
    app_functions_executed INTEGER,
    ingested_at            TEXT NOT NULL,
    UNIQUE (project_id, session_uuid)
);

-- A watched vulnerable symbol (or package, for package-granularity
-- watchlist entries) seen during a session, aggregated per route. `route`
-- is a template ("POST /upload") or job:<name> / startup / unknown, never
-- a concrete URL; '' when the producer has no request context.
CREATE TABLE IF NOT EXISTS runtime_evidence (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id          INTEGER NOT NULL REFERENCES projects(id),
    session_id          INTEGER NOT NULL REFERENCES runtime_sessions(id),
    finding_fingerprint TEXT NOT NULL,
    symbol              TEXT NOT NULL,
    route               TEXT NOT NULL DEFAULT '',
    auth                TEXT CHECK (auth IS NULL OR auth IN ('anonymous','authenticated')),
    count               INTEGER NOT NULL CHECK (count > 0),
    first_seen          TEXT,
    last_seen           TEXT,
    entry_frame         TEXT,            -- file:line, app frames only
    stack_sample        TEXT,            -- JSON array of file:line frames, never locals or arguments
    FOREIGN KEY (project_id, finding_fingerprint) REFERENCES sca_findings(project_id, fingerprint),
    UNIQUE (session_id, finding_fingerprint, symbol, route)
);

CREATE INDEX IF NOT EXISTS idx_runtime_evidence_finding ON runtime_evidence(project_id, finding_fingerprint);

-- Packages loaded in a running process (#68's inventory), per session, so
-- "Loaded" can be shown and version drift against the scanned lockfile
-- detected.
CREATE TABLE IF NOT EXISTS runtime_packages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id),
    session_id  INTEGER NOT NULL REFERENCES runtime_sessions(id),
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    path        TEXT,
    first_seen  TEXT,
    UNIQUE (session_id, ecosystem, package, version)
);

CREATE INDEX IF NOT EXISTS idx_runtime_packages_project ON runtime_packages(project_id, ecosystem, package);

-- #66: API keys a self-hosted `secfoo serve` issues for runtime sensors and
-- the CLI (`secfoo serve key create`). Only a SHA-256 of the key is stored;
-- the key itself is shown once, at creation. `project_id` NULL = every
-- project on this server; `scope` 'runtime' = runtime endpoints only.
CREATE TABLE IF NOT EXISTS runtime_api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    key_prefix    TEXT NOT NULL,            -- first characters, for `key list` only
    key_hash      TEXT NOT NULL UNIQUE,
    scope         TEXT NOT NULL CHECK (scope IN ('all','runtime')),
    project_id    INTEGER REFERENCES projects(id),
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT
);

-- #66: sensors register on their first heartbeat; the runtime page (#72)
-- lists them. `dropped_total` sums the events sensors reported dropping.
CREATE TABLE IF NOT EXISTS runtime_sensors (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL REFERENCES projects(id),
    sensor_id         TEXT NOT NULL,
    version           TEXT,
    app               TEXT,
    env               TEXT,
    instances         INTEGER,
    dropped_total     INTEGER NOT NULL DEFAULT 0,
    first_seen_at     TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    UNIQUE (project_id, sensor_id)
);

-- #68: findings raised from what production actually loaded, not from a
-- scan: an advisory against a version that differs from the scanned one
-- (drift), against a package no scanned manifest listed (unscanned), or a
-- new advisory published against a version that is running now. Not in
-- sca_findings because no scan run produced them.
CREATE TABLE IF NOT EXISTS runtime_findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL REFERENCES projects(id),
    kind           TEXT NOT NULL CHECK (kind IN ('drift','unscanned','new_advisory')),
    ecosystem      TEXT NOT NULL,
    package        TEXT NOT NULL,
    version        TEXT NOT NULL,
    advisory       TEXT NOT NULL,
    scanned_versions TEXT,           -- JSON list; empty for unscanned
    apps           TEXT,             -- JSON list of "app/env" running it
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    UNIQUE (project_id, kind, ecosystem, package, version, advisory)
);
