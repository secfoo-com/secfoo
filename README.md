# secfoo

<p align="center">
  <a href="https://pypi.org/project/secfoo/"><img src="https://img.shields.io/pypi/v/secfoo" alt="PyPI"></a>
  <a href="https://pypi.org/project/secfoo/"><img src="https://img.shields.io/pypi/dm/secfoo" alt="PyPI downloads"></a>
  <a href="https://github.com/secfoo-com/secfoo/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/secfoo-com/secfoo/ci.yml" alt="CI"></a>
  <a href="https://github.com/secfoo-com/secfoo/blob/main/LICENSE"><img src="https://img.shields.io/github/license/secfoo-com/secfoo" alt="Apache 2.0 license"></a>
</p>

<p align="center">
  Context-based security architectural assessment orchestrator: pick skills, targets, and an agent CLI to run them.
</p>

<p align="center">
  <a href="https://secfoo.com">Website</a> ·
  <a href="https://secfoo.com/docs/index.html#install">Getting Started</a> ·
  <a href="https://secfoo.com/docs/cli.html">CLI Reference</a> ·
  <a href="https://secfoo.com/docs/index.html">Documentation</a>
</p>

Pick one or more security **activities** (see the catalog below), point them
at a **target** (a public GitHub URL, a local directory, plus optional
Confluence links for extra context), choose which coding-agent CLI runs them
(Claude Code, Cursor, Antigravity, or Gemini CLI), and browse every
assessment ever run, across every project, in a local web dashboard.

> This repository is the open-source CLI and local dashboard. secfoo's
> enterprise portal (multi-tenant cloud sync, admin console) is closed-source
> and lives in a separate private repository — `secfoo cloud login` connects
> this CLI to it, but nothing about the portal itself is in this repo.

## Activity catalog

Each activity is a self-contained security engagement with its own report
shape. Run one, or several together — multiple activities execute
concurrently against the same target.

| Activity | Skill ID | What it produces |
|---|---|---|
| Security Architecture Review | `security-architecture-review` | Controls matrix (presence / placement / layering), design-principles verdict, operational & regulatory fit, CSA CCM v4 domain conformance, and a **Design verdict** for milestone gating — plus a program-level dashboard, see below |
| Threat Modeling | `threat-modeling` | Adversary classes, STRIDE (+ LINDDUN when personal data is in scope), attack chains, every threat dispositioned Mitigated/Gap/Accepted, and an explicit **residual risk** statement |
| SAST — Static Code Analysis | `sast` | Code-level findings with taint paths, CWE/OWASP mapping, and illustrative fix diffs |
| SCA — Reachability & Upgrade Triage | `sca-reachability` | Dependency inventory, **reachability verdict** per risk, and a grouped upgrade plan |
| Secret Scanning — Code, Confluence & Docs | `secret-scanning` | Exposed credentials across source, config, git history, and linked Confluence pages, with a rotation-first remediation list |
| Prompt Review | `prompt-review` | LLM prompt, tool-definition, and agent-behavior security review |
| Deployment Readiness | `deployment-readiness` | Production security and operational readiness review |
| Responsible AI Compliance | `responsible-ai-compliance` | Governance, transparency, fairness, and oversight review (drives the dashboard's Responsible AI risk badges) |

### Architecture review vs. threat modeling

These two look adjacent but answer different questions and fail
differently, so secfoo keeps them separate rather than merging them into
one "threat assessment":

- **Security Architecture Review** asks *is this design sound?* It is
  control-centric and evaluative — you judge components, boundaries, and
  topology against secure design principles and compliance baselines. Are
  controls present, correctly placed, and layered? Is least privilege
  enforced by the topology or merely by policy? Does the design fail safe?
  It also covers ground with no attacker at all: recoverability, key
  lifecycle, maintainability, regulatory fit.
- **Threat Modeling** asks *what could go wrong, and who would make it go
  wrong?* It is adversary-centric and generative — enumerate threats from
  assets and trust boundaries, then disposition each as mitigated,
  accepted, or a gap, and state residual risk explicitly.

An architecture review can pass every checklist item and still miss a
threat nobody enumerated. A threat model can list fifty threats and still
miss that the design has no blast-radius containment. Run both.

Adding an activity is a matter of dropping a Markdown file into
[`src/secfoo/skills/definitions/`](src/secfoo/skills/definitions/) — the CLI
choices, the web run form, the dashboard's coverage panel, and the
per-activity pages are all derived from that directory, so there is no
registry to keep in sync.

In the dashboard, the six focused analysis activities each get their own
page under **Analysis** in the sidebar (`/activities/<skill-id>`), showing
which projects have been scanned with that activity, when, and what it
found. Each project's own page mirrors it with an **Activity coverage**
table — including the activities that have *never* been run against it,
since that gap is usually the point.

### Architecture diagrams

Security Architecture Review and Threat Modeling reports include a
[Mermaid](https://mermaid.js.org/) data-flow diagram with one subgraph per
trust zone. Mermaid source is readable as-is, so it always appears in the
report; to render it as a picture in the dashboard, fetch the renderer once:

```bash
secfoo vendor mermaid      # ~3.6MB, stored in ~/.secfoo/vendor/
```

It's not bundled by default because it's an order of magnitude larger than
the rest of secfoo. It's served locally afterwards — the dashboard never
calls out to a CDN while you're reading a report — and rendered with
Mermaid's `securityLevel: "strict"`, since report content originates from
an agent reading a possibly untrusted repository. No outbound access on the
box? Copy the file to `~/.secfoo/vendor/mermaid.min.js` by hand.

### Keeping a scan focused

Vendored copies and unrelated repos checked out inside a project dilute
reports and cost tokens. Exclude them per run or permanently:

```bash
secfoo run --skill sast --exclude vendor/ --exclude some-cloned-repo/
```

```toml
# ~/.secfoo/config.toml — applies to every run
[defaults]
exclude = ["vendor/", "some-cloned-repo/"]
```

Exclusions are always **additive**: `--exclude` adds to `[defaults].exclude`,
which adds to secfoo's built-in list (`node_modules/`, `.git/`, `dist/`, …).
Naming one path can never silently re-enable scanning of the others.

### Security Architecture program dashboard

The Security Architecture Review activity page
(`/activities/security-architecture-review`) is a program-level view on top
of the per-project reports: coverage, exceptions, a findings-disposition
approximation, a **CSA Cloud Controls Matrix (CCM v4)** conformance
heatmap, recurring root causes, and gate-decision (approve / with
conditions / reject) mix — derived from the Design Verdict, CCM Domain
Conformance table, and Standard column the skill's report contract now
produces (v4).

This is deliberately built from what a report can state at review time and
the exceptions you record — not a separate persistent findings-lifecycle
system with manually-updated statuses. A few panels are therefore honest
approximations, not exact tracking:

- **Open findings past due** / **remediated** — no per-finding due date or
  close event exists, so "past due" means a Confirmed-verdict finding
  whose *most recent* review is older than 30 days, and "remediated" means
  the total finding count dropped between a project's two most recent
  reviews (it can't say *which* finding closed).
- **In scope** (for the Coverage % tile) means "has an assessment" — there
  is no separate system registry, so a project secfoo has never heard of
  can't appear as an uncovered denominator.
- **CCM conformance** is domain-level (17 domains), not the ~200
  individual CCM controls — an LLM review scoring every control
  individually each run would cost far more than it's worth. A domain the
  report marks `Not Assessed (process-assured)` (e.g. Human Resources
  Security, usually governed by an external process a codebase can't
  reveal) shows hatched on the heatmap rather than scored.

Reports from before this contract version (or from other skills) simply
show zeros/hatching for panels they have no data for, rather than
guessing.

### Threat Modeling program dashboard

The Threat Modeling activity page (`/activities/threat-modeling`) is the
same kind of program-level view, built on the same ground rules: coverage,
a **per-project STRIDE × asset-class coverage matrix** (empty cells are
the signal — a blank category was never exercised on *that* project, not
proven safe; kept per-project rather than aggregated, since averaging
across projects would blend one project's real gap into another's totals
and hide which system actually has it), threat disposition
(mitigated-and-tested / mitigated-untested / accepted / transferred / open
/ past due), recorded risk acceptances, models needing rework, recurring
**threat archetypes** across every model run, a model-depth mix (Full /
Feature-level / Lightweight), threats found post-build, and falsified
assumptions — all derived from the Threat Register, Assumptions, and
Executive Summary sections the skill's report contract now produces (v3).

The page shows only this specialized dashboard, not the generic
per-activity stat-card block (Projects covered / Runs / Total findings /
Critical + High) or diagram gallery every other activity page gets —
both would just duplicate tiles this dashboard already covers more
specifically.

Approximations, called out the same way as the architecture dashboard:

- **Open threats past due** uses the same 30-day-since-last-model proxy as
  Security Architecture Review's "past due" tile, for the same reason (no
  per-threat due date exists).
- **Mitigated but untested** means the Threat Register's Disposition is
  `Mitigated` but its Test Reference column is `none` — a claimed
  mitigation the model didn't verify with an actual test.
- **Models needing rework** collapses "stale (boundary moved / new
  integration / new data class)" and "superseded by a design change" into
  the one structural signal actually derivable from report text: a
  different trust-boundary count between a project's two most recent
  models. It's sorted by total findings count as a criticality proxy,
  since no separate criticality field or system registry exists.
- **Accepted threats** (the flat, report-derived list) reflects the
  model's own Disposition call, with no named human owner — see
  **Recorded risk acceptances** below for the actual loop-back.
- **Recurring threat patterns** is exact-string aggregation over the
  Threat Register's **Archetype** column (a short, deliberately reusable
  phrase like "Unauthenticated internal service call" the skill is
  instructed to reuse verbatim for the same underlying pattern) — not NLP
  clustering.
- **Threats found post-build** is inherently not derivable from any
  report — a model can't know what it missed — so it's recorded by hand
  with `secfoo miss`, the same rationale as `secfoo exception`.

**Accepting a threat.** A report's own `Accepted` disposition is just the
model's judgment call at review time — there's no button in the report
that a human actually clicked. `secfoo accept` is that loop-back: a named
owner and justification for accepting one specific threat, recorded
independently of the report and re-shown on every future dashboard load
even after the model re-runs and its Threat Register changes:

```bash
secfoo accept create --project . --threat-id T4 --title "Legacy endpoint risk" \
  --justification "Endpoint is being decommissioned next quarter" \
  --accepted-by "Jane Doe" --expires-at 2026-12-01

secfoo accept list --status active
secfoo accept update 1 --status revoked
secfoo accept delete 1
```

### Exceptions

A risk acceptance against a project, with an expiry the dashboard tracks:

```bash
secfoo exception create --project . --title "Legacy auth exemption" \
  --justification "Migration in progress, tracked in JIRA-123" \
  --granted-by "Jane Doe" --expires-at 2026-09-01 --control IAM

secfoo exception list --status active
secfoo exception update 1 --status revoked
```

`--control` is free text — typically a CCM domain code (`IAM`, `CEK`, …) or
a standard clause (`"SOC 2 CC6.1"`) — surfaced on the dashboard's exception
aging panel (30/60/90-day buckets, past-expiry highlighted).

### Post-build findings

A threat an earlier model missed — found by an incident, a pen test, or a
later scan — recorded by hand since nothing in a report can know what it
missed:

```bash
secfoo miss create --project . --title "SSRF via webhook URL" \
  --discovered-at 2026-08-01 --discovered-by "Pen test Q3" \
  --description "Webhook target URL wasn't validated against internal IP ranges" \
  --run <run-uuid>   # optional: the threat model that should have caught it

secfoo miss list
secfoo miss show 1
secfoo miss delete 1
```

Feeds the Threat Modeling dashboard's "Threats found post-build" panel
(recent-90-day trend + all-time count).

### Secret Scanning program dashboard

The Secret Scanning activity page (`/activities/secret-scanning`) is a
program-level view of exposed credentials across every project: a findings
funnel emphasizing **Looks live** credentials (rotate immediately), a
severity breakdown, a source breakdown (code / config / version-control
history / documentation), and a cross-project findings register with
evidence, exposure analysis, and remediation text pulled from each report.

Like SCA and Threat Modeling, this dashboard is derived fresh from report
text on every request — there is no persistent per-finding lifecycle.
Findings link to a detail page keyed by `(project, finding ID, type,
location)` so duplicate rows in a report remain addressable.

## Install

Pick whichever fits how you work — they're all the same tool underneath.

```bash
# PyPI (needs Python 3.10+)
pip install secfoo

# npm (no Python needed -- installs a real standalone binary, not a
# Python wrapper; see the "Distribution" section below for why)
npm install -g @rakfortltd/secfoo

# Universal installer script (macOS/Linux, no Python or Node needed)
curl -fsSL https://raw.githubusercontent.com/rakfortltd/secfoo/main/install.sh | sh

# Windows (PowerShell), no Python or Node needed
irm https://raw.githubusercontent.com/rakfortltd/secfoo/main/install.ps1 | iex

# Docker (nothing installed on the host at all)
docker run --rm ghcr.io/rakfortltd/secfoo --help

# Or grab a binary directly for your platform from the Releases page:
# https://github.com/rakfortltd/secfoo/releases
```

Developing on this repo instead? `pip install -e ".[dev]"`.

## Usage

```bash
# Run a skill against the current directory with Claude Code
secfoo run --skill security-architecture-review --agent claude

# Run multiple skills against a GitHub repo, with Confluence context
secfoo run \
  --skill security-architecture-review --skill threat-modeling \
  --target https://github.com/org/repo \
  --confluence https://yourcompany.atlassian.net/wiki/spaces/SEC/pages/123 \
  --agent agent

# See what's on PATH
secfoo agents

# List past runs
secfoo list

# View a single run's report in the terminal
secfoo show <run-uuid>

# Launch the local dashboard
secfoo serve
```

## Assessments

An **assessment** is a case-file container -- an Application ID / Security
Assessment Request, a review status (Ready → In Progress → Completed →
Blocked), and one or more attached runs and/or uploaded files (e.g. an
AI-BOM inventory). Runs can attach to a case file at creation time; the
dashboard's Assessments, Third-Party, and Responsible AI pages are all
built on top of this.

```bash
# Create a case file
secfoo assessment create --project https://github.com/org/vendor-app \
  --type third-party --app-id APP-042 --sar SAR-2026-0007 --reviewer "Jane Doe"

# Attach a skill run to it directly
secfoo run --skill security-architecture-review --agent claude --assessment 1

# Upload an AI-BOM file (parsed automatically -- see secfoo/aibom.py for the schema)
secfoo assessment upload 1 ai-bom.json

secfoo assessment list --type third-party --status in_progress
secfoo assessment show 1
secfoo assessment update 1 --status completed
secfoo assessment delete 1
```

Responsible AI risk badges in the dashboard are derived automatically from
an assessment's attached Responsible AI Compliance run (its `Overall risk
rating` line) rather than set manually, and stay "provisional" until the
assessment's own status is marked Completed.

## Configuration (`~/.secfoo/config.toml`)

Set default agent/depth/timeout and MCP servers (e.g. Confluence/Jira via
Atlassian's Rovo MCP server) once, instead of passing flags every time or
wiring each agent CLI separately.

```bash
secfoo config init      # writes a starter ~/.secfoo/config.toml
```

```toml
[defaults]
agent = "claude"
depth = "quick"
# Vendored copies / unrelated repos checked out inside a project. Added to
# the built-in exclusions (node_modules/, .git/, ...), never replacing them.
exclude = ["vendor/", "some-cloned-repo/"]

[[mcp_servers]]
name = "Atlassian-Rovo-MCP"
command = "npx"
args = ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"]
```

CLI flags always override `[defaults]`. See
[`src/secfoo/config.example.toml`](src/secfoo/config.example.toml) for the
full reference, including remote HTTP/SSE servers.

How MCP servers reach each agent varies by what its CLI actually supports:

| Agent | Mechanism |
|---|---|
| `claude` | Automatic on every `secfoo run` (`--mcp-config`, scoped to that invocation only — your global Claude config is never touched) |
| `gemini`, `agent` (Cursor) | Run `secfoo mcp sync --agent <agent>` once to register persistently in that tool's own config |
| `agy` (Antigravity) | Not supported yet — its CLI has no MCP configuration mechanism as of this writing |

```bash
secfoo mcp list                    # show what's configured
secfoo mcp sync --agent gemini     # register into gemini's own config
```

## Distribution

Every install channel above is built on the same foundation: standalone,
self-contained binaries (bundled Python interpreter + all dependencies —
nothing needs to be pre-installed) for macOS (arm64/x64), Linux
(x64/arm64), and Windows (x64), built by CI (`.github/workflows/release.yml`)
on every `vX.Y.Z` tag push and attached to the matching GitHub Release
along with a `SHA256SUMS` file.

- **pip**: the "real"/native path — a normal Python sdist+wheel, published
  to PyPI as usual.
- **npm**: `@rakfortltd/secfoo` is a tiny meta-package whose
  `optionalDependencies` are 5 per-platform packages
  (`@rakfortltd/secfoo-darwin-arm64`, etc.), each containing just that
  platform's binary. npm installs only the one matching your machine —
  no `postinstall` network fetch, which is what makes this safe to use
  behind a locked-down corporate npm/Artifactory mirror.
- **install.sh / install.ps1**: detect your OS/arch, download the matching
  binary from the latest GitHub Release, verify its SHA256, install it.
- **Docker**: `ghcr.io/rakfortltd/secfoo`, built from the PyPI package on
  a slim Python base (simplest, most robust route for a container image —
  no cross-platform concern since the image itself is the platform).
  **Note**: none of the 4 agent CLIs (claude, cursor, antigravity, gemini)
  are installed in this image, so `secfoo run` needs one made available on
  `PATH` inside the container yourself (e.g. a custom image built `FROM`
  this one, or a volume/bind mount) to actually execute a skill — without
  that it's still useful standalone for `secfoo serve`/`list`/`show`
  against a mounted `~/.secfoo` store from a host-run assessment. Also
  bind to all interfaces explicitly for `serve` to be reachable through
  Docker's port mapping (the default is `127.0.0.1`, which isn't):

  ```bash
  docker run --rm -p 8787:8787 -v ~/.secfoo:/root/.secfoo \
    ghcr.io/rakfortltd/secfoo serve --host 0.0.0.0 --port 8787
  ```

Homebrew is a planned follow-up (a tap formula in a separate
`rakfortltd/homebrew-tap` repo) — not built yet.

See [`design-system/README.md`](design-system/README.md) for the design
system used by the dashboard.
