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

## Quick Start

Requires Python 3.10+ for `pip install` — or skip Python entirely with
npm, a standalone binary, or Docker (see [Install](#install) below).

```bash
pip install secfoo
secfoo run --skill security-architecture-review --agent claude
```

You'll need an agent CLI already installed and authenticated — Claude
Code, Cursor, Antigravity, or Gemini CLI (`--agent claude|agent|agy|gemini`).
On a real terminal, that first run prompts for a project name and
application ID, then browse every result in the dashboard:

```bash
secfoo run --skill sast --skill threat-modeling \
  --target https://github.com/org/repo --agent claude
secfoo serve
```

See [Getting Started](https://secfoo.com/docs/index.html#quickstart) or
the [CLI reference](https://secfoo.com/docs/cli.html) for more.

## What can you do with secfoo?

- **Review architecture and threat-model a system** against secure
  design principles, STRIDE/LINDDUN, and CSA CCM v4 domain conformance
- **Find code and dependency vulnerabilities** — SAST and SCA reachability
  triage, tracked as an Open/Closed Findings register across rescans, not
  just a one-off report
- **Catch exposed credentials** across source, config, git history, and
  linked Confluence pages
- **Review LLM prompts and agent tool definitions** for injection and
  over-permissioning risk
- **Track third-party/vendor risk** with AI-BOM inventories and a
  dedicated third-party review workflow
- **Run it in CI**, non-interactively, with the same commands you'd use
  locally
- **Browse every assessment across every project** in a local dashboard,
  or sync to your org's enterprise portal

## Why secfoo?

- **Agent-native, not another parser**: a skill is a structured prompt,
  not a bespoke rules engine — secfoo hands your existing coding-agent
  CLI a brief and a target and lets it actually read the code, the way
  a human reviewer would.
- **Local-first**: `secfoo serve` and every run stay on your machine
  unless you explicitly connect `secfoo cloud login` to your org's portal.
- **One case file per system**: assessments consolidate repeat runs
  under the same application ID instead of fragmenting into a new
  record every rescan.
- **Concurrent by default**: multiple `--skill` flags run at the same
  time, not one after another.
- **Bring your own agent**: Claude Code, Cursor, Antigravity, or Gemini
  CLI — pick whichever you already use and trust.
- **Open source CLI**: Apache-2.0 licensed.

## Activity catalog

| Activity | Skill ID |
|---|---|
| Security Architecture Review | `security-architecture-review` |
| Threat Modeling | `threat-modeling` |
| SAST — Static Code Analysis | `sast` |
| SCA — Reachability & Upgrade Triage | `sca-reachability` |
| Secret Scanning — Code, Confluence & Docs | `secret-scanning` |
| Prompt Review | `prompt-review` |
| Deployment Readiness | `deployment-readiness` |
| Responsible AI Compliance | `responsible-ai-compliance` |

Run one, or several together — multiple `--skill` flags execute
concurrently against the same target. Each has its own report shape and
program-level dashboard; see [docs/REFERENCE.md](docs/REFERENCE.md) for
what each one actually produces, plus assessments, configuration, and
install/distribution details.

## Install

```bash
pip install secfoo               # PyPI, needs Python 3.10+
npm install -g @rakfortltd/secfoo    # npm, no Python needed
docker run --rm ghcr.io/rakfortltd/secfoo --help
```

Also available via a universal install script (macOS/Linux/Windows) and
as standalone platform binaries — see
[docs/REFERENCE.md#install](docs/REFERENCE.md#install) for every channel.
Developing on this repo instead? `pip install -e ".[dev]"`.

## Learn More

- [docs/REFERENCE.md](docs/REFERENCE.md) — full activity catalog, dashboards, assessments, configuration, distribution
- [Getting Started](https://secfoo.com/docs/index.html#quickstart)
- [Full Documentation](https://secfoo.com/docs/index.html)
- [CLI Reference](https://secfoo.com/docs/cli.html)
- [Running an assessment](https://secfoo.com/docs/guide-running-an-assessment.html)
- [Excluding paths from a scan](https://secfoo.com/docs/guide-excluding-paths.html)
- [Rendering architecture diagrams](https://secfoo.com/docs/guide-architecture-diagrams.html)
- [Connecting agent CLIs (MCP)](https://secfoo.com/docs/guide-connecting-mcp.html)
- [Editions & pricing](https://secfoo.com/editions.html)

## Contributing

We welcome contributions — see [CONTRIBUTING.md](CONTRIBUTING.md) to get
started, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community
expectations. Found a security issue? See [SECURITY.md](SECURITY.md)
instead of opening a public issue.
