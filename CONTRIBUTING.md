# Contributing to secfoo

Thanks for considering a contribution. This is the open-source CLI and
local dashboard; the enterprise portal (cloud sync, multi-tenant admin)
is closed-source and out of scope here.

## Development setup

```sh
git clone https://github.com/secfoo-com/secfoo.git
cd secfoo
pip install -e ".[dev]"
secfoo vendor mermaid   # optional: only needed to test diagram rendering
```

Requires Python 3.10+.

## Running the tests

```sh
pytest tests
ruff check .
```

CI runs both on every push and PR, on Python 3.10 and 3.12.

## Adding or changing a skill

Skills live under `src/secfoo/skills/definitions/*.md` as a prompt
template with YAML frontmatter (`id`, `name`, `description`,
`short_name`, `version`). If you're adding a skill that needs its own
dashboard (like SAST's Open/Closed Findings register), look at
`src/secfoo/web/sast_dashboard.py` and its `activities/sast_*.html`
templates as the reference shape — most skills don't need this and are
fine with the generic activity page (`activities/detail.html`).

## Adding or changing an agent adapter

Agent adapters live under `src/secfoo/agents/*.py`. Each one subclasses
`AgentAdapter` (`src/secfoo/agents/base.py`), which owns the shared
subprocess/timeout/process-tree-kill contract, so a new adapter only
needs to supply:

- `name` / `binary` class vars, and `default_timeout_seconds` if the
  1800s default doesn't fit
- `build_command(prompt, *, workdir)` — the argv to invoke the CLI
  non-interactively
- `extract_report(stdout)` — optional, only for a CLI that wraps its
  answer in a JSON envelope rather than printing the report directly
- `extract_cost(stdout)` — optional, only if the CLI itself reports a USD
  spend figure (e.g. Claude Code's `total_cost_usd` in `--output-format
  json`; see `ClaudeAdapter`). Leave it unset if the CLI doesn't report
  cost — don't estimate from token counts, since there's no pricing table
  in this repo to keep current. `secfoo cost` shows `-` for runs whose
  adapter doesn't provide this.

Then register the class in `ADAPTERS` in
`src/secfoo/agents/registry.py`. `secfoo agents`, `--agent`, and the web
run form are all driven from that dict, so there's nothing else to wire
up.

The built-in `secfoo` agent (`src/secfoo/agents/secfoo.py`) is the one
exception: it overrides `run()` directly instead of `build_command()`,
since it runs in-process via LangGraph/LiteLLM rather than shelling out
to an external CLI — use it as the reference if your adapter also needs
to skip the subprocess path.

## Pull requests

- Keep PRs focused — one behavior change per PR is easier to review
  than a bundle of unrelated cleanups.
- Add or update tests for any behavior change. `pytest tests` must
  pass before review.
- Explain the *why* in the PR description, not just the what — what
  broke, or what was missing, that this fixes.

## Reporting bugs

Open a GitHub issue with the exact command you ran, what you expected,
and what actually happened. Attach the relevant `~/.secfoo/reports/<run-uuid>/stderr.log`
if the issue is a run failure — it's almost always the fastest way to
diagnose an agent-adapter problem.

For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead
of opening a public issue.
