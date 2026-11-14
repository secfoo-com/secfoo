# secfoo in CI

secfoo is built to run unattended. Every path below ends with the same
three things: a machine-readable run summary (`--json`), structured
findings exported as SARIF 2.1.0 or JSON Lines, and an exit code your
pipeline can gate on.

| Exit code | Meaning |
|---|---|
| `0` | Clean. |
| `1` | A skill run failed or timed out. The gate verdicts are still in the JSON, but a partial scan never passes. |
| `2` | Every run succeeded and the `--fail-on <severity>` gate tripped. |
| `3` | Every run succeeded and the `--max-cost <usd>` gate tripped (wins over `2` if both trip). |

Flags that matter in CI: `--json` (one JSON document on stdout, progress on
stderr, no interactive prompts), `--rescan` (never ask "scan this commit
again?"), `--project-name` (so the dashboard shows a repo name rather than a
runner path), `--fail-on`, `--max-cost`, `--exclude`, `--timeout`. The full
list is in [REFERENCE.md](REFERENCE.md#ci-gates-and-machine-readable-output).

## Which agent in CI

| `--agent` | What the runner needs |
|---|---|
| `api` (default in the Action) | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` in the environment. No extra install; source files are sent to the model in the prompt. Pick the model with `--model` (LiteLLM names, e.g. `anthropic/claude-sonnet-4-5`). |
| `claude`, `codex`, `gemini`, `copilot` | The CLI on `PATH` plus its API key env var (the Action's `install-agent-cli` input does the npm install). The agent reads the checkout itself with read-only tools. |
| `agent` (Cursor), `agy`, `droid`, `devin`, `opencode` | The CLI on `PATH` and whatever non-interactive auth it supports; see [agents.md](agents.md). |

Cap spend with `--max-cost`; Claude and the `api` agent report real USD,
Gemini reports tokens only, Cursor and Antigravity report nothing (those
runs count as `unpriced_runs` in the JSON and never pass a cap as "$0").

## GitHub Actions

### The Action

[`secfoo-com/secfoo`](https://github.com/secfoo-com/secfoo) is a composite
Action: it installs secfoo from PyPI, runs the skills you name, exports
SARIF, uploads it to code scanning so findings appear under **Security →
Code scanning** and as annotations on pull requests, writes a summary to
the job page, and then applies secfoo's exit code.

```yaml
# .github/workflows/secfoo.yml
name: secfoo security review
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write     # needed for the SARIF upload

jobs:
  secfoo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: secfoo-com/secfoo@main
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}   # or ANTHROPIC_API_KEY / GEMINI_API_KEY
        with:
          skills: sast,secret-scanning
          fail-on: high
          max-cost: "2.00"
```

Pin to a release tag (`secfoo-com/secfoo@v0.3.1`) once you are happy with
it. Ready-to-copy files: [examples/ci/github-actions.yml](../examples/ci/github-actions.yml)
and, without the Action, [examples/ci/github-actions-manual.yml](../examples/ci/github-actions-manual.yml).

**Inputs**

| Input | Default | Purpose |
|---|---|---|
| `skills` | `sast,secret-scanning` | Comma-separated skill IDs, run concurrently. |
| `target` | `.` | Directory or GitHub URL to assess. |
| `agent` | `api` | `api`, `claude`, `codex`, `gemini`, `copilot`, `agent`, `agy`, `droid`, `devin`, `opencode`. |
| `model` | | Model override for the agent. |
| `depth` | `quick` | `quick` or `standard`. |
| `fail-on` | | `critical`, `high`, `medium` or `low`: fail the job at this severity or worse. |
| `max-cost` | | USD cap on agent-reported spend. |
| `timeout` | | Per-skill timeout in seconds. |
| `exclude` | | Comma-separated paths to skip. |
| `extra-args` | | Appended to `secfoo run` verbatim. |
| `version` | latest | secfoo version from PyPI. |
| `python-version` | `3.12` | Python used to install secfoo. |
| `install-agent-cli` | | `claude`, `codex`, `gemini` or `copilot`: npm-install that CLI first. |
| `sarif-file` | `secfoo.sarif` | SARIF export path; empty disables the export. |
| `upload-sarif` | `true` | Upload to code scanning. |
| `sarif-category` | `secfoo` | Code scanning category, so other tools' results are kept. |
| `result-file` | `secfoo-result.json` | Where the `--json` document is written. |

**Outputs**: `exit-code`, `critical`, `high`, `medium`, `low`, `cost-usd`,
`result-file`, `sarif-file`. For example, to comment on a PR only when
something High+ appeared:

```yaml
      - uses: secfoo-com/secfoo@main
        id: secfoo
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      - if: steps.secfoo.outputs.high != '0' || steps.secfoo.outputs.critical != '0'
        run: echo "::warning::secfoo found ${{ steps.secfoo.outputs.high }} High findings"
```

Code scanning needs to be available for the repository (public repos, or
GitHub Advanced Security on private ones). Without it, set
`upload-sarif: false` and keep the SARIF as an artifact.

### Using Claude Code (or Codex, Gemini, Copilot) as the reviewer

```yaml
      - uses: secfoo-com/secfoo@main
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          install-agent-cli: claude
          agent: claude
          skills: sast,secret-scanning,sca-reachability
          fail-on: high
```

## Pre-commit

secfoo ships [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml) with two hooks:

| Hook | What it does |
|---|---|
| `secfoo-secrets` | Secret scanning only; fails on High or Critical. The quick one. |
| `secfoo` | Any skills you pass in `args`; defaults to `--skill secret-scanning --fail-on high`. |

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/secfoo-com/secfoo
    rev: v0.3.1
    hooks:
      - id: secfoo-secrets
        stages: [pre-commit]
      - id: secfoo
        args: [--skill, sast, --skill, secret-scanning, --fail-on, high]
        stages: [pre-push]
```

Then `pre-commit install --hook-type pre-commit --hook-type pre-push`. An
LLM review takes minutes, so the fuller hook belongs on `pre-push`. The hooks
use whichever agent you already have (an installed CLI, or `api` when a key
is in your environment); force one with `args: [--agent, codex, ...]`.
Full example: [examples/ci/pre-commit-config.yaml](../examples/ci/pre-commit-config.yaml).

## GitLab CI

```yaml
secfoo:
  stage: test
  image: python:3.12-slim
  before_script:
    - apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null
    - pip install --quiet secfoo
  script:
    - |
      secfoo run --agent api --target . --depth quick --json --rescan \
        --project-name "$CI_PROJECT_PATH" \
        --skill sast --skill secret-scanning \
        --fail-on high --max-cost 2.00 > secfoo-result.json || code=$?
    - secfoo findings export --format sarif -o secfoo.sarif
    - exit ${code:-0}
  artifacts:
    when: always
    paths: [secfoo-result.json, secfoo.sarif]
```

Set the provider key as a masked CI/CD variable. The SARIF file is kept as
an artifact; GitLab's own security dashboard expects its report formats,
not SARIF, so treat this as the hand-off file for other tools. Full job,
including merge-request rules and a container-image variant:
[examples/ci/gitlab-ci.yml](../examples/ci/gitlab-ci.yml).

## Docker

The image on GHCR has secfoo and git, nothing else:

```bash
docker run --rm -e OPENAI_API_KEY -v "$PWD:/workspace" ghcr.io/rakfortltd/secfoo \
  run --agent api --target /workspace --depth quick --json --rescan --skill sast --fail-on high
```

No agent CLI is installed in the image, so `--agent api` is the practical
choice; build `FROM ghcr.io/rakfortltd/secfoo` and `npm install -g
@anthropic-ai/claude-code` (or another CLI) if you want one. The store is
`/root/.secfoo`; mount it to keep findings between jobs. See the
[Distribution](REFERENCE.md#distribution) notes.

## Anything else (Jenkins, Buildkite, CircleCI, Azure Pipelines, ...)

```bash
pip install secfoo                     # or: uvx secfoo run ...
secfoo run --agent api --target . --depth quick --json --rescan \
  --skill sast --skill secret-scanning --fail-on high > secfoo-result.json
code=$?
secfoo findings export --format sarif -o secfoo.sarif
exit $code
```

Everything the dashboard shows is also in the local SQLite store under
`~/.secfoo` (override with `SECFOO_HOME`), so a job can archive it, and
`secfoo serve` can show it later.
