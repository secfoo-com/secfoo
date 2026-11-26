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

## Passing documentation context in CI

Pass architecture docs, threat models, or wiki specifications to the agent with `--context`:

```bash
secfoo run --agent claude --target . --depth quick --json \
  --skill security-architecture-review --skill threat-modeling \
  --context https://yourcompany.atlassian.net/wiki/spaces/SEC/pages/123 \
  --context ../external-specs/architecture.pdf > secfoo-result.json
```

- **HTTPS URLs:** Require an MCP server configured on the runner for that host (e.g. in `~/.secfoo/config.toml`), otherwise the agent cannot query the service and the source will be recorded as not reached in the coverage table. `--agent api` cannot read URL sources and records them as not reached, while local files work with every agent because secfoo inlines them.
- **Local files:** Must live **outside** the target checkout being scanned (e.g. checked out to a sibling directory or staged from an external workflow artifact). Passing a file or folder inside the scanned target is rejected with exit code `2`.
- **Failing CI on unreached documentation:** If your pipeline requires all declared context sources to be verified and reached by the agent, check the `--json` output with `jq`:

```bash
jq -e '[.runs[].context_sources[] | select(.reached | not)] | length == 0' secfoo-result.json
```

A URL source is only reachable when the agent has an MCP server for it, so CI that gates on `reached` will also fail for that reason.

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
    - secfoo findings export --format gitlab-sast -o gl-sast-report.json
    - secfoo findings export --format gitlab-secret-detection -o gl-secret-detection-report.json
    - secfoo findings export --format sarif -o secfoo.sarif
    - exit ${code:-0}
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
      secret_detection: gl-secret-detection-report.json
    paths: [secfoo-result.json, secfoo.sarif]
```

Set the provider key as a masked CI/CD variable. GitLab's merge-request
security widget and Vulnerability Report don't read SARIF, so the job also
exports findings in GitLab's own report formats (schema v15):
`--format gitlab-sast` carries the SAST findings and
`--format gitlab-secret-detection` the secret-scanning ones (the secret
value itself is never copied). Attached under `artifacts: reports:`, they
show up in the MR widget and the Vulnerability Report on GitLab Ultimate;
on other tiers they are plain downloadable artifacts. SCA findings have no
GitLab report here (GitLab's dependency-scanning format describes
dependency files), so they stay in the SARIF and JSON Lines exports. Full
job, including merge-request rules and a container-image variant:
[examples/ci/gitlab-ci.yml](../examples/ci/gitlab-ci.yml).

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: python:3.12-slim

definitions:
  steps:
    - step: &secfoo
        name: secfoo security review
        script:
          - apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null
          - pip install --quiet secfoo
          - |
            code=0
            secfoo run --agent api --target . --depth quick --json --rescan \
              --project-name "$BITBUCKET_REPO_FULL_NAME" \
              --skill sast --skill secret-scanning \
              --fail-on high --max-cost 2.00 > secfoo-result.json || code=$?
            secfoo findings export --format sarif -o secfoo.sarif
            secfoo findings export -o secfoo-findings.jsonl
            exit $code
        artifacts:
          - secfoo-result.json
          - secfoo.sarif
          - secfoo-findings.jsonl

pipelines:
  pull-requests:
    '**':
      - step: *secfoo
  branches:
    main:
      - step: *secfoo
```

Add `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY` / `GEMINI_API_KEY`) under
**Repository settings → Pipelines → Repository variables** (or as a
workspace variable to share it across repositories) and tick **Secured**, so
Bitbucket masks it in logs and hides its value after saving. Pipelines must be
enabled for the repository. The `pull-requests` pipeline runs on every pull
request; `branches: main` covers pushes to the default branch, so rename it if
yours is not `main`.

The script records `secfoo run`'s exit code so both exports always run before
the step fails: `0` is clean, `1` means a skill run failed or timed out, `2`
means `--fail-on` tripped, and `3` means `--max-cost` tripped. The SARIF, JSON
Lines and `--json` files are kept as step artifacts, downloadable from the
**Artifacts** tab of the pipeline run. Bitbucket has no SARIF viewer, so treat
`secfoo.sarif` as the hand-off file for other tools. Full file:
[examples/ci/bitbucket-pipelines.yml](../examples/ci/bitbucket-pipelines.yml).

## Azure Pipelines

```yaml
# azure-pipelines.yml
trigger:
  branches: { include: [main] }
pr:
  branches: { include: [main] }

jobs:
  - job: secfoo
    pool:
      vmImage: ubuntu-latest
    steps:
      - checkout: self
        fetchDepth: 50
      - task: UsePythonVersion@0
        inputs:
          versionSpec: "3.12"
      - bash: pip install --quiet secfoo
      - bash: |
          code=0
          mkdir -p secfoo-reports
          secfoo run --agent api --target . --depth quick --json --rescan \
            --project-name "$(Build.Repository.Name)" \
            --skill sast --skill secret-scanning \
            --fail-on high --max-cost 2.00 > secfoo-reports/secfoo-result.json || code=$?
          secfoo findings export --format sarif -o secfoo-reports/secfoo.sarif
          secfoo findings export -o secfoo-reports/secfoo-findings.jsonl
          exit $code
        env:
          OPENAI_API_KEY: $(OPENAI_API_KEY)
      - task: PublishPipelineArtifact@1
        condition: always()
        inputs:
          targetPath: secfoo-reports
          artifact: secfoo-reports
```

Add `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY` / `GEMINI_API_KEY`) as a secret
pipeline variable under **Pipelines → your pipeline → Edit → Variables → New
variable**, with **Keep this value secret** ticked. Azure Pipelines does not
pass secret variables to scripts on its own, so the step maps it under `env:`.
The job uses a Microsoft-hosted `ubuntu-latest` agent: git is preinstalled,
and `pip install` works without root (a container job runs steps as a
non-root user, so `apt-get` and a system-wide `pip install` fail there).

The `pr:` trigger works for GitHub and Bitbucket Cloud repositories. For Azure
Repos Git, pull-request runs come from a branch policy instead: **Repos →
Branches → main → Branch policies → Build validation**.

The script records `secfoo run`'s exit code so both exports always run before
the step fails: `0` is clean, `1` means a skill run failed or timed out, `2`
means `--fail-on` tripped, and `3` means `--max-cost` tripped. The reports are
published as the `secfoo-reports` pipeline artifact even when the step fails.
Azure has no built-in SARIF viewer, so treat `secfoo.sarif` as the hand-off
file for other tools. Full file:
[examples/ci/azure-pipelines.yml](../examples/ci/azure-pipelines.yml).

## Jenkins

A declarative pipeline that runs in the published image. It needs the
Docker Pipeline plugin and Docker on the agent:

```groovy
pipeline {
    agent {
        docker {
            image 'ghcr.io/secfoo-com/secfoo:latest'
            args '--entrypoint='   // the image's entrypoint is `secfoo`
        }
    }
    environment {
        SECFOO_HOME = "${env.WORKSPACE}/.secfoo"
    }
    stages {
        stage('secfoo security review') {
            steps {
                withCredentials([string(credentialsId: 'openai-api-key', variable: 'OPENAI_API_KEY')]) {
                    sh '''
                        code=0
                        secfoo run --agent api --target . --depth quick --json --rescan \
                          --project-name "${JOB_NAME}" \
                          --skill sast --skill secret-scanning \
                          --fail-on high --max-cost 2.00 > secfoo-result.json || code=$?
                        secfoo findings export --format sarif -o secfoo.sarif
                        secfoo findings export -o secfoo-findings.jsonl
                        exit ${code}
                    '''
                }
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'secfoo-result.json, secfoo.sarif, secfoo-findings.jsonl',
                             allowEmptyArchive: true
        }
    }
}
```

Add `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY` / `GEMINI_API_KEY`) as a
**Secret text** credential under **Manage Jenkins → Credentials → System →
Global credentials** with ID `openai-api-key`. `withCredentials` masks the
secret in console output, and the single-quoted `sh '''` block lets the
shell, not Groovy, expand it.

Jenkins runs the container as its own user, so the workspace stays owned by
Jenkins, and `SECFOO_HOME` puts secfoo's store in the workspace because that
user has no home directory in the image. The `sh` step records `secfoo run`'s
exit code so `secfoo findings export` always runs before the stage fails: `0`
is clean, `1` means a skill run failed or timed out, `2` means `--fail-on`
tripped, and `3` means `--max-cost` tripped. `post { always { archiveArtifacts
... } }` keeps `secfoo-result.json`, `secfoo.sarif` and
`secfoo-findings.jsonl` on the build even when a gate fails. Full pipeline:
[examples/ci/Jenkinsfile](../examples/ci/Jenkinsfile).

## Docker

The image on GHCR has secfoo and git, nothing else:

```bash
docker run --rm -e OPENAI_API_KEY -v "$PWD:/workspace" ghcr.io/secfoo-com/secfoo \
  run --agent api --target /workspace --depth quick --json --rescan --skill sast --fail-on high
```

No agent CLI is installed in the image, so `--agent api` is the practical
choice; build `FROM ghcr.io/secfoo-com/secfoo` and `npm install -g
@anthropic-ai/claude-code` (or another CLI) if you want one. The store is
`/root/.secfoo`; mount it to keep findings between jobs. See the
[Distribution](REFERENCE.md#distribution) notes.

## Anything else (Buildkite, CircleCI, ...)

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
