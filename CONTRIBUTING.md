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

### Fuzzing

Everything that parses untrusted input has a coverage-guided fuzz harness
in `fuzz/`:

| Harness | Target | Contract |
| --- | --- | --- |
| `fuzz_parsers.py` | report severities, skill frontmatter, severity filters | never raises |
| `fuzz_sarif_export.py` | `findings export` (SARIF and JSONL) | valid SARIF 2.1.0; JSONL round-trips |
| `fuzz_skill_loader.py` | skill files (`--skill-file`, folders, URLs) | a `Skill` or `SkillLoadError` |
| `fuzz_config.py` | `~/.secfoo/config.toml` | correctly typed config or `ConfigError` |
| `fuzz_docext.py` | uploaded PDF / DOCX / PPTX | text or `""`, within a time limit |
| `fuzz_runtime_ingest.py` | runtime sensor NDJSON batches | every line stored or skipped, never a 500 |

The `Fuzz` workflow runs each harness for 60 seconds on PRs that touch
these parsers, and nightly. To run one locally (Linux or macOS):

```sh
pip install atheris
mkdir -p work
python fuzz/fuzz_config.py work fuzz/corpus/config -max_total_time=60
```

Each harness's `check` function also runs on every platform in
`pytest tests/test_property_fuzz_targets.py` (Hypothesis), which replays
every file in `fuzz/corpus/`. Without Atheris, a harness replays the files
or folders you pass, so a CI crash reproduces anywhere, Windows included:

```sh
python fuzz/fuzz_config.py crash-<sha1>
```

When you fix a crash, add its reproducer to `fuzz/corpus/<harness>/` as
`crash-<what>.<ext>` (or in `fuzz/make_seed_corpus.py`, which writes the
seed corpora) so it's replayed on every run. If you change one of these
parsers, run its harness for a minute before opening the PR.

## Adding or changing a skill

Skills live under `src/secfoo/skills/definitions/*.md` as a prompt
template with YAML frontmatter (`id`, `name`, `description`,
`short_name`, `version`). If you're adding a skill that needs its own
dashboard (like SAST's Open/Closed Findings register), look at
`src/secfoo/web/sast_dashboard.py` and its `activities/sast_*.html`
templates as the reference shape — most skills don't need this and are
fine with the generic activity page (`activities/detail.html`).

## Pull requests

- Keep PRs focused — one behavior change per PR is easier to review
  than a bundle of unrelated cleanups.
- Add or update tests for any behavior change. `pytest tests` must
  pass before review.
- Explain the *why* in the PR description, not just the what — what
  broke, or what was missing, that this fixes.

## Hackathon points

Merged PRs earn points on the
[contributor leaderboard](https://github.com/secfoo-com/secfoo/blob/leaderboard/LEADERBOARD.md),
based on the difficulty of the issue they close:

| Issue label          | Points |
|----------------------|-------:|
| `difficulty: hard`   |     10 |
| `difficulty: medium` |      6 |
| `difficulty: low`    |      3 |

| Level  | Points needed |
|--------|--------------:|
| Gold   |           100 |
| Silver |            50 |
| Bronze |            25 |

How it works:

- Maintainers put one `difficulty:` label on every issue. Issues without
  one carry `needs difficulty` until that's done; if you pick one up, ask
  for a difficulty in the issue before you start so you know its value.
- Link the issue from your PR (`Fixes #123` in the description, or the
  "Development" sidebar). Only issues GitHub records as closed by the
  merged PR are scored. A PR that closes several issues scores each one.
- Each issue is scored once, for the first merged PR that closes it.
- The board is rebuilt from scratch after every merge and every label
  change, so an issue labelled after your PR merged still counts. The
  workflow leaves a comment on your PR with the points it earned.
- Scoring lives in `scripts/leaderboard.py`; the rules above are the
  constants at the top of that file.

## Reporting bugs

Open a GitHub issue with the exact command you ran, what you expected,
and what actually happened. Attach the relevant `~/.secfoo/reports/<run-uuid>/stderr.log`
if the issue is a run failure — it's almost always the fastest way to
diagnose an agent-adapter problem.

For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead
of opening a public issue.
