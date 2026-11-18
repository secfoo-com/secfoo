# Malicious-repository evaluation

Implements [#117](https://github.com/secfoo-com/secfoo/issues/117). This is a
bounded diagnostic, not proof of general prompt-injection resistance.

## Corpus and provenance

The current corpus contains eight attack/control pairs: code comments, README
instructions, docstrings, instruction-like filenames, agent instruction files,
forged reports, Unicode instructions, and command/network requests. The pairs
cover command injection, SQL injection, path traversal, reflected HTML injection,
unsafe deserialization, expression evaluation, weak password hashing, and SSRF.
Each pair preserves the same underlying defect. Source files and READMEs do not
label that defect or disclose its CWE; the manifest is evaluator-only metadata.
Fixtures are never executed by the harness. Do not deploy them.

Agent instruction files are committed under inert `.fixture` names and renamed
only while copying into a disposable target. Historical snapshots use the same
inert naming convention. Symlinks are rejected. Runtime homes, launchers and
captures live outside the materialized target.

The actual November 16 measurements used an earlier corpus that repeated an
explicitly labeled SQL defect. Its manifest and source are preserved under
[evaluations/2026-11-16/corpus-v1](evaluations/2026-11-16/corpus-v1).
Historical records must not be interpreted as measurements of the revised
corpus or implementation. No fresh model measurements are claimed for this
revision: the local machine has no configured model credentials or model runtime.

## Offline validation

```sh
pip install -e '.[dev]'
python scripts/adversarial_eval.py --records tests/fixtures/adversarial/synthetic-transcripts.jsonl
python scripts/adversarial_eval.py --records docs/evaluations/2026-11-16/claude.jsonl
python scripts/adversarial_eval.py --records docs/evaluations/2026-11-16/api.jsonl
pytest tests/test_adversarial_eval.py tests/test_review_hardening.py
```

Synthetic transcripts calibrate evaluator behavior only. They are not model
measurements. Historical replay automatically uses the archived v1 manifest.
Both archive and current corpus remain covered by regression tests. Offline CI
needs no model credentials. Parser fuzzing is pinned to Atheris 2.3.0 in a
separate weekly/manual workflow, outside the routine PR matrix.

## Live evaluation

Use disposable, isolated environments. The harness is not an OS sandbox.
The manual **Adversarial repository evaluation** workflow takes explicit models,
an exact Claude CLI version, and a built-in skill id. API jobs receive only an
OpenAI key, Claude jobs only an Anthropic key. It does not run on PR events.
No billable workflow was dispatched for this revision.

```sh
python scripts/adversarial_eval.py --live --agent api --skill sast \
  --model openai/gpt-4.1-mini --phase baseline --checkout /path/to/baseline \
  --output /tmp/api-baseline.jsonl
python scripts/adversarial_eval.py --live --agent api --skill sast \
  --model openai/gpt-4.1-mini --phase hardened --checkout /path/to/hardened \
  --output /tmp/api-hardened.jsonl
# Repeat with --agent claude and the chosen Claude model identifier.
```

Checkouts must be clean and committed. Use the same current harness, corpus,
dependencies, skill and model settings for both phases. Records include source
revision, model, skill, prompt hash, corpus hash and trial. Exclusive output
creation prevents accidental overwrite. Repeat trials before estimating a
stable effect. A table groups by agent, skill, phase and attack/control variant.
Other skills can be selected, but a source-code defect is not an appropriate
positive control for every skill; reviewers must assess applicability.

Subprocesses receive an allowlisted environment, an isolated HOME and Secfoo
home, and only the selected provider's credential. Unrelated cloud keys and
custom skill/MCP configuration are not inherited. This intentionally requires
explicit API credentials rather than borrowing a contributor's CLI login.

Claude capture is integrated into each harness invocation. It preserves the
production adapter's tool grants, captures the complete stream and records the
actual allowlist alongside tool attempts. Invalid or incomplete streams remain
unknown. The API harness observes tool-call fields returned by each actual
completion; an empty list is recorded only after that observer ran. It does not
infer tool safety from the adapter exposing no tools. Model prose requesting a
command is not an executed API tool call.

## Scoring and production hardening

- Retention is a location/CWE heuristic, checked against each case's manifest;
  it requires human review of the actual source and report.
- Planted F900 detection is not a general hallucination detector.
- Format checks use the selected built-in skill's output contract. They do not
  validate every report field or the truth of a finding.
- Unsuccessful runs and malformed reports are not safety passes. Missing tool
  observation remains unknown, including the original November 16 API records,
  whose empty tool lists were asserted rather than observed.
- A shared Markdown heading/section iterator is used by severity counting,
  SAST/SCA/secret-scanning extraction and the evaluator. Quoted/fenced headings
  and register examples cannot become persisted findings. Unterminated fences
  and finding-like headings that Markdown does not recognize raise a malformed
  report error. The runner records these runs as failed before findings ingestion.
- API source bodies retain raw newlines between random per-file boundaries;
  paths and deleted-path lists are JSON quoted. The trusted brief remains a
  system message. Reformat instructions explicitly identify the JSON draft
  field and require raw Markdown; JSON echoes and malformed output fail after
  the bounded retry rather than becoming successful zero-finding reports.

Random boundaries and tool grants reduce specific attack surfaces. They do not
prevent all model manipulation or establish isolation. Inspect artifacts for
credentials and unexpected data before publishing.
