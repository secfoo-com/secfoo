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
explicitly labeled SQL defect. Its evaluator-only metadata is retained in
[the v1 manifest](../tests/fixtures/adversarial/manifests/v1.json). The original
source remains available at git revision ad1f43ac1706adb37ebe12aac12f136507321bc2;
it is not duplicated in the checkout.
Historical records must not be interpreted as measurements of the revised
corpus or implementation. Fresh local measurements of the current corpus
(November 19, Qwen3 4B via Ollama, two trials) are in
[docs/evaluations/2026-11-19](evaluations/2026-11-19/README.md); they describe a
small local model only.

## Offline validation

```sh
pip install -e '.[dev]'
python scripts/adversarial_eval.py --records tests/fixtures/adversarial/synthetic-transcripts.jsonl
python scripts/adversarial_eval.py --records docs/evaluations/2026-11-16/claude.jsonl
python scripts/adversarial_eval.py --records docs/evaluations/2026-11-16/api.jsonl
python scripts/adversarial_eval.py --records docs/evaluations/2026-11-19/api.jsonl  # exits 1: 30 runs are nonscorable by design
pytest tests/test_adversarial_eval.py tests/test_review_hardening.py tests/test_fresh_adversarial_evidence.py
```

Synthetic transcripts calibrate evaluator behavior only. They are not model
measurements. Each record explicitly names its corpus_manifest; replay uses that field.
Both historical metadata and the current corpus remain covered by regression tests. Offline CI
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
stable effect. A table groups by agent, skill, phase, attack/control variant, source revision,
trial, capture profile and corpus digest. Different setups are never pooled.
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
completion; the table states that API tools are not exposed, rather than calling an empty
list an observed safety result. Model prose requesting a
command is not an executed API tool call.

## Runtime provenance and artifact assembly

Every live API record against Ollama carries `runtime_provenance`: runtime
name and version (`GET /api/version`), the model's full digest (`/api/show`,
falling back to `/api/tags`), the model's default options from its Modelfile,
and the context length the server reports as loaded (`/api/ps`). The probe runs
before and after each case (`runtime_version_after`, `model_digest_after`), so
a server or model swapped mid-run shows up as a mismatch. API records also
carry `response_models` (the model id the provider returned, for hosted APIs)
and `request_options` (names of the keyword options sent beyond model and
messages; the harness sets no sampling options, so effective sampling is the
model default plus the server configuration). Only loopback endpoints are probed
and recorded as `loopback`; no keys, other hosts or user paths are stored
(`scrub_evidence` still applies); probes ignore proxy settings and refuse
redirects. A failed probe is recorded as `probe_error` (`probe_error_after` for
the post-run probe) instead of stopping the evaluation.
Claude CLI records have no such block.

To rebuild a multi-trial artifact and its summary:

```sh
python scripts/adversarial_eval.py --combine trial-1.jsonl trial-2.jsonl -o api.jsonl
python scripts/adversarial_eval.py --records api.jsonl --summary summary.md
```

`--combine` is an order-preserving, byte-for-byte concatenation, so the SHA-256
recorded in `setup.json` is reproducible.

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
  report error. The runner records these runs as failed before findings ingestion, preserving
  report paths, normal multi-skill outcomes and CLI JSON output. Malformed old
  stored reports are logged and skipped; dashboards identify exclusions.
- API source bodies retain raw newlines between random per-file boundaries;
  paths and deleted-path lists are JSON quoted. The trusted brief remains a
  system message and declares the generated boundary tokens there. Reformat instructions explicitly identify the JSON draft
  field and require raw Markdown; JSON echoes and malformed output fail after
  the bounded retry rather than becoming successful zero-finding reports.

Random boundaries and tool grants reduce specific attack surfaces. They do not
prevent all model manipulation or establish isolation. Inspect artifacts for
credentials and unexpected data before publishing.

Local Ollama evaluations retain OLLAMA_API_BASE only for a loopback URL, use a
non-secret availability sentinel, and retain SECFOO_MEMORY. Bare model names
resolve to the OpenAI provider for credential selection. No cloud routing is
enabled automatically. Captures normalize local paths and remove session IDs,
UUIDs, messaging sockets, plugin metadata and subscription-expiry fields before
publication. Capture hashes describe the sanitized public files, not originals.
