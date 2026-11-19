# Responsible AI Compliance Report

## Summary
The target, `https://github.com/openai/openai-quickstart-python`, is a set of four minimal demo applications (a streaming chat UI, an Assistants API Flask app with file upload and code interpreter, and two CLI assistant scripts) that forward user text to OpenAI's hosted `gpt-3.5-turbo` models and display the response. The system makes no eligibility, access, employment, legal, financial, biometric, or safety decisions about any person, so no high-stakes or rights-affecting use case exists. Governance artifacts (model card, limitations, bias testing, audit trail, framework reference) are entirely absent, which is expected for a quickstart but matters if the code is copied into production as-is; the most concrete concern is that all users of a running Flask instance share one global conversation and one shared file store. Given the stakes, every gap is rated Low.

**Overall risk rating:** Low

## Findings Register

| ID | Finding | Severity | CWE | Verdict |
|----|---------|----------|-----|---------|
| F1 | Shared global chat history and file store leaks one user's data to all others | Low | CWE-668 | Conditional |
| F2 | No model card, intended-use statement, or known-limitations documentation | Low | unverified | Confirmed |
| F3 | No audit trail of AI interactions, tool calls, or file uploads | Low | CWE-778 | Confirmed |
| F4 | No disclosure of third-party data processing or retention for user inputs and uploads | Low | unverified | Conditional |
| F5 | Minimal end-user AI disclosure (branding only, no limitations or accuracy notice) | Low | unverified | Confirmed |
| F6 | Autonomous tool execution (code interpreter, function calls) with no human checkpoint or allowlist guidance | Low | unverified | Latent |

## Findings

### [Low] F1: Shared global chat history and file store leaks one user's data to all others
- **Severity:** Low
- **CWE:** CWE-668
- **Verdict:** Conditional (precondition: the Flask app is run where more than one person can reach it, e.g. bound to a non-loopback interface or deployed behind a shared URL)
- **Location:** `examples/chat-basic/app.py:15-62`, `examples/assistant-flask/app.py:14-19, 26-58, 142-193`
- **Description:** Both Flask examples keep conversation state in module-level globals (`chat_history`, `assistant_id`, `thread_id`) with no session, authentication, or per-user scoping. Every visitor sees every other visitor's prompts and model replies on page load, can append to the same OpenAI thread, and in the Assistants example can upload files to, list, and delete files from the single shared assistant. Any `/reset` call wipes everyone's conversation. From a responsible AI data-governance standpoint this means user inputs (which may include personal data) are exposed to unrelated parties and retrieval context is silently polluted across users. The README offers no warning that the samples are single-user demos.
- **Recommendation:** Scope state per user: store chat history and thread IDs in a Flask session (`flask.session` with a server-set `SECRET_KEY`) or a per-user record keyed by an authenticated identity, and create one Assistants thread per session rather than one per process. Attach uploaded files to the per-user thread/message rather than the shared assistant. Add a prominent README note that the examples are single-user, localhost-only demos and must not be exposed on a network without these changes.

### [Low] F2: No model card, intended-use statement, or known-limitations documentation
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `README.md` (repository-wide; no `MODEL_CARD.md`, `docs/`, or equivalent exists)
- **Description:** The README covers installation and running only. There is no description of which models are used and why, their intended and out-of-scope uses, known failure modes (hallucination, prompt injection via uploaded files, non-deterministic code-interpreter output), or a pointer to the upstream model's system card and usage policies. Training-data provenance is OpenAI's responsibility, but the repo does not even link to it. The models hard-coded in all four examples (`gpt-3.5-turbo`, `gpt-3.5-turbo-0125`) and the `client.beta.assistants.files` API surface are legacy, so the documentation is also stale about what will actually run. No bias or fairness testing exists, which is appropriate for a quickstart but should be stated explicitly so downstream adopters do not assume it was done.
- **Recommendation:** Add a short "Model and responsible use" section to `README.md` that: names the model(s) and links to OpenAI's model documentation and usage policies; states the intended use (local developer demo) and explicit non-goals (no production use, no decisions about people); lists known limitations (fabricated answers, injection via files, shared state per F1); and states that no fairness evaluation was performed. Parameterise the model name via an environment variable so documentation and code stay aligned.

### [Low] F3: No audit trail of AI interactions, tool calls, or file uploads
- **Severity:** Low
- **CWE:** CWE-778
- **Verdict:** Confirmed
- **Location:** `examples/chat-basic/app.py:32-55`, `examples/assistant-flask/app.py:26-58, 147-182`, `examples/assistant-functions/functions.py:107-147`
- **Description:** No example logs prompts, completions, run IDs, tool invocations, or file upload/delete events in a durable or structured way. The only output is two debugging `print()` calls in the Assistants app (one of which dumps the full file list to stdout). The function-calling example executes model-selected tools (`run_action`) with no record of what was called or with what arguments. Without this, there is no way to reconstruct what the model said to a user, investigate a harmful or incorrect output, or offer recourse. Because no consequential decisions are made, this is a hygiene gap rather than a rights issue.
- **Recommendation:** Introduce Python `logging` with a structured record per request containing timestamp, session identifier, model, OpenAI run/thread/message IDs, tool name and arguments for function calls, and file IDs for upload/delete. Write to an append-only sink (file or log service) rather than stdout, and remove the ad-hoc `print()` calls. Document retention and who may read the logs.

### [Low] F4: No disclosure of third-party data processing or retention for user inputs and uploads
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Conditional (precondition: a person other than the operator uses the app and submits personal or sensitive content)
- **Location:** `examples/assistant-flask/app.py:38-51`, `examples/assistant-flask/templates/index.html:41-50`, `README.md`
- **Description:** User messages and uploaded files (txt, pdf, images, csv) are transmitted to OpenAI and, in the Assistants example, persisted server-side as assistant files and thread messages that outlive the local process. The UI only says "Attach files to make them available to code interpreter"; nothing tells the user that content leaves the machine, is retained by a third party, or how to have it deleted (the delete button removes the assistant association but not necessarily the underlying file object). Nothing documents the licensing or consent basis for data placed into the retrieval/code-interpreter context. There is no training, fine-tuning, or RAG corpus in the repo, so provenance obligations are limited to this runtime data flow.
- **Recommendation:** Add a visible notice in both templates and the README stating that messages and files are sent to and stored by OpenAI under its API data-usage policy, with a link. In `upload_file`, document (or implement) full cleanup by calling `client.files.delete(file_id)` after detaching from the assistant, and expose a "delete my data" action. Advise users not to upload personal or confidential data in the demo.

### [Low] F5: Minimal end-user AI disclosure (branding only, no limitations or accuracy notice)
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `examples/chat-basic/templates/index.html:4, 11-17, 86`, `examples/assistant-flask/templates/index.html:4, 16-22, 303`
- **Description:** Users can infer they are talking to an AI from the page titles ("OpenAI Chat", "OpenAI Assistant Chat"), the OpenAI logo, a "Demo" tag, and the "Assistant" role label. There is no explicit statement that responses are machine-generated, may be inaccurate, and should not be relied on for advice. The CLI examples print "Response:" with no framing at all. For a developer-facing quickstart this is adequate in practice, but the templates are the obvious copy-paste starting point for public-facing apps.
- **Recommendation:** Add a one-line persistent disclaimer under the header in both templates (for example, "Responses are generated by an AI model and may be inaccurate") and a matching line in the CLI startup output. Keep it in the templates so downstream copies inherit it.

### [Low] F6: Autonomous tool execution (code interpreter, function calls) with no human checkpoint or allowlist guidance
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Latent (the shipped tools are harmless: OpenAI-sandboxed code interpreter and two hard-coded stub functions; becomes relevant only when a developer swaps in real side-effecting functions at the "Add your next tool here" marker)
- **Location:** `examples/assistant-flask/app.py:116-121`, `examples/assistant-functions/functions.py:45, 107-147`
- **Description:** The Assistants Flask app enables `code_interpreter` and instructs the model to "write and run code" on uploaded files, and the function-calling example dispatches whatever tool the model requests via `run_action` with arguments parsed straight from model output. There is no human-in-the-loop confirmation step, no argument validation, and no guidance in the code or README about which categories of action should require review before execution. As shipped, nothing irreversible can happen, so this is a design pattern concern rather than a live risk.
- **Recommendation:** Add a comment block at the "Add your next tool here" marker and a README paragraph stating that side-effecting tools (payments, email, data deletion, account changes) must gate on an explicit user confirmation before `submit_tool_outputs` is called, and must validate model-supplied arguments against a schema (e.g. with `pydantic`) rather than trusting `json.loads` output directly. Show a minimal confirm-prompt pattern in `run_action` so adopters copy the safe shape.

## Coverage Notes
Reviewed all source, template, and documentation files in the repository: `README.md`, `LICENSE`, `requirements.txt`, `.gitignore`, and the four examples under `examples/` (both Flask `app.py` files and their `index.html` templates, `assistant-basic/assistant.py`, `assistant-functions/functions.py`). Static CSS and PNG assets were not examined. The `.env.example` file could not be read because a local policy hook blocks access to `.env*` paths; based on the README it is expected to contain only an `OPENAI_API_KEY` placeholder, which has no bearing on the governance findings. No Confluence URL was supplied, so no external documentation was consulted. No governance framework (NIST AI RMF, EU AI Act tier, internal policy) is referenced anywhere in the repo; because the system is a low-impact developer demo with no decisions about people, this absence was not raised as a separate finding. The codebase is small (roughly 600 lines) and was read in full, so confidence in the assessment is high.
