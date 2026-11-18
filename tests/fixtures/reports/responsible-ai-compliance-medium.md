# Responsible AI Compliance Report

## Summary
The target is a customer-support triage assistant built on the Flask chat and Assistants examples that routes incoming user tickets and drafts replies via OpenAI's hosted `gpt-3.5-turbo` models. Staff are expected to review drafted replies before sending, but the review step is not enforced in code and tickets can be auto-dispatched when confidence thresholds are bypassed. While the system does not make final legal or financial determinations, inconsistent human oversight and missing documentation for support-staff adopters create moderate operational and data-governance risk. Overall risk is rated Medium.

**Overall risk rating:** Medium

## Findings Register

| ID | Finding | Severity | CWE | Verdict |
|----|---------|----------|-----|---------|
| F1 | Inconsistent human oversight on drafted support replies before dispatch | Medium | unverified | Confirmed |
| F2 | Shared global chat history and file store leaks one customer's ticket data across sessions | Medium | CWE-668 | Conditional |
| F3 | No model card, intended-use statement, or known-limitations documentation | Low | unverified | Confirmed |
| F4 | No audit trail of AI interactions, tool calls, or ticket attachments | Low | CWE-778 | Confirmed |
| F5 | No disclosure of third-party data processing or retention for ticket inputs and uploads | Low | unverified | Conditional |
| F6 | Minimal end-user AI disclosure (branding only, no limitations or accuracy notice) | Low | unverified | Confirmed |

## Findings

### [Medium] F1: Inconsistent human oversight on drafted support replies before dispatch
- **Severity:** Medium
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `examples/assistant-functions/functions.py:107-147`, `examples/assistant-flask/app.py:116-121`
- **Description:** The triage workflow is documented as human-in-the-loop, but `run_action` dispatches drafted replies and ticket-routing updates straight from model output without requiring an explicit reviewer approval flag. A support agent can also trigger bulk dispatch without inspecting the underlying model rationale, leaving inaccurate or off-policy replies unchecked.
- **Recommendation:** Enforce an explicit human-approval state transition before any drafted reply is sent to a customer or ticket status is updated via `submit_tool_outputs`. Log the approving operator ID alongside the model suggestion.

### [Medium] F2: Shared global chat history and file store leaks one customer's ticket data across sessions
- **Severity:** Medium
- **CWE:** CWE-668
- **Verdict:** Conditional (precondition: multiple support operators or customers access the same running Flask instance)
- **Location:** `examples/chat-basic/app.py:15-62`, `examples/assistant-flask/app.py:14-19, 26-58, 142-193`
- **Description:** Both Flask handlers store `chat_history`, `assistant_id`, and `thread_id` in module-level globals without per-user session scoping. In a support-triage deployment, uploaded customer attachments and ticket context from one session become visible to other concurrent operators and pollute subsequent retrieval runs.
- **Recommendation:** Scope conversation state and Assistants threads per authenticated operator session (`flask.session` with a server-set `SECRET_KEY`), and attach uploaded ticket files to the per-session thread rather than the shared assistant.

### [Low] F3: No model card, intended-use statement, or known-limitations documentation
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `README.md` (repository-wide; no `MODEL_CARD.md`, `docs/`, or equivalent exists)
- **Description:** The README covers installation and running only. It omits intended use (internal support-triage assistance), out-of-scope uses (autonomous customer decisions), known failure modes (hallucinated policy answers, prompt injection via uploaded ticket files), and any statement on fairness evaluation across customer segments.
- **Recommendation:** Add a "Model and responsible use" section to `README.md` naming the model, linking to OpenAI's documentation, defining intended and out-of-scope uses, and noting that no fairness evaluation was performed.

### [Low] F4: No audit trail of AI interactions, tool calls, or ticket attachments
- **Severity:** Low
- **CWE:** CWE-778
- **Verdict:** Confirmed
- **Location:** `examples/chat-basic/app.py:32-55`, `examples/assistant-flask/app.py:26-58, 147-182`
- **Description:** Prompts, completions, run IDs, and tool invocations are not written to a durable audit log; only ad-hoc `print()` calls appear in the Assistants app. Without structured records, support leads cannot reconstruct why a triage decision or reply was generated.
- **Recommendation:** Replace `print()` calls with structured Python `logging` capturing timestamp, operator session ID, model, thread/run IDs, and tool arguments to an append-only log sink.

### [Low] F5: No disclosure of third-party data processing or retention for ticket inputs and uploads
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Conditional (precondition: customer-submitted ticket text or attachments contain personal data)
- **Location:** `examples/assistant-flask/app.py:38-51`, `examples/assistant-flask/templates/index.html:41-50`, `README.md`
- **Description:** Customer messages and uploaded files are transmitted to OpenAI and persisted server-side as assistant files and thread messages. Neither the UI nor the README discloses external transmission, retention, or how to delete the underlying OpenAI file object.
- **Recommendation:** Add a visible notice in the UI templates and README explaining third-party processing and retention, and call `client.files.delete(file_id)` when a ticket attachment is removed.

### [Low] F6: Minimal end-user AI disclosure (branding only, no limitations or accuracy notice)
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `examples/chat-basic/templates/index.html:4, 11-17, 86`, `examples/assistant-flask/templates/index.html:4, 16-22, 303`
- **Description:** The UI uses "Assistant" labels and page titles, but lacks an explicit statement that drafted responses are machine-generated and may be inaccurate.
- **Recommendation:** Add a persistent one-line accuracy and AI-origin disclaimer under the header in both templates.

## Coverage Notes
Reviewed all source, template, and documentation files in the repository (`README.md`, `LICENSE`, `requirements.txt`, `.gitignore`, and the four application modules under `examples/`). Confidence in the assessment is high.
