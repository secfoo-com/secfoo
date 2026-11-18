# Responsible AI Compliance Report

## Summary
The target is an internal developer-support Q&A assistant built on the Flask chat and Assistants examples that answers staff questions about internal runbooks via OpenAI's hosted `gpt-3.5-turbo` models. It makes no decisions about people, eligibility, employment, or finances. However, a shared module-level session store in the Flask app creates a High-severity data-leakage finding if multiple staff members upload sensitive runbook attachments concurrently. Because the deployment is restricted to an internal VPN with no consequential decisions about individuals, the overall system risk rating is Medium rather than High.

**Overall risk rating:** Medium

## Findings Register

| ID | Finding | Severity | CWE | Verdict |
|----|---------|----------|-----|---------|
| F1 | Shared global chat history and file store leaks internal attachments across staff sessions | High | CWE-668 | Conditional |
| F2 | No model card, intended-use statement, or known-limitations documentation | Medium | unverified | Confirmed |
| F3 | No audit trail of AI interactions, tool calls, or file uploads | Low | CWE-778 | Confirmed |
| F4 | No disclosure of third-party data processing or retention for user inputs and uploads | Low | unverified | Conditional |
| F5 | Minimal end-user AI disclosure (branding only, no limitations or accuracy notice) | Low | unverified | Confirmed |
| F6 | Autonomous tool execution (code interpreter, function calls) with no human checkpoint or allowlist guidance | Low | unverified | Latent |

## Findings

### [High] F1: Shared global chat history and file store leaks internal attachments across staff sessions
- **Severity:** High
- **CWE:** CWE-668
- **Verdict:** Conditional (precondition: multiple staff members access the shared internal Flask instance concurrently)
- **Location:** `examples/chat-basic/app.py:15-62`, `examples/assistant-flask/app.py:14-19, 26-58, 142-193`
- **Description:** Module-level globals (`chat_history`, `assistant_id`, `thread_id`) are shared across all visitors. One engineer's uploaded incident logs or configuration files remain attached to the shared assistant and are exposed to subsequent users.
- **Recommendation:** Scope chat history and Assistants threads per authenticated user session (`flask.session` with a server-set `SECRET_KEY`) and attach uploaded files to the per-session thread rather than the shared assistant.

### [Medium] F2: No model card, intended-use statement, or known-limitations documentation
- **Severity:** Medium
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `README.md` (repository-wide; no `MODEL_CARD.md`, `docs/`, or equivalent exists)
- **Description:** The README documents setup only and omits intended use, known hallucination risks on internal runbooks, and out-of-scope uses.
- **Recommendation:** Add a "Model and responsible use" section to `README.md` detailing intended internal Q&A use, non-goals, and limitations.

### [Low] F3: No audit trail of AI interactions, tool calls, or file uploads
- **Severity:** Low
- **CWE:** CWE-778
- **Verdict:** Confirmed
- **Location:** `examples/chat-basic/app.py:32-55`, `examples/assistant-flask/app.py:26-58, 147-182`
- **Description:** Prompts, completions, and file uploads are not logged durably; only ad-hoc `print()` calls exist.
- **Recommendation:** Introduce structured Python `logging` with timestamp, session ID, model, and file IDs to an append-only sink.

### [Low] F4: No disclosure of third-party data processing or retention for user inputs and uploads
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Conditional (precondition: staff submit sensitive or personal data in prompts or attachments)
- **Location:** `examples/assistant-flask/app.py:38-51`, `examples/assistant-flask/templates/index.html:41-50`, `README.md`
- **Description:** User inputs and uploaded files are sent to OpenAI and persisted server-side without an explicit UI notice or full `client.files.delete(file_id)` cleanup.
- **Recommendation:** Add a third-party data-processing notice in the templates and README and delete OpenAI file objects on removal.

### [Low] F5: Minimal end-user AI disclosure (branding only, no limitations or accuracy notice)
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `examples/chat-basic/templates/index.html:4, 11-17, 86`, `examples/assistant-flask/templates/index.html:4, 16-22, 303`
- **Description:** The UI lacks an explicit disclaimer that responses are AI-generated and may be inaccurate.
- **Recommendation:** Add a persistent one-line disclaimer under the header in both templates.

### [Low] F6: Autonomous tool execution (code interpreter, function calls) with no human checkpoint or allowlist guidance
- **Severity:** Low
- **CWE:** unverified
- **Verdict:** Latent
- **Location:** `examples/assistant-flask/app.py:116-121`, `examples/assistant-functions/functions.py:45, 107-147`
- **Description:** `run_action` dispatches model-selected tools without schema validation or confirmation; shipped tools are harmless stubs.
- **Recommendation:** Validate model-supplied arguments with `pydantic` and require confirmation before executing any side-effecting tool.

## Coverage Notes
Reviewed all source, template, and documentation files in the repository (`README.md`, `LICENSE`, `requirements.txt`, `.gitignore`, and the four modules under `examples/`). Confidence in the assessment is high.
