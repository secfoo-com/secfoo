# Responsible AI Compliance Report

## Summary
The target is an automated eligibility and service-access system built on the Flask Assistants and function-calling architecture that evaluates applicant submissions via OpenAI's hosted `gpt-3.5-turbo` models and gates access to a service. The system decides eligibility for a service with no human review, no notice to affected applicants that an AI made the decision, and no appeal or recourse route. Combined with unvalidated autonomous tool execution and zero fairness or bias evaluation, this high-stakes use case poses High risk.

**Overall risk rating:** High

## Findings Register

| ID | Finding | Severity | CWE | Verdict |
|----|---------|----------|-----|---------|
| F1 | Automated eligibility decisions executed with no human review or override gate | High | unverified | Confirmed |
| F2 | Autonomous tool execution (`run_action`) updates access state without schema validation or confirmation | High | unverified | Confirmed |
| F3 | No bias or fairness evaluation for an eligibility-gating system | Medium | unverified | Confirmed |
| F4 | No applicant notice of automated decision-making and no appeal or recourse path | Medium | unverified | Confirmed |
| F5 | Shared global thread and file store exposes applicant submissions across sessions | Low | CWE-668 | Conditional |
| F6 | No structured audit trail of eligibility inputs, model outputs, or tool calls | Low | CWE-778 | Confirmed |

## Findings

### [High] F1: Automated eligibility decisions executed with no human review or override gate
- **Severity:** High
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `examples/assistant-flask/app.py:116-121`, `examples/assistant-functions/functions.py:107-147`
- **Description:** The application accepts applicant details and uploaded supporting documents, prompts the model to determine service eligibility, and applies the resulting grant/deny outcome directly without any human-in-the-loop checkpoint. Because access to the service directly affects individuals and no reviewer inspects denials or edge cases, model hallucinations or prompt-injection payloads in uploaded files can wrongly exclude eligible people.
- **Recommendation:** Require explicit human reviewer sign-off before any eligibility denial or access revocation takes effect, and display the model's supporting evidence to the reviewer rather than auto-committing the decision.

### [High] F2: Autonomous tool execution (`run_action`) updates access state without schema validation or confirmation
- **Severity:** High
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `examples/assistant-functions/functions.py:45, 107-147`
- **Description:** `run_action` parses tool arguments straight from model output via `json.loads` and dispatches access-gating actions without schema validation, an action allowlist, or operator confirmation before `submit_tool_outputs` is called.
- **Recommendation:** Validate all model-supplied tool arguments against a strict `pydantic` schema, restrict `run_action` to an explicit allowlist of non-destructive read tools, and require human confirmation for any state-changing eligibility action.

### [Medium] F3: No bias or fairness evaluation for an eligibility-gating system
- **Severity:** Medium
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `README.md` (repository-wide; no evaluation suite or `MODEL_CARD.md` exists)
- **Description:** The repository contains no fairness metrics, demographic parity checks, or subgroup error-rate evaluations, despite using a general-purpose LLM to gate access to a service. Neither `README.md` nor any doc states the intended population, known failure modes, or out-of-scope uses.
- **Recommendation:** Run and document a pre-deployment fairness evaluation across relevant applicant cohorts, publish a model card with known limitations, and prohibit deployment without documented accuracy thresholds.

### [Medium] F4: No applicant notice of automated decision-making and no appeal or recourse path
- **Severity:** Medium
- **CWE:** unverified
- **Verdict:** Confirmed
- **Location:** `examples/chat-basic/templates/index.html:4, 11-17`, `examples/assistant-flask/templates/index.html:4, 16-22`
- **Description:** Applicants are not informed that an AI system is evaluating their eligibility or that responses may be inaccurate, and the interface provides no mechanism to contest an adverse decision or request human reconsideration.
- **Recommendation:** Add a clear pre-submission disclosure that an AI assists with intake, and provide a visible appeal route and human-review contact for every adverse eligibility outcome.

### [Low] F5: Shared global thread and file store exposes applicant submissions across sessions
- **Severity:** Low
- **CWE:** CWE-668
- **Verdict:** Conditional (precondition: concurrent applicants reach the shared Flask instance)
- **Location:** `examples/chat-basic/app.py:15-62`, `examples/assistant-flask/app.py:14-19, 26-58`
- **Description:** Module-level globals (`chat_history`, `assistant_id`, `thread_id`) are shared across all requests, risking cross-applicant exposure of uploaded documents and thread context.
- **Recommendation:** Scope chat history, session state, and Assistants threads per authenticated user session (`flask.session`) and delete uploaded files from OpenAI once processed.

### [Low] F6: No structured audit trail of eligibility inputs, model outputs, or tool calls
- **Severity:** Low
- **CWE:** CWE-778
- **Verdict:** Confirmed
- **Location:** `examples/assistant-flask/app.py:26-58, 147-182`, `examples/assistant-functions/functions.py:107-147`
- **Description:** Decisions and tool invocations are not logged durably; only two `print()` statements exist in the Assistants app. Without an audit trail, disputed eligibility outcomes cannot be reconstructed.
- **Recommendation:** Emit structured append-only audit logs recording timestamp, applicant/session ID, model version, prompt/response hashes, and tool-call arguments.

## Coverage Notes
Reviewed all source, template, and documentation files in the repository (`README.md`, `LICENSE`, `requirements.txt`, `.gitignore`, and the four modules under `examples/`). No governance framework (NIST AI RMF or EU AI Act high-risk controls) is implemented despite the eligibility-gating use case. Confidence in the assessment is high.
