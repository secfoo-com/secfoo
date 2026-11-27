# Responsible AI Compliance Report

## Summary
The target is a loan-preapproval assistant that drafts eligibility recommendations for human reviewers. It materially influences access to credit, so the stakes are high and the gaps in oversight, disclosure and recourse are medium rather than low.

**Overall risk rating:** Medium

## AI System Profile

| Field | Value |
|-------|-------|
| Models and providers | `gpt-4o (OpenAI)`, `claude-3-5-sonnet (Anthropic)` |
| Decides or influences | Loan preapproval recommendations reviewed by staff |
| Affected people | Applicants for consumer credit |
| Stakes tier | high |

## Findings Register

| ID | Finding | Severity | Dimension | Framework |
|----|---------|----------|-----------|-----------|
| F1 | Reviewers can approve a recommendation without seeing the model's stated reasons | Medium | Human oversight | NIST AI RMF GOVERN 4.2 |
| F2 | Applicants are not told that AI influenced the preapproval decision | Medium | Transparency to end users | EU AI Act Art. 26 |
| F3 | No durable record links a recommendation to the data and model version used | Low | Auditability & recourse | Internal AI-07 |

## Detailed Findings

### [Medium] F1: Reviewers can approve a recommendation without seeing the model's stated reasons
- **Dimension:** Human oversight
- **Framework:** NIST AI RMF GOVERN 4.2
- **Stakes:** high
- **Description:** The review screen shows the final score but hides the model's explanation, so the human checkpoint is a rubber stamp.
- **Recommendation:** Show the reasons alongside the score and require a reviewer to record an override or acceptance.

### [Medium] F2: Applicants are not told that AI influenced the preapproval decision
- **Dimension:** Transparency to end users
- **Framework:** EU AI Act Art. 26
- **Stakes:** high
- **Description:** The decision letter describes the outcome without naming the automated preapproval step or its limits.
- **Recommendation:** Add a short AI-disclosure paragraph and the route to request human reconsideration.

### [Low] F3: No durable record links a recommendation to the data and model version used
- **Dimension:** Auditability & recourse
- **Framework:** Internal AI-07
- **Stakes:** high
- **Description:** Recommendations are logged only as a score, not with the prompt, model version or input snapshot needed to reconstruct them.
- **Recommendation:** Persist an immutable decision record with model version and input fingerprint.

## Dimension Coverage

| Dimension | Status | Evidence | Finding IDs |
|-----------|--------|----------|-------------|
| Documentation | partial | `docs/model-card.md` names the model but omits known limitations | — |
| Bias & fairness | missing | No fairness evaluation or protected-attribute testing exists in `tests/` or `docs/` | — |
| Human oversight | partial | `review/approve.py` records a reviewer but not the model's reasons | F1 |
| Transparency to end users | missing | `templates/decision.html` has no AI-disclosure text | F2 |
| Data provenance & consent | adequate | `docs/data-sources.md` lists each source and its licence | — |
| Framework alignment | partial | `docs/risk-tier.md` claims NIST AI RMF alignment but maps no controls | — |
| Auditability & recourse | partial | `review/audit.py` stores scores without model version or inputs | F3 |

## Remediation Roadmap
1. Expose model reasons at the reviewer checkpoint (F1).
2. Add the end-user AI disclosure and appeal route (F2).
3. Write complete decision records (F3).
