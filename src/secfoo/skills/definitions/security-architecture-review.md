---
id: security-architecture-review
name: Security Architecture Review
description: Control-centric evaluation of whether the design is sound — trust boundaries and data flow (cross-referenced by ID), control placement and layering, least privilege, fail-safe behavior, blast radius, operational/regulatory fit, and CCM v4 domain conformance.
short_name: Security Architecture
version: 4
---

Answer one question: **is this design sound?** This is a control-centric,
evaluative review — you judge the architecture against secure design
principles, reference architectures, and any internal standards or
compliance baselines the project claims to meet.

This is deliberately NOT threat enumeration. Do not produce a STRIDE table
or an adversary list — that is the Threat Modeling skill's job, and the two
fail differently: a design can pass every checklist item and still lose to
a threat nobody enumerated, while a threat model can list fifty threats and
still miss that the design has no blast-radius containment at all. Stay on
structure, controls, and their placement. Likewise, code-level defects
belong to SAST and dependency risk to SCA.

1. **Component inventory & data flow.** Components, entry points, data
   stores, external dependencies, and how data moves between them. Note
   where sensitive data (credentials, PII, tokens, model inputs/outputs)
   enters, rests, and leaves. You will render this as a Mermaid data flow
   diagram — see the output format below.

2. **Trust boundaries.** Where does data or control cross from a less
   trusted zone into a more trusted one (internet → app, app → database,
   tenant → tenant, user → admin, agent/LLM output → privileged action)?
   For each, name what actually enforces the trust decision. Every
   boundary you identify here must appear as a labeled, ID'd edge in the
   data flow diagram — the diagram and the trust boundary list are one
   artifact, cross-referenced by ID, not two independent write-ups. If a
   boundary can't be placed on the diagram, that usually means the
   component inventory in step 1 is incomplete — fix that first.

3. **Control presence, placement, and layering.** For each expected
   control, three separate questions: does it exist, is it in the right
   place, and is anything behind it if it fails? A control enforced only
   in the client, or only at one of several entry points to the same sink,
   is misplaced even though it "exists". Single points of control failure
   with nothing layered behind them are findings.

4. **Least privilege — topology vs. policy.** Is least privilege actually
   enforced by the structure (separate credentials, scoped tokens, network
   segmentation, distinct service identities), or merely asserted in
   documentation and configuration that a single mistake could undo? A
   shared admin database credential used by every service is not least
   privilege regardless of what the policy says.

5. **Fail-safe behavior.** What happens when a control's dependency is
   unavailable — auth service down, policy fetch fails, rate limiter
   backend unreachable, token validation errors? Does the system deny by
   default, or does it fail open? Trace at least the authentication and
   authorization paths explicitly.

6. **Blast radius & separation of duties.** If one component, credential,
   or tenant is fully compromised, what else follows? Look for containment
   boundaries (network, credential scope, data partitioning) and for
   duties that should be separated but are not (the same identity that
   deploys can also read production data, one key encrypts everything).

7. **Secrets & key management lifecycle.** Not just where secrets live —
   the whole lifecycle: issuance, distribution, scope, rotation, and
   revocation. Can a leaked credential actually be rotated without a code
   change or downtime? Is there any key hierarchy, or is one key doing
   every job?

8. **Recoverability & operational soundness.** Non-adversarial, and still
   in scope: backup and restore, disaster recovery, audit trail
   durability, observability of security-relevant events, and whether the
   design is maintainable enough that controls survive future changes.

9. **Regulatory & standards fit.** If the project claims a framework,
   baseline, or data-residency requirement (SOC 2, ISO 27001, PCI, HIPAA,
   GDPR, an internal standard), check the design against what it claims.
   If it handles regulated data while claiming nothing at all, that gap is
   itself a finding. Where a finding traces to a specific clause of a
   named standard, cite it — this feeds the platform-wide "most-deviated
   standards" view, which only works if the citation is real and specific,
   never guessed.

10. **CCM domain conformance.** Rate the design against all 17 CSA Cloud
    Controls Matrix (CCM v4) domains — see the output format below for the
    fixed list and rating scale. Several domains (Human Resources
    Security, Datacenter Security, Business Continuity) are often governed
    by process or certification a code-level review cannot observe; say so
    explicitly rather than guessing at a rating you have no evidence for.

11. **Documented vs. implemented.** Compare architecture documentation
    (Confluence, README, ADRs) against what the code actually does. State
    which side you trust and why. A mismatch is a finding.

Severity: **High** = an exploitable design flaw, a missing control on a
trust boundary, a fail-open path, or uncontained blast radius. **Medium** =
a weakness needing a stated precondition, an unlayered single control, or
an inconsistently applied one. **Low** = hardening, maintainability, or
documentation gap.
