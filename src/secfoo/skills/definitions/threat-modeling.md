---
id: threat-modeling
name: Threat Modeling
description: Adversary-centric enumeration — STRIDE, attack chains, optional LINDDUN privacy threats, assumptions validated, each threat dispositioned (mitigated/gap/accepted/transferred) and residual risk stated explicitly.
short_name: Threat Modeling
version: 3
---

Answer one question: **what could go wrong, and who would make it go
wrong?** This is adversary-centric and generative — you start from assets
and trust boundaries and systematically enumerate threats, then disposition
each one.

This is deliberately NOT a design-soundness review. Do not produce a
security controls matrix or judge the architecture against standards —
that is the Security Architecture Review skill's job. Your output is a
ranked threat list with residual risk stated explicitly.

0. **Frame the model.** Components, entry points, trust boundaries, and the
   assets worth attacking (data, credentials, compute, availability,
   model/IP). Keep this brief — it exists to frame the threats. State your
   model depth honestly: a whole-system review (Full), one feature or new
   data flow (Feature-level), or a fast checklist pass (Lightweight) —
   this determines how much weight the model should be given later, so
   don't overclaim it.

1. **Trust boundaries, cross-referenced.** Every boundary you place on the
   diagram gets an ID, and every threat that crosses one cites it — the
   diagram, the boundary table, and the threat register are one
   cross-referenced artifact, not three independent write-ups. See the
   output format below for the exact scheme (shared with the Security
   Architecture Review skill).

2. **Assumptions.** What does this model take as given rather than verify
   itself — "the upstream gateway authenticates", "the platform isolates
   tenants at the network layer"? For each, say whether the codebase
   actually confirms it (Holds), contradicts it (Falsified — and raise the
   corresponding threat), or you simply can't tell from this codebase
   alone (Unverified). A model's assumptions are exactly where it's wrong
   when the system changes and nobody revisits them.

3. **Adversary classes.** Who plausibly attacks this — unauthenticated
   internet user, authenticated low-privilege user, malicious tenant,
   compromised dependency, untrusted input reaching an AI agent, insider?
   List only classes that actually apply, with the capability each starts
   with. A threat's severity depends heavily on which adversary can reach
   it.

4. **STRIDE per component.** For each component/entry point consider
   Spoofing, Tampering, Repudiation, Information disclosure, Denial of
   service, and Elevation of privilege. Record a threat only where there
   is a concrete, evidenced concern — leave a cell blank rather than
   filling it for symmetry. An empty column is itself the signal that the
   category was never exercised, not that the system is safe from it.

5. **Privacy threats (LINDDUN) — only if personal data is in scope.** If
   the system handles personal data, additionally consider Linkability,
   Identifiability, Non-repudiation, Detectability, Disclosure of
   information, Unawareness, and Non-compliance. Skip this section
   entirely, saying so, when no personal data is processed — do not
   invent privacy threats for a system that has none.

6. **Name the pattern, not just the instance.** Each threat gets a short,
   reusable archetype phrase (e.g. "Unauthenticated internal service
   call", "Unbounded tool invocation") in addition to its specific title —
   the same archetype should recur verbatim when the same underlying
   pattern shows up elsewhere, since that recurrence is what turns
   scattered per-system findings into a platform-level fix.

7. **Attack chains.** Where do individual weaknesses combine into a
   realistic kill chain (foothold → pivot → impact)? A chain of two
   Mediums often outranks an isolated High; call that out when it happens.

8. **Disposition every threat, and say whether it's tested.** Each threat
   ends in exactly one of:
   - **Mitigated** — an existing control breaks it. Name the control and
     where it lives, and cite the test that proves it works (or "none" if
     the mitigation is unverified — a real and common state worth
     surfacing honestly, not glossing over).
   - **Gap** — nothing currently stops it. Name the control that should.
   - **Accepted** — plausible but a reasonable risk to carry. State the
     justification and who would need to own that acceptance.
   - **Transferred** — the risk now sits with another party (insurance, a
     vendor contract, a different team). Name who/what.
   A threat with no disposition is an incomplete model.

9. **Residual risk.** After dispositions, state plainly what risk remains
   and at what level — Gap, Accepted, AND Transferred threats all count.
   Do not imply the system is safe because threats were enumerated. State
   which STRIDE/LINDDUN categories were actually exercised versus
   entirely skipped — a coverage claim, not just a finding list.

10. **Detection.** For High/Medium threats, what would reveal exploitation
    in progress (logs, metrics, alerts, WAF rules)? A threat that cannot
    be detected and cannot be mitigated is worse than one that can be
    seen.

Rate each threat by Likelihood × Impact, and state explicitly the
precondition an attacker needs — a threat requiring pre-existing admin
access is not the same as one reachable anonymously.

Severity: **High** = realistic path to significant impact. **Medium** =
requires a stated precondition, or yields limited impact. **Low** = largely
theoretical or already heavily mitigated.
