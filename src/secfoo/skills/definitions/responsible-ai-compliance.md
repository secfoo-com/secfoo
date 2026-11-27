---
id: responsible-ai-compliance
name: Responsible AI Compliance
description: Checks for responsible-AI governance, transparency, and fairness practices.
short_name: Responsible AI
version: 1
---

Review this codebase and any accompanying documentation for responsible AI
governance and compliance practices.

1. **Documentation.** Is there a model card, data card, or equivalent
   documentation describing the model(s) used, their intended use, known
   limitations, and training/fine-tuning data provenance?

2. **Bias & fairness.** Is there any evidence of bias or fairness testing
   against protected characteristics? Are there known failure modes or
   subgroups documented?

3. **Human oversight.** For high-stakes or irreversible decisions made or
   influenced by the model, is there a human-in-the-loop review step or an
   escalation path? Is fully autonomous action limited to lower-stakes
   cases?

4. **Transparency to end users.** Are users clearly informed when they are
   interacting with an AI system, and when AI has materially influenced a
   decision that affects them?

5. **Data provenance & consent.** For any training, fine-tuning, or
   retrieval data, is there documentation of where it came from and whether
   appropriate consent/licensing was obtained?

6. **Framework alignment.** If the project references a specific governance
   framework (e.g. NIST AI RMF, EU AI Act risk tiers, an internal AI policy),
   check whether the implementation is consistent with the claimed tier or
   requirements. If no framework is referenced at all but the system appears
   to be a high-impact use case, flag the absence of a documented risk tier
   as a finding.

7. **Auditability & recourse.** Is there an audit trail of significant AI
   decisions? Is there a mechanism for a user to contest or appeal an
   AI-influenced decision?

In the report's Dimension Coverage table, include a row for EVERY one of
these seven dimensions, in the order above, even when there is no finding:
mark such a dimension `adequate` and cite the concrete evidence that
supports that call (a file, a section, a control), never just "none". Use
`partial`, `missing` or `not applicable` with evidence when that is what
the code shows. A CWE ID is not expected in a Responsible AI report -- the
report's register uses a Dimension column and an optional Framework column
(NIST AI RMF function, EU AI Act article or risk class, or an internal
policy ID) instead of a CWE and a finding verdict. If an AI-BOM is attached
to this assessment, its models are listed in the brief as reference data;
compare them with the models you find in code and name both sides of any
mismatch in the AI System Profile.

Severity (this drives the assessment's overall risk rating, so ground it
in what's actually true of this system rather than a general impression):
**High** = the system makes or materially influences a high-stakes,
irreversible, or rights-affecting decision about a person (eligibility,
access, employment, legal/financial standing, biometric identification,
safety) AND at least one of human oversight, transparency to the affected
person, or auditability/recourse is missing or clearly inadequate.
**Medium** = a high-stakes use case exists but the missing pieces above
are partial, not absent (e.g. an oversight step exists but isn't
consistently applied; documentation exists but omits known limitations).
**Low** = no high-stakes or rights-affecting decision is made by the
system, or every dimension above is adequately covered for the stakes
involved.
