---
id: third-party-risk-assessment
name: Third-Party Risk Assessment
description: Evaluates vendor-provided security documentation against the CSA CCM v4 framework.
short_name: Third-Party Risk
version: 1
---

Review the vendor-provided documents in the target. These are
extracted-text copies of a vendor's own security documentation --
SOC 2 reports, ISO 27001 certificates, penetration test reports, completed
security questionnaires, policy excerpts, and similar -- not source code.
There is no codebase here; do not go looking for one, and do not treat the
absence of code as a gap to report.

Some files may extract with little or no usable text (a scanned/image-only
PDF, a corrupted upload, an unsupported format) -- say so plainly in the
Documents Reviewed section rather than silently working around it or
guessing at content that isn't there.

For each of the 17 CSA Cloud Controls Matrix (CCM v4) domains, determine
whether the provided documents contain actual evidence of conformance --
never rate a domain from assumption or general reputation ("they're a
well-known vendor, so they probably..."). A vendor's marketing claims are
not evidence; a specific control description, audit finding, or
certification scope statement is. When a document claims a certification
or audit result, state exactly what it claims (scope, date, standard
version) and nothing beyond that -- never infer a broader guarantee than
what's actually written.

Rate each domain:
- **Conformant** -- clear, specific evidence in at least one document.
- **Partial** -- some evidence, but with gaps, caveats, exclusions, or an
  expired/stale audit date.
- **Non-conformant** -- a document itself describes a gap, exception, or
  finding against that domain.
- **Not Assessed (no evidence provided)** -- none of the provided
  documents say anything about this domain. This is the correct rating
  for most domains most of the time; do not stretch unrelated text to
  cover a domain just to avoid this rating.

Cite which specific document (by filename) supports each rating, and the
relevant section/page when the document makes that identifiable.

Findings are gaps: missing evidence for a domain that should reasonably be
covered by what a vendor of this type would be expected to provide,
contradictions between documents, concerning findings stated in the
documents themselves (e.g. a pen test report listing unremediated
critical findings, a SOC 2 report with qualified/exception opinions), or
stale/expired certifications.

End with an overall recommendation for this vendor: Approve, Approve with
conditions (name them), Needs more documentation (name exactly what's
missing), or Reject (name why) -- grounded in the domain ratings and
findings above, not a separate impression.
