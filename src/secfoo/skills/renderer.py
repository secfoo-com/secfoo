"""Assembles the final prompt sent to an agent CLI from a Skill + target context.

The output contract and safety preamble are defined once here and shared by
every skill, so the dashboard can rely on a consistent report shape
regardless of which skill or agent produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from secfoo.skills.loader import Skill

SAFETY_PREAMBLE = """\
You are performing a READ-ONLY security architectural review. Do not modify,
delete, move, or create any files in the target. Only read and analyze. Do
not run any commands that change state (no installs, no git commits, no
network calls other than fetching the reference material described below).
"""

DEFAULT_EXCLUDE_PATHS = [
    "node_modules/", ".git/", "dist/", "build/", "out/", ".next/", ".nuxt/",
    "venv/", ".venv/", "env/", "__pycache__/", ".pytest_cache/", ".mypy_cache/",
    ".ruff_cache/", "coverage/", ".turbo/", "target/", "vendor/", ".terraform/",
    "*.min.js", "*.min.css", "*.egg-info/", "*.lock",
]

def _exclude_section(extra_excludes: list[str] | None = None) -> str:
    """Scope section listing paths the agent must not read.

    `extra_excludes` are user-supplied (--exclude / [defaults].exclude) and
    are additive on top of DEFAULT_EXCLUDE_PATHS rather than replacing them
    -- excluding one vendored directory should never silently re-enable
    scanning of node_modules. They're called out separately in the prompt
    because a user exclusion means "not my code / out of scope", which is a
    different instruction from "build artifact, nothing of interest".
    """
    section = (
        "## Scope\n"
        "Do not read, analyze, or enumerate files under the following paths — "
        "they are build artifacts, dependencies, or caches, never "
        "security-relevant, and reading them wastes time:\n"
        + ", ".join(f"`{p}`" for p in DEFAULT_EXCLUDE_PATHS)
    )
    cleaned = [p.strip() for p in (extra_excludes or []) if p.strip()]
    if cleaned:
        section += (
            "\n\nThe following paths are explicitly OUT OF SCOPE for this "
            "assessment — they are not part of the system under review "
            "(vendored copies, unrelated checked-out repositories, test "
            "fixtures). Do not read them, do not report findings in them, "
            "and do not count them in your inventory or coverage:\n"
            + ", ".join(f"`{p}`" for p in cleaned)
        )
    return section


# Kept for backwards compatibility with anything importing the old constant.
EXCLUDE_SECTION = _exclude_section()


def merge_excludes(*sources: list[str] | None) -> list[str]:
    """Combines exclude lists (config file, CLI flags, web form) into one
    de-duplicated list, preserving first-seen order. Additive by design --
    see _exclude_section.
    """
    merged: list[str] = []
    for source in sources:
        for path in source or []:
            cleaned = path.strip()
            if cleaned and cleaned not in merged:
                merged.append(cleaned)
    return merged

DEPTH_GUIDANCE = {
    "quick": (
        "## Scan depth: QUICK\n"
        "Time is limited — optimize for speed over exhaustiveness. Triage "
        "fast: identify the most important 3-8 findings, prioritizing "
        "Critical/High severity and the most security-relevant entry points "
        "(auth, input handling, secrets, network boundaries). Do not attempt "
        "an exhaustive file-by-file review or enumerate every instance of a "
        "pattern — it's fine to describe a category of concern once with a "
        "representative example rather than listing every occurrence."
    ),
    "standard": (
        "## Scan depth: STANDARD\n"
        "Perform a thorough review covering the full scope of the skill's "
        "checklist above, examining the codebase in depth rather than "
        "sampling."
    ),
}

OUTPUT_CONTRACT = """\
## Required output format

Produce your assessment as a single Markdown document with EXACTLY this
structure (do not add extra top-level sections, do not omit any). Use only
the severity levels specified in the skill instructions above.

# {skill_name} Report

## Summary
2-4 sentence executive summary and an overall risk rating on its own line,
formatted as: **Overall risk rating:** <severity>.

## Findings Register
Immediately after the summary, one compact table covering every finding,
most severe first, for a fast at-a-glance scan -- this doubles as your
severity breakdown, so do not also produce a separate counts table:

| ID | Finding | Severity | CWE | Verdict |
|----|---------|----------|-----|---------|
| F1 | short title | High | CWE-XXX or "unverified" | Confirmed / Conditional / Latent |

If there are no findings at all, state that explicitly instead of an empty
table.

## Findings
Detailed write-up for each finding, same order and IDs as the register
above. For each finding use this exact heading shape (the severity word in
brackets is required and must match the register):

### [SEVERITY] F1: Finding title
- **Severity:** matches the register above
- **CWE:** a specific CWE ID (e.g. CWE-79) only if you're confident it
  applies -- otherwise write "unverified", never guess one
- **Verdict:** `Confirmed` (exploitable as-is), `Conditional` (exploitable
  given a stated precondition -- name the precondition), or `Latent` (a
  real defect that isn't currently reachable)
- **Location:** file path, component, or N/A
- **Description:** what the issue is and why it matters
- **Recommendation:** a concrete, actionable fix — not "review this"

## Coverage Notes
What was reviewed, what was skipped or inaccessible (e.g. a Confluence page
you could not reach), and your confidence level in this assessment.

Output ONLY the Markdown document above as your final response -- no
preamble before it, no commentary, follow-up questions, or offers after it.
Do not save the report to a file yourself; return it directly as your
response text, since it is captured and stored by the caller.
"""



# ---------------------------------------------------------------------------
# Per-activity output contracts
# ---------------------------------------------------------------------------
# Each focused skill (architecture review, threat modeling, SAST, SCA, secret
# scanning) is a distinct professional security activity with a distinct
# deliverable shape -- a dependency upgrade plan and a STRIDE model don't fit
# the same table. They share two invariants so downstream tooling keeps
# working regardless of which skill produced a report:
#   * a `**Overall risk rating:** <severity>` line (report/severity.py parses
#     it to derive the Responsible AI / risk badges), and
#   * `### [SEVERITY] <ID>: <title>` detail headings (report/severity.py
#     counts these into the per-run severity columns, and report/markdown.py
#     turns them into design-system badges).
# Break either one and the dashboard silently reads zero findings.

_REPORT_TRAILER = """\
## Coverage Notes
What was reviewed, what was skipped or inaccessible (e.g. a Confluence page
you could not reach), and your confidence level in this assessment.

Output ONLY the Markdown document above as your final response -- no
preamble before it, no commentary, follow-up questions, or offers after it.
Do not save the report to a file yourself; return it directly as your
response text, since it is captured and stored by the caller.
"""

ARCHITECTURE_REVIEW_OUTPUT_CONTRACT = """\
## Required output format

Produce a single Markdown document with EXACTLY these sections, in order.

# Security Architecture Review Report

## 1. Executive Summary
2-4 sentences, then **Overall risk rating:** <severity> on its own line.

## 2. Scope
Components and directories actually reviewed, documentation consulted (or
"not available"), and anything explicitly out of scope.

## 3. Data Flow Diagram
A **Mermaid** data flow diagram in a fenced ```mermaid block, followed by a
component inventory table. This diagram and the Trust Boundaries table in
section 4 are one artifact, not two -- every edge that crosses a trust
zone gets a boundary ID (`B1`, `B2`, ...) in its label, and section 4 has
exactly one row per ID. A boundary in the table with no matching edge, or
an edge crossing a subgraph with no ID, is an inconsistency -- fix it
before finishing, don't ship a diagram and a table that disagree.

Use `flowchart LR` (or `TD` if the system is deeply layered). Put each
trust zone in its own `subgraph` so the boundaries are visible as the box
edges, and additionally label every boundary-crossing edge with its ID.
Keep it to roughly 12 nodes -- a diagram nobody can read is worse than
none.

```mermaid
flowchart LR
  subgraph untrusted["Untrusted — internet"]
    user([End user])
  end
  subgraph app["Application tier"]
    api["API service"]
    worker["Background worker"]
  end
  subgraph data["Data tier"]
    db[("Primary DB")]
  end
  user -->|"B1: HTTPS, session cookie"| api
  api -->|"B2: parameterized SQL"| db
  api -.->|"B3: job payload"| worker
```

Rules for the diagram, so it renders reliably:
- Always quote node labels that contain spaces, punctuation, or slashes:
  `api["Auth service (OIDC)"]`, never `api[Auth service (OIDC)]`.
- Quote edge labels too: `-->|"B1: user-supplied file"|`.
- Use `-.->` for asynchronous/queued flows and `-->` for synchronous.
- Node IDs must be simple alphanumeric identifiers — no dots or dashes.
- Do not use `click`, `style`, raw HTML, or `<br>` in labels.
- An edge that does NOT cross a trust zone (both ends in the same
  `subgraph`) does not need a boundary ID -- only label those with what
  crosses them, no `Bn:` prefix.

Then the component inventory:

| Component | Purpose | Trust zone | Sensitive data handled |

## 4. Trust Boundaries
| ID | Boundary | What crosses it | Enforced by | Gap |
|----|----------|------------------|--------------|-----|
| B1 | Internet → API service | HTTPS request, session cookie | TLS termination + session middleware | — |

Every ID must appear on an edge in the section 3 diagram, and every
boundary-crossing edge in the diagram must have a row here -- this is a
single cross-referenced artifact, checked both directions. State
explicitly whether this section is derived from documentation or from
code alone -- do not blend the two silently.

## 5. Security Controls Matrix
The core of a control-centric review -- presence, placement, and layering
are three separate judgements:

| Control | Present | Correctly placed | Layered behind | Evidence |

Present / Correctly placed are Yes / Partial / No. "Layered behind" names
what still protects the asset if this control fails, or "nothing". Cover
at least: authentication, authorization, input validation, output
encoding, transport security, encryption at rest, secret management,
logging/audit, session management, CORS/security headers, rate limiting,
tenant isolation, dependency management.

## 6. Design Principles Assessment
| Principle | Verdict | Evidence |

Verdict is Upheld / Partial / Violated. Assess exactly these:
- **Least privilege (topology vs. policy)** -- enforced by structure
  (scoped credentials, segmentation, distinct identities) or merely
  asserted in config a single mistake could undo?
- **Fail-safe defaults** -- when an auth/policy/rate-limit dependency is
  unavailable, does the system deny or fail open? Trace the authn and
  authz paths explicitly.
- **Defense in depth** -- any single point of control failure with
  nothing behind it?
- **Blast radius containment** -- if one component, credential, or tenant
  is fully compromised, what else follows?
- **Separation of duties** -- duties that should be split but are not.
- **Complete mediation** -- can any path reach a sensitive sink while
  bypassing the control that guards the others?

## 7. Operational & Regulatory Fit
Non-adversarial coverage, still in scope for a design review:

| Area | Status | Notes |

Cover: backup/restore, disaster recovery, key management lifecycle
(issuance, scope, rotation, revocation -- can a leaked credential be
rotated without a code change?), audit trail durability, observability of
security events, and maintainability. Then state the regulatory/standards
position: any framework or baseline the project claims (SOC 2, ISO 27001,
PCI, HIPAA, GDPR, internal standard) and whether the design is consistent
with it. If it handles regulated data while claiming nothing, say so.

## 8. CCM Domain Conformance
Rate this design against all 17 CSA Cloud Controls Matrix (CCM v4)
domains, in EXACTLY this order (do not omit or reorder any):

| Domain | Code | Conformance | Evidence |
|--------|------|--------------|----------|
| Audit & Assurance | A&A | Partial | one-line evidence |
| Application & Interface Security | AIS | ... | ... |
| Business Continuity Management and Operational Resilience | BCR | ... | ... |
| Change Control and Configuration Management | CCC | ... | ... |
| Cryptography, Encryption & Key Management | CEK | ... | ... |
| Datacenter Security | DCS | ... | ... |
| Data Security and Privacy Lifecycle Management | DSP | ... | ... |
| Governance, Risk and Compliance | GRC | ... | ... |
| Human Resources Security | HRS | ... | ... |
| Identity & Access Management | IAM | ... | ... |
| Interoperability & Portability | IPY | ... | ... |
| Infrastructure & Virtualization Security | IVS | ... | ... |
| Logging and Monitoring | LOG | ... | ... |
| Security Incident Management, E-Discovery, and Cloud Forensics | SEF | ... | ... |
| Supply Chain Management, Transparency, and Accountability | STA | ... | ... |
| Threat & Vulnerability Management | TVM | ... | ... |
| Universal Endpoint Management | UEM | ... | ... |

Conformance is exactly one of:
- `Conformant` -- the design meets this domain's intent, with evidence
- `Partial` -- meets it in some places, not others; the Evidence column
  must say which
- `Non-conformant` -- a real gap; this MUST also appear as a finding in
  section 9
- `Not Assessed (process-assured)` -- this domain is governed by an
  external process, certification, or organizational control a code-level
  review cannot observe (e.g. Human Resources Security, Datacenter
  Security for a cloud-hosted system, Business Continuity for a
  documented-elsewhere DR program). Use this rather than guessing at
  something outside what you can actually verify from the codebase.
- `Not Applicable` -- the domain doesn't apply to this system at all;
  say why in Evidence

## 9. Findings Register
| ID | Finding | Severity | Category | Standard | Verdict |
|----|---------|----------|----------|----------|---------|
| A1 | short title | High | Authorization | ISO 27001 A.9 | Confirmed |

Category is one of: Authentication, Authorization, Secrets Management,
Data Protection, Isolation, Logging & Audit, Input Handling, Dependency
Governance, Recoverability, Regulatory. Standard is the specific clause of
a named framework this finding violates (e.g. "SOC 2 CC6.1", "PCI DSS
Req 8", "Internal: Auth Standard v2") when you're confident one applies,
or "N/A" -- never guess a clause number. If there are no findings, say so
explicitly rather than emitting an empty table.

## 10. Detailed Findings
Same order and IDs as the register. Exact heading shape required:

### [SEVERITY] A1: Finding title
- **Severity:**, **Category:**, **Standard:**, **Verdict:** (`Confirmed`
  / `Conditional` -- name the precondition / `Latent`)
- **Location:** component or `file:line`
- **Description:** the design weakness and why it matters
- **Recommendation:** the specific control, where it belongs, and what it
  should be layered with

## 11. Documentation vs. Implementation
Mismatches between documented and actual behavior, or "no documentation
available for comparison". State which side you trust and why.

## 12. Design Verdict & Remediation Roadmap
Open with an explicit verdict on one line: **Design verdict:** Sound /
Sound with conditions / Not sound -- this review is often gated to a
milestone, so the reader needs a clear answer, not just a finding list.
If "Sound with conditions", state the conditions.

Then findings grouped P0 (blocking) through P3, grouping items that share
one root fix.

""" + _REPORT_TRAILER

THREAT_MODELING_OUTPUT_CONTRACT = """\
## Required output format

Produce a single Markdown document with EXACTLY these sections, in order.

# Threat Modeling Report

## 1. Executive Summary
2-4 sentences, then **Overall risk rating:** <severity> on its own line,
then **Model depth:** Full / Feature-level / Lightweight on its own line
(Full = whole system, Feature-level = one feature or new data flow,
Lightweight = a fast checklist pass -- say which honestly rather than
overclaiming), then a compact risk heat map -- Likelihood rows (High/
Medium/Low) x Impact columns (High/Medium/Low), each cell listing the
threat IDs landing there (blank cells are fine).

## 2. Scope & Assets
Components, entry points, and the assets worth attacking (data,
credentials, compute, availability, model/IP).

## 3. Trust Boundaries & Data Flow
A **Mermaid** diagram in a fenced ```mermaid block, plus a Trust
Boundaries table. This diagram and the table are one cross-referenced
artifact, exactly like the Security Architecture Review skill: every
boundary-crossing edge in the diagram gets a `Bn` ID in its label, and
the table has exactly one row per ID -- a threat model is only as current
as this baseline, so it must be internally consistent.

Use `flowchart LR`, one `subgraph` per trust zone. Quote every label
containing spaces or punctuation (`api["Auth service (OIDC)"]`), keep
node IDs alphanumeric, avoid `click`/`style`/raw HTML, and label
boundary-crossing edges `-->|"B1: what crosses it"|`.

| ID | Boundary | What crosses it |
|----|----------|------------------|
| B1 | Internet -> API | HTTPS request |

## 4. Assumptions
What this model takes as given, rather than verifies itself (e.g.
"upstream API gateway authenticates all requests", "the deployment
platform isolates tenants at the network layer"). Every threat model
rests on assumptions like these -- stating them is what lets someone
later notice one stopped holding.

| ID | Assumption | Validity | Note |
|----|------------|----------|------|
| X1 | Upstream gateway authenticates all requests | Holds | Verified: gateway config requires JWT on all routes |

Validity is exactly one of:
- `Holds` -- you found evidence in the code/config confirming it
- `Falsified` -- you found evidence CONTRADICTING it; this MUST also
  produce a corresponding threat in the register below, since a falsified
  assumption is exactly where the model was wrong
- `Unverified` -- plausible but you found no evidence either way from
  this codebase alone (common for assumptions about infrastructure or
  other teams' services)

## 5. Adversary Classes
| Adversary | Starting capability | Motivation |

Only classes that plausibly apply to this system.

## 6. STRIDE Analysis
Rows are components/entry points from section 3, columns are S / T / R /
I / D / E. Fill a cell only where there is a concrete, evidenced concern;
leave it blank otherwise -- an empty column is itself the signal that this
category was never exercised, not that the system is safe from it.

## 7. Privacy Threats (LINDDUN)
ONLY if the system processes personal data. Same table shape, columns
Linkability / Identifiability / Non-repudiation / Detectability /
Disclosure / Unawareness / Non-compliance. If no personal data is in
scope, keep the heading and write one line saying so -- do not invent
privacy threats for a system that has none.

## 8. Threat Register
| ID | Threat | Archetype | Asset Class | Boundary | STRIDE | Severity | Disposition | Test Reference |
|----|--------|-----------|-------------|----------|--------|----------|--------------|-----------------|
| T1 | short title | Unauthenticated internal service call | Process | B1 | E | High | Gap | none |

- **Archetype** is a SHORT, REUSABLE phrase (2-6 words) naming the
  *pattern*, not the specific instance -- "Unauthenticated internal
  service call", "Unbounded tool invocation", "Unsigned pipeline
  artifact". The same archetype should recur verbatim across different
  systems and different reviews when the underlying pattern repeats; that
  recurrence is what turns per-system findings into platform-level
  mitigation work, so don't invent a bespoke phrase per finding.
- **Asset Class** is exactly one of: `External Entity`, `Process`, `Data
  Store`, `Data Flow`, `Model/Agent` (the classic DFD element types, plus
  Model/Agent for an AI model or agent as the thing under threat).
- **Boundary** is the `Bn` ID from section 3 that this threat crosses, or
  `N/A` for a threat that's internal to one trust zone.
- **Disposition** is exactly one of **Mitigated** / **Gap** / **Accepted**
  / **Transferred** (risk moved to another party -- insurance, a vendor
  contract, a different team's ownership; say which in Detailed Threats).
  Every threat must carry one -- an undispositioned threat is an
  incomplete model.
- **Test Reference** is a specific test name/ID that exercises this
  mitigation, or `none`. A `Mitigated` disposition with `none` here is a
  claimed-but-unverified mitigation -- exactly the gap between "we added
  a control" and "we proved it works".

If there are no credible threats, state that explicitly instead of an
empty table.

## 9. Detailed Threats
Same order and IDs as the register. Exact heading shape required:

### [SEVERITY] T1: Threat title
- **Archetype:**, **Asset Class:**, **Boundary:**, **STRIDE:** (or LINDDUN
  category), **Likelihood x Impact:**
- **Precondition:** what the attacker needs first ("none" if anonymous)
- **Attack path:** the concrete steps, referencing real code/components
- **Disposition:** `Mitigated` (name the existing control and where it
  lives), `Gap` (name the control that should exist), `Accepted` (state
  the justification and who would need to own that acceptance), or
  `Transferred` (name who/what now carries the risk)
- **Test Reference:** the test that exercises the mitigation, or "none"
- **Residual risk:** what remains after the disposition above

## 10. Attack Chains
Chains of 2-4 steps (foothold -> pivot -> impact) referencing threat IDs.
Map to MITRE ATT&CK technique IDs only where you can verify them -- write
"unverified" rather than guessing. If nothing chains, say so rather than
forcing one.

## 11. Detection Opportunities
| Threat ID | What to monitor | Signal |

For each High/Medium threat, what would reveal exploitation in progress
(logs, metrics, alerts, WAF rules). A threat that can be neither mitigated
nor detected deserves saying so plainly.

## 12. Residual Risk Statement
The honest bottom line: with the dispositions above in place, what risk
remains and at what level? List every `Gap`, `Accepted`, and `Transferred`
threat, since together they ARE the residual risk. Do not imply the
system is safe merely because threats were enumerated. State which
STRIDE/LINDDUN categories were actually exercised (had at least one
evidenced cell) versus entirely skipped -- a coverage claim, not just a
finding list.

## 13. Mitigation Roadmap
Threats grouped P0 (blocking) through P3.

""" + _REPORT_TRAILER

SAST_OUTPUT_CONTRACT = """\
## Required output format

Produce a single Markdown document with EXACTLY these sections, in order.

# SAST Report

## 1. Executive Summary
2-4 sentences, then **Overall risk rating:** <severity> on its own line,
then a severity count table (Severity | Count).

## 2. Scope
Languages and frameworks detected, directories actually reviewed, and what
was excluded.

## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | short title | High | CWE-89 | A03:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | `app/db.py:42` | Confirmed |

CWE and OWASP entries must be specific or "unverified" -- never guessed.
CVSS Vector must be a complete CVSS v3.1 base vector (all eight metrics:
AV/AC/PR/UI/S/C/I/A) describing this finding's own attack surface,
privileges required, and blast radius as you assessed it from the code --
secfoo computes the numeric score from this vector itself, using the
public CVSS v3.1 formula; do not also state a numeric score yourself, and
do not write "unverified" here -- reason through the eight characteristics
the same way you already reasoned through CWE/OWASP for this finding.
If there are no findings, state that explicitly instead of an empty table.

## 4. Detailed Findings
Same order and IDs as the register. Exact heading shape required:

### [SEVERITY] F1: Finding title
- **Severity:**, **CWE:**, **OWASP:**, **Verdict:** (`Confirmed` /
  `Conditional` -- name the precondition / `Latent`)
- **Location:** `file:line`
- **Description:** the vulnerability and the exploit path
- **Vulnerable code:** a short fenced snippet of the actual code (a few
  lines, not the whole function)
- **Recommendation:** a concrete fix -- not "review this"

## 5. Taint Summary
| Source | Sink | Path | Sanitized? |

One row per traced data flow. Omit this table's rows (but keep the
section, saying so) if no untrusted-input flows were found.

## 6. Remediation Roadmap
Findings grouped P0 (blocking) through P3, grouping items sharing a root
fix.

## 7. Code-Fix Appendix
For P0/P1 findings, a short illustrative fix as a fenced ```diff block.
Label each clearly as illustrative and untested, not a verified patch.

""" + _REPORT_TRAILER

SCA_OUTPUT_CONTRACT = """\
## Required output format

Produce a single Markdown document with EXACTLY these sections, in order.
This report is dependency-centric: the unit of analysis is a package, not
a line of code.

# SCA Report — Reachability & Upgrade Triage

## 1. Executive Summary
2-4 sentences, then **Overall risk rating:** <severity> on its own line,
then counts of reachable vs. conditionally reachable vs. not-reachable
risks.

## 2. Dependency Inventory
| Package | Version | Direct/Transitive | Ecosystem | Source manifest |

List direct dependencies in full. If the transitive set is large, include
only the security-relevant ones and say explicitly that you did so.

## 3. Version Hygiene
Unbounded ranges, missing lockfiles, wildcard pins, and stale or
unmaintained packages -- as a short table or bullet list.

## 4. Risk Register
| ID | Package | Version | Issue | Severity | Reachability | Fixed in |
|----|---------|---------|-------|----------|--------------|----------|
| D1 | pkg | 1.2.3 | class of issue | High | Reachable | 1.2.9 |

Reachability is exactly one of: Reachable / Conditionally reachable /
Not reachable. Never invent a CVE ID -- write "unverified" and describe
the issue class instead. If there are no notable risks, state that.

## 5. Detailed Findings
Same order and IDs as the register. Exact heading shape required:

### [SEVERITY] D1: package@version — short issue title
- **Package / version:**, **CVE:** (specific ID or "unverified"),
  **Severity:**
- **Reachability:** Reachable / Conditionally reachable / Not reachable,
  with the evidence -- cite `file:line` where the affected API is called,
  or state what you checked to conclude it isn't
- **Fixed in:** target version, and whether it's a patch/minor/major bump
- **Breaking changes:** what to expect on upgrade, or "none expected"
- **Recommendation:** the concrete upgrade or mitigation action

## 6. Reachability Summary
| Package | Affected API | Called from | Verdict |

## 7. Upgrade Plan
Grouped by priority P0-P3: target versions, bump type, transitive
constraints that block the upgrade, and which upgrades must ship
together.

## 8. Supply-Chain Hygiene
Install-time scripts, non-registry sources (git URLs, direct tarballs),
recently-transferred or typosquat-prone packages, and plain-HTTP fetches.

""" + _REPORT_TRAILER

SECRET_SCANNING_OUTPUT_CONTRACT = """\
## Required output format

Produce a single Markdown document with EXACTLY these sections, in order.

# Secret Scanning Report

## 1. Executive Summary
2-4 sentences, then **Overall risk rating:** <severity> on its own line,
then counts by severity and by source (code / config / history / docs).

## 2. Scope
Paths scanned, whether version-control history was checked (and how far
back), and which documentation/Confluence sources were reached. If a
provided documentation source could NOT be reached, say so here as well
as in Coverage Notes -- an unscanned doc source is a gap, not a pass.

## 3. Findings Register
| ID | Secret type | Location | Source | Validity | Severity |
|----|-------------|----------|--------|----------|----------|
| S1 | AWS access key | `deploy/ci.yml:14` | config | Looks live | High |

Source is one of: code, config, history, docs. Validity is one of: Looks
live, Unclear, Placeholder. If nothing was found, state that explicitly
instead of an empty table.

## 4. Detailed Findings
Same order and IDs as the register. Exact heading shape required:

### [SEVERITY] S1: <secret type> in <location>
- **Type:**, **Source:**, **Validity:**
- **Location:** `file:line`, or page title + URL for documentation
- **Evidence:** a REDACTED fragment only -- at most ~8 leading characters
  (e.g. `AKIAJ4F2...`). Never reproduce a full secret value.
- **Exposure:** who can see it and what it unlocks
- **Remediation:** for any real secret this MUST begin with rotating the
  credential; removing the line alone is never sufficient

## 5. Documentation & Confluence Coverage
| Source | Reached? | Secrets found |

One row per documentation source provided or discovered.

## 6. Remediation Roadmap
P0 first and it must be the rotation list -- every credential that needs
rotating now, then P1-P3 for cleanup (history rewrite, ignore rules,
moving to a secret manager).

## 7. Prevention
Concrete controls: `.gitignore` entries, pre-commit secret scanning, CI
secret detection, and secret-manager adoption -- tailored to what this
project actually lacks.

""" + _REPORT_TRAILER

THIRD_PARTY_RISK_ASSESSMENT_OUTPUT_CONTRACT = """\
## Required output format

Produce a single Markdown document with EXACTLY these sections, in order.

# Third-Party Risk Assessment Report

## 1. Executive Summary
2-4 sentences on overall vendor risk posture, then **Overall risk rating:**
<severity> on its own line, then how many of the 17 CCM domains had usable
evidence (e.g. "6 of 17 domains had supporting evidence; the rest were Not
Assessed").

## 2. Documents Reviewed
| Document | Apparent type | Notes |
|----------|----------------|-------|
| soc2-2025.pdf | SOC 2 Type II report | Audit period 2025-01 to 2025-12 |

One row per document actually provided in the target. If a document's
text could not be extracted (empty or near-empty content), say so in
Notes rather than omitting the row.

## 3. CCM Domain Conformance
Rate this vendor against all 17 CSA Cloud Controls Matrix (CCM v4)
domains, in EXACTLY this order (do not omit or reorder any):

| Domain | Code | Conformance | Evidence |
|--------|------|--------------|----------|
| Audit & Assurance | A&A | Not Assessed (no evidence provided) | -- |
| Application & Interface Security | AIS | ... | ... |
| Business Continuity Management and Operational Resilience | BCR | ... | ... |
| Change Control and Configuration Management | CCC | ... | ... |
| Cryptography, Encryption & Key Management | CEK | ... | ... |
| Datacenter Security | DCS | ... | ... |
| Data Security and Privacy Lifecycle Management | DSP | ... | ... |
| Governance, Risk and Compliance | GRC | ... | ... |
| Human Resources Security | HRS | ... | ... |
| Identity & Access Management | IAM | ... | ... |
| Interoperability & Portability | IPY | ... | ... |
| Infrastructure & Virtualization Security | IVS | ... | ... |
| Logging and Monitoring | LOG | ... | ... |
| Security Incident Management, E-Discovery, and Cloud Forensics | SEF | ... | ... |
| Supply Chain Management, Transparency, and Accountability | STA | ... | ... |
| Threat & Vulnerability Management | TVM | ... | ... |
| Universal Endpoint Management | UEM | ... | ... |

Conformance is one of: Conformant, Partial, Non-conformant, or
"Not Assessed (no evidence provided)". Evidence cites the specific
document (and page/section when identifiable) -- never a guess.

## 4. Findings
| ID | Finding | Severity | CCM Domain | Evidence |
|----|---------|----------|------------|----------|
| V1 | short title | High | IAM | which document says so |

If there are no findings, state that explicitly instead of an empty table.

## 5. Detailed Findings
Same order and IDs as the register. Exact heading shape required:

### [SEVERITY] V1: Finding title
- **Severity:**, **CCM Domain:**
- **Evidence:** which document (and page/section if identifiable)
- **Description:** what's missing, contradictory, or concerning, and why
- **Recommendation:** what documentation or remediation would close this gap

## 6. Recommendation
One of: Approve / Approve with conditions / Needs more documentation /
Reject, with the specific conditions or missing documentation named.

""" + _REPORT_TRAILER

# Skill id -> its own contract. Anything absent falls back to the shared
# OUTPUT_CONTRACT (which is parameterized by skill name).
SKILL_OUTPUT_CONTRACTS = {
    "security-architecture-review": ARCHITECTURE_REVIEW_OUTPUT_CONTRACT,
    "threat-modeling": THREAT_MODELING_OUTPUT_CONTRACT,
    "sast": SAST_OUTPUT_CONTRACT,
    "sca-reachability": SCA_OUTPUT_CONTRACT,
    "secret-scanning": SECRET_SCANNING_OUTPUT_CONTRACT,
    "third-party-risk-assessment": THIRD_PARTY_RISK_ASSESSMENT_OUTPUT_CONTRACT,
}


@dataclass(frozen=True)
class TargetContext:
    kind: Literal["local", "github"]
    local_path: Path
    display_source: str
    confluence_urls: list[str] = field(default_factory=list)


def _target_section(target: TargetContext) -> str:
    lines = [
        "## Target",
        f"Inspect the codebase at: `{target.local_path}`",
    ]
    if target.kind == "github":
        lines.append(
            f"This is a temporary shallow clone of the GitHub repository "
            f"`{target.display_source}` — reference that URL (not the local "
            f"temp path) in your report when identifying the target."
        )
    else:
        lines.append(f"Original source path: `{target.display_source}`")
    return "\n".join(lines)


def _confluence_section(target: TargetContext) -> str | None:
    if not target.confluence_urls:
        return None
    urls = "\n".join(f"- {url}" for url in target.confluence_urls)
    return (
        "## Additional context (Confluence)\n"
        "The following Confluence pages may contain relevant architectural "
        "or compliance context. If you have MCP tooling or another means of "
        "fetching URLs available, retrieve and incorporate them. If not, "
        "note that gap under Coverage Notes and proceed without them:\n"
        f"{urls}"
    )


def render_prompt(
    skill: Skill,
    target: TargetContext,
    *,
    depth: Literal["quick", "standard"] = "quick",
    exclude_paths: list[str] | None = None,
) -> str:
    sections = [
        SAFETY_PREAMBLE,
        f"## Skill: {skill.name}\n{skill.body}",
        DEPTH_GUIDANCE[depth],
        _target_section(target),
        _exclude_section(exclude_paths),
    ]
    confluence = _confluence_section(target)
    if confluence:
        sections.append(confluence)
    contract = SKILL_OUTPUT_CONTRACTS.get(skill.id)
    sections.append(contract or OUTPUT_CONTRACT.format(skill_name=skill.name))
    return "\n\n".join(sections)
