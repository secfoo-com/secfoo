---
id: sast
name: SAST — Static Code Analysis
description: Code-level vulnerability review with taint paths, CWE mapping, and concrete fixes.
short_name: SAST
version: 1
---

Perform a static application security review of the source code. Stay at
the code level — design gaps belong to the Security Architecture Review
skill and dependency risk to the SCA skill.

Prioritize these classes, roughly in this order:

1. **Injection.** SQL/NoSQL, OS command, LDAP, template, XPath, and header
   injection. Trace from an untrusted source (HTTP request, file, env,
   agent/LLM output) to a dangerous sink; report only where the path is
   real and you can cite both ends.

2. **Cross-site scripting & output encoding.** Unescaped rendering,
   `dangerouslySetInnerHTML` / `|safe` / `v-html`, autoescaping disabled,
   and raw HTML passthrough in Markdown or template renderers.

3. **Path traversal & file handling.** Client-controlled filenames or
   paths reaching filesystem APIs, unsafe archive extraction (zip-slip),
   and unrestricted upload type/size.

4. **Deserialization & dynamic execution.** `pickle`, `yaml.load`,
   `eval`, `exec`, dynamic import, unsafe reflection, and template
   injection via user-controlled template strings.

5. **AuthN/AuthZ enforcement in code.** Missing checks on state-changing
   handlers, IDOR (object lookups not scoped to the caller), and
   privilege checks that run *after* a side effect.

6. **Cryptography & randomness.** Weak or legacy algorithms, ECB mode,
   static/reused IVs, `random` used for security purposes, homemade
   crypto, and disabled TLS certificate verification.

7. **SSRF & unsafe outbound requests.** User-controlled URLs, missing
   host allowlists, and redirect-following into internal ranges.

8. **Hardcoded credentials.** Note them here briefly — the Secret
   Scanning skill covers this in depth.

9. **Error handling & information leakage.** Stack traces or internal
   detail returned to callers; secrets or tokens written to logs.

For every finding give `file:line`, the exploit path in one or two
sentences, a CWE ID **only** when you are confident it applies, and a
concrete fix. Never report a finding you have not actually located in the
code — an empty report is far better than a fabricated one.

Severity: **High** = exploitable and reachable from untrusted input.
**Medium** = exploitable given a stated precondition. **Low** =
defense-in-depth, or a real defect that isn't currently reachable.

For every finding, also state a full CVSS v3.1 base vector (all eight
metrics: AV/AC/PR/UI/S/C/I/A) — you already know everything it takes from
tracing the finding itself, so reason through each one directly:

- **AV** (Attack Vector): can the exploit path be reached over a network
  (`N`), only from the adjacent network (`A`), only with local access
  (`L`), or only with physical access (`P`)? An internet-facing HTTP
  handler is `N`; a CLI flag only an operator on the host can set is `L`.
- **AC** (Attack Complexity): does exploitation work reliably as-is (`L`),
  or does it depend on conditions outside the attacker's control — a race,
  a specific config, information they'd have to gather first (`H`)?
- **PR** (Privileges Required): does the attacker need no account (`N`),
  a regular authenticated account (`L`), or admin-level access (`H`)
  before reaching this code path?
- **UI** (User Interaction): does exploitation require another person to
  do something (click a link, open a file) (`R`), or does it fire with no
  one else involved (`N`)?
- **S** (Scope): does exploiting this let the attacker affect resources
  beyond what this component itself controls — e.g. a container escape, or
  a vulnerable library affecting the whole host — (`C`), or does the
  impact stay within this component's own security authority (`U`)? Most
  application-level findings are `U`.
- **C/I/A** (Confidentiality/Integrity/Availability impact): for each,
  none (`N`), some limited exposure/tampering/disruption (`L`), or total
  compromise of that property (`H`) — judged from what this specific
  finding actually lets an attacker read, change, or take down, not the
  worst case for the whole application.

Do not compute or state a numeric score yourself — only the vector; the
score is derived from it deterministically elsewhere.
