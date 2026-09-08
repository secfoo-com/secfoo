---
id: secret-scanning
name: Secret Scanning — Code, Confluence & Docs
description: Finds exposed credentials in source, config, version-control history, and linked Confluence/documentation.
short_name: Secret Scanning
version: 1
---

Hunt for exposed secrets across code *and* documentation. Documentation is
a first-class target here, not an afterthought — a credential pasted into a
runbook or Confluence page is as dangerous as one committed to code, and
far less likely to be caught by other tooling.

1. **Source & config.** Scan for API keys, tokens, passwords, private
   keys, connection strings, cloud credentials, webhook URLs, and signing
   keys across source, config files, IaC, CI definitions, Dockerfiles,
   notebooks, and test fixtures.

2. **Committed environment files.** `.env`, `.env.*`, `credentials`,
   `*.pem`, `*.p12`, `*.keystore`, `secrets.*`, and service-account JSON —
   check whether they are actually tracked rather than ignored, and
   whether `.gitignore` genuinely covers them.

3. **Version-control history.** If `git log` / `git show` is available,
   check whether a secret was committed and later removed — deleting it
   from the working tree does **not** remove it from history. Report these
   separately, since remediation differs (rotate *and* rewrite history).

4. **Documentation & Confluence.** If Confluence pages or other docs were
   provided (or are reachable via MCP tooling), scan them for pasted
   credentials, connection strings, internal hostnames with embedded
   tokens, and "temporary" passwords in onboarding or runbook pages. If
   you could not reach the documentation, say so explicitly under Coverage
   Notes rather than silently skipping it.

5. **Distinguish real from placeholder.** `password = "changeme"`,
   `sk-xxxxxxxx`, `<YOUR_API_KEY>`, and obvious test fixtures are not
   findings. A high-entropy value, a recognizable key prefix (`AKIA`,
   `ghp_`, `sk-`, `xoxb-`, `-----BEGIN ... PRIVATE KEY-----`), or a
   credential paired with a real hostname is.

6. **Redact in your report.** Never reproduce a full secret value. Show at
   most a short prefix (~8 characters) plus the location — enough to
   identify it, not enough to use it.

For each finding give the location (`file:line`, or page title/URL for
docs), the credential type, whether it looks live or placeholder, and the
remediation — which for any real secret always begins with **rotate the
credential**, not merely delete the line.

Severity: **High** = live-looking credential for a real system, or any
private key. **Medium** = credential of unclear validity, internal-only,
or present only in history. **Low** = placeholder-adjacent, expired, or
low-value.
