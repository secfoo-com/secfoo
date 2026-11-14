# Sample output: OWASP NodeGoat

A real, unedited run of secfoo against
[OWASP/NodeGoat](https://github.com/OWASP/NodeGoat), the intentionally
vulnerable Node.js/Express/MongoDB training app, so you can see what a
review produces before installing anything.

```bash
secfoo run --skill sast --skill secret-scanning --agent claude --depth quick \
    --target https://github.com/OWASP/NodeGoat --project-name NodeGoat --fail-on high
```

| | |
|---|---|
| Date | 2026-11-14 |
| secfoo | 0.3.x (this repository) |
| Agent | Claude Code (`--agent claude`), `--depth quick` |
| Wall clock | 4 min 12 s (both skills run concurrently) |
| Agent-reported spend | $3.73 |
| Exit code | `2`, because `--fail-on high` tripped on 9 High findings |

| Skill | Critical | High | Medium | Low | Time | Cost |
|---|---|---|---|---|---|---|
| SAST — Static Code Analysis | 0 | 6 | 5 | 1 | 251.9 s | $2.34 |
| Secret Scanning — Code, Confluence & Docs | 0 | 3 | 2 | 1 | 135.3 s | $1.39 |

## Files

| File | What it is |
|---|---|
| [run.txt](run.txt) | The terminal output of the command above. |
| [sast-report.md](sast-report.md) | The full SAST report: executive summary, findings register with CWE / OWASP / CVSS vectors, detailed findings with vulnerable code and fixes, taint summary, remediation roadmap. |
| [secret-scanning-report.md](secret-scanning-report.md) | The full secret-scanning report. Secret evidence is truncated to its first 8 characters before it is stored. |
| [findings.sarif](findings.sarif) | `secfoo findings export --format sarif`: 18 results, 15 rules, ready for `github/codeql-action/upload-sarif`. |
| [findings.jsonl](findings.jsonl) | `secfoo findings export`: one JSON record per finding, same shape for every skill. |

## What it found

High findings, as written in the reports:

- **F1** Server-side JS injection via `eval()` on POST body (CWE-95) — `app/routes/contributions.js:32-34`
- **F2** SSRF with raw response body reflected as HTML (CWE-918) — `app/routes/research.js:15-26`
- **F3** NoSQL injection via `$where` string interpolation (CWE-943) — `app/data/allocations-dao.js:77-79`
- **F4** IDOR: allocations looked up by URL `userId`, not session (CWE-639) — `app/routes/allocations.js:16-23`
- **F5** Missing admin check on `/benefits` (CWE-862) — `app/routes/index.js:55-56`
- **F6** Global template autoescape disabled; stored and reflected XSS (CWE-79) — `server.js:135-137`
- **S1** RSA private key committed — `artifacts/cert/server.key`
- **S2** Session cookie signing secret — `config/env/all.js:8`
- **S3** AES-256 encryption key — `config/env/all.js:9`

NodeGoat documents its planted vulnerabilities (the OWASP Top 10 tutorial
pages ship with the app). The SAST report's register lines up with them,
including the `isAdmin` middleware that is deliberately commented out.

## Reproduce

```bash
pip install secfoo            # or: uvx secfoo ...
secfoo run --skill sast --skill secret-scanning --target https://github.com/OWASP/NodeGoat --fail-on high
secfoo findings export --format sarif -o findings.sarif
secfoo serve                  # browse the reports in the local dashboard
```

Model output varies between runs; counts and wording will differ a little.
