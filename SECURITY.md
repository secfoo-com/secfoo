# Security Policy

secfoo takes security seriously. We appreciate responsible disclosure and
will work with you to address valid issues.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected security
vulnerability. Instead, email **security@rakfort.com** with a description
and, if possible, steps to reproduce. We aim to acknowledge reports within
2 business days.

## Security model

secfoo is a developer tool that runs in your environment with your user
permissions. `secfoo run` shells out to a coding-agent CLI you already have
installed and trust (Claude Code, Cursor, Antigravity, Gemini CLI, or Codex CLI) and
points it at a target — a local directory or a shallow clone of a public
GitHub repo — with an instruction prompt telling it to *read and report
only*. secfoo does not itself execute code from the target; the agent CLI
does whatever it would normally do when you point it at that same target
directly. Treat scanning an untrusted or adversarial repository the same
way you'd treat opening it in your agent CLI in the first place.

`secfoo serve` binds to `127.0.0.1` by default and has no authentication —
it is meant for local use. Do not expose it on a network interface without
putting your own authenticating reverse proxy in front of it (`secfoo serve`
prints a warning when `--host` is not loopback).

Because the dashboard runs on your machine while you browse other sites, it
defends against your own browser being used against it:

- **Cross-site writes are refused.** Every state-changing request (start an
  agent run, delete a case file, review a finding) must come from the
  dashboard's own origin; a request whose `Origin`, `Sec-Fetch-Site` or
  `Referer` names another site gets `403`. Clients that send none of these
  (curl, scripts) are unaffected. The runtime ingest API is authenticated by
  its API key instead.
- **DNS rebinding is refused.** Requests must name the dashboard by
  `localhost`, `127.0.0.1`, `[::1]` or its `--host`; any other `Host` gets
  `400`. Reaching it through a port-forwarding or proxy name? Add that name
  with `secfoo serve --allow-host NAME`. A wildcard `--host 0.0.0.0` accepts
  any name.
- **Security headers** on every response: a Content-Security-Policy with
  `script-src 'self'` and `frame-ancestors 'none'`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`.

`secfoo cloud login` stores an API key in `~/.secfoo/cloud.toml`
(mode `0600`). This key is scoped to push completed run data to your
organization's enterprise portal; treat it like any other credential — if
it leaks, revoke it from the portal's admin console.

Report content (findings, diagrams) is agent-generated from a target
that may itself be untrusted or adversarial, so it's rendered
defensively: report markdown never executes embedded HTML/scripts, and
Mermaid diagrams render with `securityLevel: "strict"`.

## Supported versions

Only the latest published release on PyPI is supported. Please upgrade
before reporting an issue.
