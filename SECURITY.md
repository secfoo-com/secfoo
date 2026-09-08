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
installed and trust (Claude Code, Cursor, Antigravity, or Gemini CLI) and
points it at a target — a local directory or a shallow clone of a public
GitHub repo — with an instruction prompt telling it to *read and report
only*. secfoo does not itself execute code from the target; the agent CLI
does whatever it would normally do when you point it at that same target
directly. Treat scanning an untrusted or adversarial repository the same
way you'd treat opening it in your agent CLI in the first place.

`secfoo serve` binds to `127.0.0.1` by default and has no authentication —
it is meant for local use. Do not expose it on a network interface without
putting your own authenticating reverse proxy in front of it.

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
