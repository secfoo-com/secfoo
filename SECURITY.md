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

### Local dashboard threat model

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
- **Report content cannot run script.** Reports are agent output over a
  target that may be hostile, and the run page shows them as HTML. Raw HTML
  in a report renders as text; links keep only `http(s)` URLs with a host
  (no `javascript:`, `data:`, `file:` or protocol-relative links, no
  credentials in the URL); images are removed, since loading one would be an
  exfiltration channel; Mermaid source stays escaped text and Mermaid runs
  with `securityLevel: "strict"`, which a `%%{init}%%` directive cannot
  change. `tests/test_web/test_xss_corpus.py` puts 56 payloads (event
  handlers, SVG, `javascript:` links in eleven spellings, link-title quote
  breakouts, entities in headings, data URIs, Mermaid blocks with script)
  through the renderer and through the run, SAST and secret-scanning pages
  that show report data, and fails if a page gains anything executable.
- **Uploads are bounded.** Every attachment is capped at 25 MB: a request
  declaring more is refused (`413`) before it is spooled to disk, and one
  without a `Content-Length` gets `411`. A PDF, DOCX or PPTX whose bytes are
  not that format is refused (`415`) before any parser sees it, and a DOCX
  or PPTX that would expand past 200 MB or holds more than 5,000 archive
  members is stored but not parsed. Uploaded files are never served back by
  the dashboard. Text extraction still runs in the request process: a
  pathological PDF can cost CPU time (see `docext.py`); `fuzz/fuzz_docext.py`
  checks that each input finishes within 30 seconds.
- **The runtime ingest API** (`/api/runtime/v1/`) needs a valid API key on
  every route, reads or writes; keys are random 256-bit tokens stored only
  as SHA-256 hashes and compared in constant time. It is exempt from the
  origin check because a page on another site cannot attach an
  `Authorization` header without a CORS preflight, which the dashboard
  never grants. On a non-loopback `--host` it refuses keys over plain HTTP;
  `--allow-insecure-runtime` lifts that one check and nothing else (keys,
  the `Host` check and rate limits still apply).

`secfoo cloud login` stores an API key in `~/.secfoo/cloud.toml`
(mode `0600`). This key is scoped to push completed run data to your
organization's enterprise portal; treat it like any other credential — if
it leaks, revoke it from the portal's admin console.

Report content (findings, diagrams) is agent-generated from a target
that may itself be untrusted or adversarial, so it's rendered
defensively: report markdown never executes embedded HTML/scripts, and
Mermaid diagrams render with `securityLevel: "strict"`.

The store (`~/.secfoo`, or `SECFOO_HOME`) holds prompts with the scanned
source, reports and findings, so secfoo keeps its root directory `0700`
(tightening one created by an older version) and writes files that hold a
credential (`cloud.toml`, `memory.toml`, `claude-mcp-config.json`) as `0600`
from the moment they are created.

## Supported versions

Only the latest published release on PyPI is supported. Please upgrade
before reporting an issue.
