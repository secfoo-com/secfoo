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
putting your own authenticating reverse proxy in front of it.

`secfoo cloud login` stores an API key in `~/.secfoo/cloud.toml`
(mode `0600`). This key is scoped to push completed run data to your
organization's enterprise portal; treat it like any other credential — if
it leaks, revoke it from the portal's admin console.

Report content (findings, diagrams) is agent-generated from a target
that may itself be untrusted or adversarial, so it's rendered
defensively: report markdown never executes embedded HTML/scripts, and
Mermaid diagrams render with `securityLevel: "strict"`.

## Local dashboard threat model

The `secfoo serve` dashboard is designed to run locally on developer workstations and CI runners. Because it operates within reach of web browsers running untrusted public web pages, it implements defense-in-depth protections against web-based attacks targeting localhost services:

### Cross-Site Request Forgery (CSRF) Defense
All state-changing HTTP endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) require cross-site request validation via `CrossSiteProtectionMiddleware`:
- Browser requests carrying `Sec-Fetch-Site: cross-site` are immediately rejected with `403 Forbidden`.
- Requests carrying an `Origin` or `Referer` header must match the expected dashboard origin (`localhost`, `127.0.0.1`, `[::1]`, or the configured host and port). Cross-origin origins/referers are blocked with `403 Forbidden`.
- Non-browser clients (such as automated scripts or curl) that omit `Origin`, `Referer`, and `Sec-Fetch-Site` are allowed without weakening browser cross-origin protection.

### DNS Rebinding Protection
To prevent malicious external websites from rebinding hostnames to loopback IP addresses (`127.0.0.1` / `::1`), the dashboard enforces Starlette's `TrustedHostMiddleware`. Only explicit local loopback hostnames (`localhost`, `127.0.0.1`, `[::1]`, `testserver`, and the explicitly configured `--host`) are accepted. Requests with unrecognized `Host` headers are rejected with `400 Bad Request`.

### Security Headers and Content Security Policy (CSP)
Every HTTP response includes standard hardening headers via `SecurityHeadersMiddleware`:
- `Content-Security-Policy`: Restricts scripts and styles to `'self'`, `'unsafe-inline'` (for UI components), and trusted CDN distributions (e.g., Tailwind, FontAwesome, Mermaid, KaTeX), while blocking unauthorized framing and object execution (`frame-ancestors 'none'; object-src 'none'`).
- `X-Frame-Options: DENY`: Prevents embedding in iframes or clickjacking attacks.
- `X-Content-Type-Options: nosniff`: Prevents browsers from MIME-sniffing responses away from the declared content type.
- `Referrer-Policy: strict-origin-when-cross-origin`: Minimizes referrer leakage on outbound links.

### XSS Prevention and Markdown Sanitization
Security assessment reports, findings, and diagrams often contain untrusted or adversarial text parsed from scanned targets:
- Assessment notes, finding titles, recommendations, and descriptions are rendered defensively. Any rendered Markdown strips dangerous HTML tags and script injections.
- Mermaid diagrams are initialized with `securityLevel: 'strict'`.
- Regression test coverage verifies that malicious inputs containing script tags, `javascript:` URIs, or iframe injections are neutralized.

### File Upload Limits and Extension Whitelist
The assessment attachment upload endpoint protects against disk exhaustion and malicious file types:
- Uploads are validated against an allowlist of permitted documentation extensions (`.pdf`, `.docx`, `.pptx`, `.md`, `.html`, `.htm`, `.txt`, `.json`, `.yaml`, `.yml`, `.csv`). Executables and arbitrary extensions are rejected with `400 Bad Request`.
- Upload size is enforced chunk-by-chunk during streaming against `MAX_UPLOAD_BYTES` (50 MB). Exceeding this limit immediately terminates the upload with `413 Payload Too Large` and cleans up any partially written files on disk.

### Safe Attachment Downloads
User-uploaded assessment attachments are served via a dedicated download endpoint (`GET /assessments/{assessment_id}/attachments/{attachment_id}/download`):
- Served with `Content-Type: application/octet-stream` and `Content-Disposition: attachment; filename="<sanitized_filename>"`.
- Accompanied by `X-Content-Type-Options: nosniff` to prevent browsers from executing active content (such as HTML or SVG) in the dashboard's origin.

### Runtime Key Comparison and Insecure Runtime Opt-in
- Runtime API keys used for authentication are compared using constant-time string comparison (`hmac.compare_digest`) via SQLite candidate lookups, preventing timing side-channel attacks.
- When `secfoo serve` binds to an external, non-loopback network interface, runtime key authentication requires HTTPS by default. The `--allow-insecure-runtime` CLI flag provides an explicit opt-in for deployments running behind TLS-terminating reverse proxies, without weakening CSRF or host header protections.

## Supported versions

Only the latest published release on PyPI is supported. Please upgrade
before reporting an issue.
