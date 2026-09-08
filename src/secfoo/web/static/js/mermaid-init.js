// Initializes and runs Mermaid against every `pre.mermaid` block on the
// page. Split out from the templates that need it (run_detail.html,
// activities/detail.html) into this external file for the same CSP
// reason as interactive.js -- an inline <script> block is silently
// blocked on the portal (Content-Security-Policy: default-src 'self',
// no 'unsafe-inline'), so the mermaid.min.js bundle would load fine but
// never actually get invoked there.
//
// startOnLoad:false + an explicit run() rather than relying on mermaid's
// own DOMContentLoaded hook, which never fires when this script (loaded
// after mermaid.min.js) finishes after that event has already passed.
mermaid.initialize({
  startOnLoad: false,
  // Report content is agent-generated from a possibly untrusted target
  // repo. "strict" sanitizes labels and disables HTML in them -- the same
  // threat model that required disabling raw HTML passthrough in
  // report/markdown.py.
  securityLevel: "strict",
  theme: "neutral",
  flowchart: { htmlLabels: false, useMaxWidth: true },
});
mermaid.run({ querySelector: "pre.mermaid" });
