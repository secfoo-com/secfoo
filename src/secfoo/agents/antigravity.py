"""Google Antigravity CLI adapter.

Verified against a real `agy --help` (Aug 2026): `-p`/`--print` runs a
single prompt non-interactively and prints the response as plain text to
stdout (no `--output-format`/JSON mode exists, unlike Claude Code and
Gemini CLI -- so the base class's default `extract_report`, which returns
stdout as-is, is correct here and deliberately not overridden).

`agy --print` has its own internal timeout (`--print-timeout`, default
`5m0s`) independent of the timeout this package enforces at the subprocess
level. Without passing it explicitly, `agy` could silently truncate a long
review well before our own (longer) timeout fires, so `build_command()`
sets `--print-timeout` to match whatever effective timeout `run()` is using.

Deliberately does NOT pass `--dangerously-skip-permissions`: headless mode
soft-denies any tool call requiring approval rather than hanging, and a
read-only review should never need that flag.

OBSERVED FLAKINESS (Aug 2026, real testing): on at least one machine, `agy
--print` sometimes exits 0 with completely empty stdout, and on repeated
calls has failed outright with `Error: Agent execution terminated due to
error.` on stderr. Both are handled correctly by this adapter (empty output
renders as "no report content" in the dashboard rather than crashing;
non-zero exit is captured as status="failed" with the stderr message
preserved) -- but this suggests the CLI itself is still unstable this early
in its release. If Antigravity runs are unreliable, prefer another agent.
"""

from __future__ import annotations

from pathlib import Path

from secfoo.agents.base import AgentAdapter, AgentResult


class AntigravityAdapter(AgentAdapter):
    name = "agy"
    binary = "agy"
    default_timeout_seconds = 1800

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        effective_timeout = getattr(self, "_effective_timeout", self.default_timeout_seconds)
        return [self.binary, "--print", prompt, "--print-timeout", f"{effective_timeout}s"]

    def run(self, prompt: str, *, workdir: Path, timeout: int | None = None) -> AgentResult:
        self._effective_timeout = timeout or self.default_timeout_seconds
        return super().run(prompt, workdir=workdir, timeout=timeout)
