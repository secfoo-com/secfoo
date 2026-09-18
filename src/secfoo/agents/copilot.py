"""GitHub Copilot CLI adapter.

Binary is `copilot` (npm package `@github/copilot`, GA since Feb 2026) --
not the older `gh copilot` GitHub CLI extension, which is now just a thin
wrapper that shells out to this same binary. Flags verified against a real
`copilot --help` (Sep 2026, CLI version 1.0.86); the CLI ships updates
often and flags have already drifted once (the pre-GA `gh copilot`
extension used different flags entirely), so re-verify before trusting an
older doc.

`--allow-all-tools` is not a convenience flag here -- `copilot --help`
states it directly: "required for non-interactive mode." Without it, `-p`
just hangs waiting for a permission prompt that can never be answered
non-interactively.

Deliberately does NOT pass `--allow-all-paths` or `--allow-all-urls` (both
folded into the broader `--allow-all`/`--yolo` flags) -- a read-only
security review only needs to read files already inside the target
workdir and never needs unrestricted filesystem or network access.
`--allow-all-tools` alone still lets the model use tools like `write`
without a prompt, but secfoo's prompts are read-only reviews by
instruction, not by sandboxing, matching the same trust level the other
adapters accept (none of claude.py/cursor.py/gemini.py/antigravity.py
sandbox writes at the OS level either).

`-s`/`--silent` drops the token-usage stats banner so stdout is just the
agent's answer -- confirmed directly (no JSON envelope to unwrap, unlike
claude.py/gemini.py), so `extract_report()` is not overridden here.

CONFIRMED QUIRK (reproduced twice, Sep 2026 -- once on a casual prompt,
once on a real `secfoo run --skill sast --agent copilot` end-to-end run):
this CLI unpromptedly auto-invokes its own built-in security-scanning
tool first, emitting a "## Security Findings" / "### Alert N" block (plus
its own Remediation Roadmap) *before* going on to separately produce the
skill's actual requested Markdown contract. The result is a report.md
roughly double the length it should be, with the required content
duplicated in two different shapes back-to-back.

This is cosmetic, not a data-integrity bug -- confirmed directly against
report/sast.py's real parser: `extract_findings_register_rows()` finds
the genuine "## 3. Findings Register" section by name regardless of what
precedes it, and `count_severities()`'s `### [SEVERITY]` pattern only
matches the compliant second half (Copilot's own native Alert format
uses plain "Severity: CRITICAL" text, no brackets), so the SAST Findings
Register and dashboard severity counts both come out correct. The actual
casualty was `report/markdown.py`'s `strip_preamble()`: it assumed every
agent emits a single top-level `# <Skill> Report` heading to anchor on,
but Copilot's output never uses a single `#` anywhere (every heading is
`##`/`###`), so the preamble-stripping regex found nothing to anchor on
and left the whole duplicated block in place. Fixed there (not here) by
adding a fallback anchor on "## 1. Executive Summary" -- every skill's
contract requires that as its first numbered section regardless of
which agent is running it, so it's a safe, skill-agnostic backstop for
any agent that skips the title outright. Verified against this exact
captured report: 713 lines / 29396 chars down to 281 / 14442, landing
exactly on the real content with no pollution left. No attempt was made
to suppress Copilot's native tool from firing in the first place (e.g.
via `--deny-tool`) -- the tool/skill name isn't known and guessing at it
without being able to verify the guess isn't worth the risk; cutting the
resulting preamble downstream is the safer fix.
"""

from __future__ import annotations

from pathlib import Path

from secfoo.agents.base import AgentAdapter


class CopilotAdapter(AgentAdapter):
    name = "copilot"
    binary = "copilot"
    default_timeout_seconds = 1800

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        return [self.binary, "-p", prompt, "-s", "--allow-all-tools"]
