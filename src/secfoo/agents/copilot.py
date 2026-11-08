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

`--output-format json` (JSONL events) replaces the earlier `-s` plain-text
mode. SECFOO-10 E2E (Sep 2026, CLI 1.0.89) showed the quirk below is
worse than cosmetic: the built-in scanner runs as a *subagent*
("security-review") and in text mode its output streams to stdout
concurrently with the main answer, interleaving mid-line (e.g.
"**Severity:# Secret LOW Scanning Report") and corrupting the report.
`--stream off` stops the interleaving but renders Markdown to plain text,
dropping the headings the report parsers need. In JSONL every subagent
event carries an `agentId`, so `extract_report()` takes the last
non-empty `assistant.message` without one -- the main agent's final
answer, clean and in raw Markdown. The history below is kept for context;
the `strip_preamble()` fallback it describes is still correct but no
longer needed for Copilot.

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

import json
from pathlib import Path

from secfoo.agents.base import AgentAdapter


class CopilotAdapter(AgentAdapter):
    name = "copilot"
    binary = "copilot"
    default_timeout_seconds = 1800
    model_flag = "--model"
    # Piped stdin instead of `-p <prompt>`: on Windows `copilot` is a `.bat`
    # shim, and cmd.exe cut a `-p` prompt off at its first newline
    # (reproduced Sep 2026, CLI 1.0.89). With stdin piped and no `-p`, the
    # CLI still runs one non-interactive turn and exits.
    prompt_via_stdin = True

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        return [self.binary, *self.model_arguments(), "--output-format", "json", "--allow-all-tools"]

    def extract_report(self, stdout: str) -> str:
        report = None
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or event.get("type") != "assistant.message" or "agentId" in event:
                continue
            content = (event.get("data") or {}).get("content")
            if content:
                report = content
        # Not JSONL at all (e.g. an older CLI ignoring the flag): stdout is
        # the answer itself, as in the old `-s` mode.
        return report if report is not None else stdout
