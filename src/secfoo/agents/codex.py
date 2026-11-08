"""OpenAI Codex CLI adapter.

Flags verified against a real `codex exec --help` (codex-cli 0.155, Sep 2026):
`codex exec` runs a single prompt non-interactively. Progress/tool activity
goes to stderr and only the agent's final message is printed to stdout, so
the base class's default `extract_report` (stdout is the report) is correct
here and deliberately not overridden. `--json` would switch stdout to a JSONL
event stream, which we do not want for a plain-markdown report.

Deliberately NOT passed:
- `--dangerously-bypass-approvals-and-sandbox` / `--full-auto`: a read-only
  review never needs write access, so we pin `--sandbox read-only` instead.
- `--json`: see above.

Token usage: `codex exec` ends its stderr with a "tokens used" line followed
by the run's total on the next line (e.g. "tokens used\n15,201"). It is a
single total with no input/output split and no cost, so it is recorded as
`input_tokens` with `output_tokens` and `cost_usd` left unknown (None) --
`secfoo cost` then shows the total under "Input tokens", "-" for output, and
"-" for cost.

MCP servers from ~/.secfoo/config.toml are not wired up for Codex yet
(`secfoo mcp sync --agent codex` is a follow-up); Codex runs use whatever is
already in the user's own ~/.codex/config.toml.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from secfoo.agents.base import AgentAdapter, Usage

# "tokens used" on its own line, then the total (thousands separators allowed).
_TOKENS_USED_RE = re.compile(r"^\s*tokens used\s*\n\s*([\d,]+)\s*$", re.MULTILINE | re.IGNORECASE)

# Module-level so tests can flip it; patching os.name itself breaks pytest.
_IS_WINDOWS = os.name == "nt"


class CodexAdapter(AgentAdapter):
    name = "codex"
    binary = "codex"
    default_timeout_seconds = 1800
    model_flag = "--model"
    # `codex exec -` reads the prompt from stdin; passing it as argv breaks
    # on Windows, where `codex` is a `.cmd` shim and cmd.exe truncates the
    # argument at its first newline.
    prompt_via_stdin = True

    def detect_failure(self, stdout: str, stderr: str) -> str | None:
        # If Codex's sandbox still refuses its commands, `codex exec` exits 0
        # with a "could not inspect" report (SECFOO-10 E2E, codex-cli
        # 0.159.2). Never record that as success.
        if "exec_command failed" not in stderr:
            return None
        return "Codex's sandbox rejected its commands, so the target was never read."

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        windows_sandbox: list[str] = []
        if _IS_WINDOWS:
            # With no Windows sandbox configured, `--sandbox read-only`
            # rejects every command, reads included ("blocked by policy").
            # The unelevated (restricted-token) sandbox needs no admin setup
            # and was verified to allow reads and deny writes both inside
            # and outside the workdir (SECFOO-38, codex-cli 0.159.2).
            windows_sandbox = ["-c", 'windows.sandbox="unelevated"']
        return [
            self.binary,
            "exec",
            *self.model_arguments(),
            # Read-only filesystem: the assessment only reads the target.
            "--sandbox",
            "read-only",
            *windows_sandbox,
            # secfoo runs against arbitrary targets (cloned repos, user
            # paths, non-git dirs); without this Codex refuses to start
            # outside a trusted git repository.
            "--skip-git-repo-check",
            # Don't litter ~/.codex/sessions with one file per assessment.
            "--ephemeral",
            # No ANSI escapes in captured stdout/stderr.
            "--color",
            "never",
            "--cd",
            str(workdir),
            # `-`: read the prompt from stdin (see prompt_via_stdin).
            "-",
        ]

    def extract_usage_from_stderr(self, stderr: str) -> Usage:
        matches = _TOKENS_USED_RE.findall(stderr or "")
        if not matches:
            return Usage()
        # Last occurrence is the end-of-run summary.
        return Usage(input_tokens=int(matches[-1].replace(",", "")))
