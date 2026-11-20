r"""Devin CLI adapter.

Answers the open question the Q4 sprint plan flagged for this integration
("check whether Devin offers a true local CLI vs. only a cloud session
API"): as of Devin CLI 3000.11.3 (Sep 2026, official `devin-cli` Homebrew
cask -- *not* the unofficial `devin-cli`/`devin` packages that also exist
on PyPI under the same-sounding name, which are unrelated third-party
projects and were deliberately not used here), it is a real local-first
agent binary with its own non-interactive mode, so this is a normal
CLI adapter, not the API-based shape Initiative 2 uses.

Flags verified against a real `devin --help` / `devin auth status`
(no Devin account was available while writing this, so every flag below
was confirmed by checking it parses through to devin's own runtime error --
"Error: Login canceled" -- rather than a CLI parse error, the same
verification standard codex.py and droid.py use):

- `-p <prompt>`: non-interactive mode, prompt passed as the flag's own
  value (same convention as claude.py's `-p`) -- verified directly.
- `--respect-workspace-trust false`: REQUIRED. Devin's own --help states
  print/non-interactive mode "cannot show the trust prompt and fails in
  an untrusted directory" unless this is passed; secfoo always runs
  against a target Devin has never seen before, so omitting this would
  make every single run fail on a fresh machine. The flag's presence and
  value syntax were verified directly (parses through to the same
  "Login canceled" runtime error); the trust-prompt behavior itself is
  from Devin's documented help text, not independently reproduced here,
  since no run got past the auth step.
- `--permission-mode auto`: passed explicitly even though Devin's own
  --help lists "auto" as the default (auto-approves read-only tools) --
  same belt-and-suspenders reasoning as claude.py's explicit
  `--permission-mode default`. NOT independently verified in combination
  with the other two flags in this session (a three-flag combined probe
  was blocked by this session's own tooling safety policy, which read the
  combination as looking like an autonomous/"unsafe agent" configuration
  attempt) -- re-verify this exact command once a real account is
  available, before relying on it in CI.
- No `--cwd`-equivalent flag exists for Devin (checked the full --help
  output -- there is none). Devin's print mode is assumed to operate on
  the process's own working directory instead, which base.py already
  sets via `subprocess.Popen(cwd=workdir)`. Not independently confirmed
  end-to-end.
- No `--output-format`/JSON flag exists either (only `--export`, which
  writes a separate file rather than emitting to stdout) -- so, like
  codex.py, extract_report() is left at the default stdout-passthrough
  and extract_usage() is not overridden (cost/tokens stay unknown, not
  guessed).

Auth: unlike codex/api/droid (env-var or API-key based, so a CI runner can
authenticate non-interactively from zero), Devin only supports
`devin auth login` -- a one-time interactive OAuth flow, or
`--force-manual-token-flow` to paste a token by hand. Once done, the
resulting `~/.local/share/devin/credentials.toml` is presumably reused by
later non-interactive `-p` calls, the same operational model claude/gemini
already use in secfoo (a human logs in once, outside of secfoo, before any
`secfoo run` invocation). This means Devin can never be authenticated from
a bare CI runner the way `--agent api`/`--agent droid` (with an env var
key) can -- worth flagging back to whoever owns Initiative 1's sequencing
note about CI testing.

NOT yet verified end-to-end: no Devin account was available while writing
this. Every flag above parses correctly against the real CLI, and
`secfoo run --agent devin` completes the full pipeline and reports a clean
`failed` status rather than crashing (same shape confirmed for the droid
adapter) -- but no real report has been produced or inspected. Re-run
the adapter tests plus one real assessment once an account is available.

MCP servers from ~/.secfoo/config.toml reach Devin via `secfoo mcp sync
--agent devin`, which merges into ~/.config/devin/mcp_config.json
(%APPDATA%\devin\mcp_config.json on Windows).
"""

from __future__ import annotations

from pathlib import Path

from secfoo.agents.base import AgentAdapter


class DevinAdapter(AgentAdapter):
    name = "devin"
    binary = "devin"
    default_timeout_seconds = 1800

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        return [
            self.binary,
            "-p",
            prompt,
            # Required: non-interactive mode fails in a directory Devin
            # hasn't seen before unless this is explicitly disabled (see
            # module docstring).
            "--respect-workspace-trust",
            "false",
            # Explicit even though it's the documented default -- a
            # review-only skill never needs "accept-edits"/"dangerous".
            "--permission-mode",
            "auto",
        ]
