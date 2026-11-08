"""Factory Droid CLI adapter.

Flags verified against a real `droid exec --help` (Factory CLI 0.227.0,
Sep 2026) and confirmed by probing until each one reached droid's own auth
check (no FACTORY_API_KEY/login available while writing this) rather than a
flag-parsing error:

- `--` before the prompt is genuinely supported (verified:
  `droid exec -- "--looks-like-a-flag"` reaches the "Authentication failed"
  auth check, not an "unknown option" parse error) -- unlike
  agents/cursor.py and agents/gemini.py, which pass the prompt to
  `-p`/positional with no such separator.
- `--cwd` is accepted (belt and suspenders -- base.py's subprocess.Popen
  already sets cwd=workdir; passing both keeps droid's own notion of the
  project root in sync with the OS-level cwd).
- `--output-format json` wraps the answer in an envelope with `result`
  (the final message) and `usage` (input_tokens/output_tokens plus a
  `factory_credits` figure -- not a dollar amount, so `cost_usd` is left
  unknown here rather than guessing a conversion rate).

`droid exec` defaults to read-only mode (no file/system modification) with
no extra flag needed -- exactly what a review-only skill wants, so no
`--auto` flag is passed; `--auto`/`--skip-permissions-unsafe` would only
be relevant for a future skill that's allowed to write, which none of
secfoo's current skills are.

Auth: droid needs either an interactive `/login` session or a
FACTORY_API_KEY environment variable. secfoo always invokes non-
interactively, so only FACTORY_API_KEY works here; if it's unset, every
run fails with droid's own "Authentication failed" message rather than
secfoo's cleaner `binary_not_found` status -- same tradeoff codex.py makes
(is_available() only checks the binary is on PATH, not that it's actually
authenticated).

NOT yet verified end-to-end: no FACTORY_API_KEY was available while
writing this, so build_command()'s flags are confirmed by direct probing
against the real CLI (see above) but a full `secfoo run --agent droid`
against a live account has not been exercised. Re-run the adapter tests
plus one real assessment once a key is available, before relying on this
in CI.
"""

from __future__ import annotations

import json
from pathlib import Path

from secfoo.agents.base import AgentAdapter, Usage


class DroidAdapter(AgentAdapter):
    name = "droid"
    binary = "droid"
    default_timeout_seconds = 1800
    model_flag = "-m"

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        return [
            self.binary,
            "exec",
            *self.model_arguments(),
            "--output-format",
            "json",
            "--cwd",
            str(workdir),
            # `--` so a prompt that happens to start with "-" is never
            # parsed as a flag (verified directly against the real CLI --
            # see module docstring).
            "--",
            prompt,
        ]

    def extract_report(self, stdout: str) -> str:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return stdout
        return payload.get("result", stdout)

    def extract_usage(self, stdout: str) -> Usage:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return Usage()
        if not isinstance(payload, dict):
            return Usage()
        usage = payload.get("usage") or {}
        input_tokens = sum(
            usage.get(key) or 0
            for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
        )
        return Usage(
            input_tokens=input_tokens if usage else None,
            output_tokens=usage.get("output_tokens"),
            # factory_credits (also in the usage block) is not a dollar
            # figure and we have no confirmed conversion rate -- leave
            # cost_usd unknown rather than report a made-up number.
            cost_usd=None,
        )
