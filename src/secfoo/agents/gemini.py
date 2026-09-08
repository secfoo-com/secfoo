"""Gemini CLI adapter.

Flags verified against a real `gemini --help` (Aug 2026): `-p`/`--prompt`
for headless mode, `-o`/`--output-format json` for structured output.

Note: on individual/free-tier accounts, Google has been migrating users to
Antigravity CLI -- a real invocation on such an account fails fast with
`IneligibleTierError` rather than hanging, which surfaces correctly here as
`status="failed"` with the error in `stderr`. If this adapter consistently
fails with that error, prefer the `antigravity` agent instead.
"""

from __future__ import annotations

import json
from pathlib import Path

from secfoo.agents.base import AgentAdapter


class GeminiAdapter(AgentAdapter):
    name = "gemini"
    binary = "gemini"
    default_timeout_seconds = 1800

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        # Deliberately no --yolo: a read-only review never needs
        # auto-approved write access, and we'd rather a blocked tool call
        # show up as a lower-quality report than silently grant it edit
        # rights.
        return [self.binary, "-p", prompt, "--output-format", "json"]

    def extract_report(self, stdout: str) -> str:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return stdout
        return payload.get("response", payload.get("result", stdout))
