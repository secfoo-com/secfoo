"""OpenCode CLI adapter, tested against opencode 1.18.34.

The non-interactive `run` command reads the prompt from stdin and rejects
permission requests without --auto. Read-only permissions are configured via
OPENCODE_CONFIG_CONTENT and OPENCODE_PERMISSION; --pure disables external plugins.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

from secfoo.agents.base import AgentAdapter, Usage


def _events(stdout: str):
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and isinstance(event.get("part"), dict):
            yield event


class OpenCodeAdapter(AgentAdapter):
    name = "opencode"
    binary = "opencode"
    prompt_via_stdin = True
    model_flag = "-m"
    extra_env: ClassVar[dict[str, str]] = {
        "OPENCODE_CONFIG_CONTENT": json.dumps(
            {"permission": {"bash": "deny", "edit": "deny", "webfetch": "deny"}}
        ),
        "OPENCODE_PERMISSION": json.dumps({"bash": "deny", "edit": "deny", "webfetch": "deny"}),
    }

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        return [
            self.binary, "run", "--pure", "--format", "json",
            "--dir", str(workdir), *self.model_arguments(),
        ]

    def extract_report(self, stdout: str) -> str:
        parts = [
            event["part"]["text"]
            for event in _events(stdout)
            if event.get("type") == "text" and isinstance(event["part"].get("text"), str)
        ]
        return "\n".join(parts) if parts else stdout

    def extract_usage(self, stdout: str) -> Usage:
        steps = [event["part"] for event in _events(stdout) if event.get("type") == "step_finish"]
        if not steps:
            return Usage()

        def total(values):
            numbers = [value for value in values if isinstance(value, (int, float)) and not isinstance(value, bool)]
            return sum(numbers) if numbers else None

        tokens = [part.get("tokens") if isinstance(part.get("tokens"), dict) else {} for part in steps]
        return Usage(
            input_tokens=total(token.get("input") for token in tokens),
            output_tokens=total(token.get("output") for token in tokens),
            cost_usd=total(part.get("cost") for part in steps),
        )
