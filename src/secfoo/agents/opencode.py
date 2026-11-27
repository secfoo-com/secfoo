"""OpenCode CLI adapter, verified against @opencode/cli 2.3.0 (Windows x64, 2026-11-27).

OpenCode v2 removed the v1 ``--pure`` and ``--dir`` flags (passing either makes
``run`` print help and exit 1), and moved permissions from the v1 ``permission``
object to an ordered ``permissions`` array. The CLI only loads an explicit
config when ``--standalone`` is used; with the shared background server the
v1 env overrides are ignored and writes are allowed. The read-only policy is
therefore shipped in ``opencode-readonly.json`` and passed via OPENCODE_CONFIG.
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


def _errors(stdout: str):
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "error" and isinstance(event.get("error"), dict):
            yield event["error"]


class OpenCodeAdapter(AgentAdapter):
    name = "opencode"
    binary = "opencode"
    prompt_via_stdin = True
    model_flag = "-m"
    extra_env: ClassVar[dict[str, str]] = {
        "OPENCODE_CONFIG": str(Path(__file__).with_name("opencode-readonly.json")),
    }

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        # --standalone is required for OPENCODE_CONFIG to be applied; cwd is
        # set by AgentAdapter.run(), so no --dir is needed (v2 has no --dir).
        return [
            self.binary, "run", "--standalone", "--format", "json",
            *self.model_arguments(),
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

    def describe_failure(self, stdout: str, stderr: str) -> str | None:
        # v2 reports auth/no-route failures as JSON events on stdout with an
        # empty stderr; surface the CLI's own message instead of a blank error.
        for error in _errors(stdout):
            message = error.get("message")
            if isinstance(message, str) and message:
                return message
        return None
