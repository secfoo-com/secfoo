"""Cursor CLI adapter.

KNOWN ISSUE (as of Aug 2026): the `agent -p` headless/print mode has a
documented bug where it can hang indefinitely and never return
(https://forum.cursor.com/t/cursor-agent-p-print-headless-mode-hangs-indefinitely-and-never-returns/150246).
Do not remove or loosen the hard timeout in AgentAdapter.run() for this
adapter — it is the only thing standing between this bug and a `secfoo
run` invocation that never completes. The shorter default timeout below is
intentional: we'd rather fail fast and let the user retry than tie up a
batch run.
"""

from __future__ import annotations

from pathlib import Path

from secfoo.agents.base import AgentAdapter


class CursorAdapter(AgentAdapter):
    name = "agent"
    binary = "agent"
    default_timeout_seconds = 900

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        return [self.binary, "-p", prompt]
