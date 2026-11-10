from __future__ import annotations

from secfoo.agents.antigravity import AntigravityAdapter
from secfoo.agents.api import ApiAdapter
from secfoo.agents.base import AgentAdapter
from secfoo.agents.claude import ClaudeAdapter
from secfoo.agents.copilot import CopilotAdapter
from secfoo.agents.codex import CodexAdapter
from secfoo.agents.cursor import CursorAdapter
from secfoo.agents.devin import DevinAdapter
from secfoo.agents.droid import DroidAdapter
from secfoo.agents.gemini import GeminiAdapter
from secfoo.agents.opencode import OpenCodeAdapter

ADAPTERS: dict[str, type[AgentAdapter]] = {
    ClaudeAdapter.name: ClaudeAdapter,
    CursorAdapter.name: CursorAdapter,
    AntigravityAdapter.name: AntigravityAdapter,
    GeminiAdapter.name: GeminiAdapter,
    CopilotAdapter.name: CopilotAdapter,
    ApiAdapter.name: ApiAdapter,
    CodexAdapter.name: CodexAdapter,
    DroidAdapter.name: DroidAdapter,
    DevinAdapter.name: DevinAdapter,
    OpenCodeAdapter.name: OpenCodeAdapter,
}


def get_adapter(agent_id: str) -> AgentAdapter:
    try:
        return ADAPTERS[agent_id]()
    except KeyError:
        available = ", ".join(sorted(ADAPTERS))
        raise ValueError(f"unknown agent id {agent_id!r}. Available: {available}") from None
