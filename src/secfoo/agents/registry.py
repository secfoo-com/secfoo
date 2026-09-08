from __future__ import annotations

from secfoo.agents.antigravity import AntigravityAdapter
from secfoo.agents.base import AgentAdapter
from secfoo.agents.claude import ClaudeAdapter
from secfoo.agents.cursor import CursorAdapter
from secfoo.agents.gemini import GeminiAdapter

ADAPTERS: dict[str, type[AgentAdapter]] = {
    ClaudeAdapter.name: ClaudeAdapter,
    CursorAdapter.name: CursorAdapter,
    AntigravityAdapter.name: AntigravityAdapter,
    GeminiAdapter.name: GeminiAdapter,
}


def get_adapter(agent_id: str) -> AgentAdapter:
    try:
        return ADAPTERS[agent_id]()
    except KeyError:
        available = ", ".join(sorted(ADAPTERS))
        raise ValueError(f"unknown agent id {agent_id!r}. Available: {available}") from None
