from __future__ import annotations

import sys
import types

from secfoo.agents.secfoo import SecFooAdapter


class _Response:
    class _Choice:
        class _Message:
            content = "# Security report"

        message = _Message()

    choices = [_Choice()]


def test_secfoo_agent_uses_langgraph_and_litellm(monkeypatch, tmp_path):
    calls = []

    class _Graph:
        def __init__(self, state_type):
            self.node = None

        def add_node(self, name, node):
            self.node = node

        def add_edge(self, *_args):
            return None

        def compile(self):
            return self

        def invoke(self, state):
            return self.node(state)

    langgraph_graph = types.ModuleType("langgraph.graph")
    langgraph_graph.END = "__end__"
    langgraph_graph.START = "__start__"
    langgraph_graph.StateGraph = _Graph
    langgraph = types.ModuleType("langgraph")
    langgraph.graph = langgraph_graph

    litellm = types.ModuleType("litellm")

    def completion(**kwargs):
        calls.append(kwargs)
        return _Response()

    litellm.completion = completion
    litellm.completion_cost = lambda completion_response: 0.0123
    monkeypatch.setitem(sys.modules, "langgraph", langgraph)
    monkeypatch.setitem(sys.modules, "langgraph.graph", langgraph_graph)
    monkeypatch.setitem(sys.modules, "litellm", litellm)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("SECFOO_MODEL", "openai/test-model")

    result = SecFooAdapter().run("review this target", workdir=tmp_path)

    assert result.status == "success"
    assert result.raw_report == "# Security report"
    assert result.cost_usd == 0.0123
    assert calls == [{
        "model": "openai/test-model",
        "messages": [{"role": "user", "content": "review this target"}],
        "timeout": 1800,
    }]


def test_secfoo_agent_requires_provider_key(monkeypatch):
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert not SecFooAdapter().is_available()
