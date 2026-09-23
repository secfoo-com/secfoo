"""The built-in LangGraph agent, with LiteLLM as its only model gateway."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import TypedDict

from secfoo.agents.base import AgentAdapter, AgentResult


class _State(TypedDict):
    prompt: str
    report: str
    cost_usd: float | None


def _cost(response: object) -> float | None:
    try:
        from litellm import completion_cost

        value = completion_cost(completion_response=response)
        return float(value) if value is not None else None
    except Exception:
        return None


class SecFooAdapter(AgentAdapter):
    name = "secfoo"
    binary = "secfoo-agent"
    default_timeout_seconds = 1800

    def is_available(self) -> bool:
        return bool(
            os.getenv("OPENAI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
            or os.getenv("GEMINI_API_KEY")
        )

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        raise NotImplementedError("the built-in agent runs in-process")

    def run(self, prompt: str, *, workdir: Path, timeout: int | None = None) -> AgentResult:
        started = time.monotonic()
        try:
            from langgraph.graph import END, START, StateGraph
            from litellm import completion

            model = os.getenv("SECFOO_MODEL", "openai/gpt-4o-mini")
            effective_timeout = timeout or self.default_timeout_seconds

            def call_model(state: _State) -> _State:
                response = completion(
                    model=model,
                    messages=[{"role": "user", "content": state["prompt"]}],
                    timeout=effective_timeout,
                )
                content = response.choices[0].message.content or ""
                return {"prompt": state["prompt"], "report": content, "cost_usd": _cost(response)}

            graph = StateGraph(_State)
            graph.add_node("security_assessment", call_model)
            graph.add_edge(START, "security_assessment")
            graph.add_edge("security_assessment", END)
            result = graph.compile().invoke({"prompt": prompt, "report": "", "cost_usd": None})
            report = result["report"]
            return AgentResult(
                agent=self.name,
                exit_code=0,
                stdout=report,
                stderr="",
                duration_seconds=time.monotonic() - started,
                timed_out=False,
                status="success",
                raw_report=report,
                cost_usd=result["cost_usd"],
            )
        except Exception as exc:
            return AgentResult(
                agent=self.name,
                exit_code=1,
                stdout="",
                stderr=str(exc),
                duration_seconds=time.monotonic() - started,
                timed_out=False,
                status="failed",
                raw_report="",
            )