"""Agent that calls a model API directly (OpenAI, Anthropic, Gemini via LiteLLM).

Unlike the CLI adapters, the model can't open files itself, so the target's
source files are pasted into the prompt ("context stuffing", Tier A).

The run is a small LangGraph graph:

    collect_files -> assess -> (report complete?) -> END
                        ^              | no, first attempt
                        +- request_fix <+

`request_fix` asks the model to reformat its own draft into the required
report format without resending the source, so a malformed report costs one
cheap extra call rather than a second full assessment.
"""

from __future__ import annotations

import fnmatch
import os
import time
from pathlib import Path
from typing import TypedDict

from secfoo.agents.base import AgentAdapter, AgentResult, Status, Usage
from secfoo.report.severity import extract_overall_risk_rating
from secfoo.skills.renderer import DEFAULT_EXCLUDE_PATHS

KEY_VARS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY")
DEFAULT_MODEL = "openai/gpt-4.1-mini"
MAX_FILE_BYTES = 200_000
MAX_TOTAL_CHARS = 2_000_000
MAX_ATTEMPTS = 2  # one assessment + at most one reformat
NUM_RETRIES = 3  # LiteLLM's own backoff for rate limits / transient errors

DIR_PATTERNS = [p.rstrip("/") for p in DEFAULT_EXCLUDE_PATHS if p.endswith("/")]
FILE_PATTERNS = [p for p in DEFAULT_EXCLUDE_PATHS if not p.endswith("/")]

FIX_REQUEST = (
    "## Draft report to reformat\n"
    "You already reviewed the target source and wrote the draft below, but it does not "
    "follow the required output format above (it has no `**Overall risk rating:**` line). "
    "Rewrite it into exactly that format. Keep every finding as-is: do not add, drop, or "
    "re-rate findings. Output only the report.\n\n"
)


class _State(TypedDict):
    prompt: str
    workdir: str
    model: str
    timeout: int
    messages: list[dict]
    report: str
    attempts: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    unpriced: bool


def _matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def collect_files(workdir: Path) -> str:
    """Return every readable text file under `workdir` as one labelled string."""
    chunks: list[str] = []
    total = 0
    for root, dirs, files in os.walk(workdir):
        dirs[:] = sorted(d for d in dirs if not _matches(d, DIR_PATTERNS))
        for name in sorted(files):
            path = Path(root) / name
            if _matches(name, FILE_PATTERNS) or path.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue  # binary file (image, font, ...)
            chunk = f"\n===== FILE: {path.relative_to(workdir).as_posix()} =====\n{text}\n"
            total += len(chunk)
            if total > MAX_TOTAL_CHARS:
                raise ValueError(
                    f"Target is too large for the api agent (over {MAX_TOTAL_CHARS:,} characters). "
                    "Use --exclude to narrow it, or use a CLI agent."
                )
            chunks.append(chunk)
    return "".join(chunks)


def build_graph(litellm, StateGraph, START, END):
    """The assessment workflow. Takes the libraries as arguments so tests can
    run the real graph against a fake LiteLLM."""

    def collect(state: _State) -> dict:
        code = collect_files(Path(state["workdir"]))
        content = (
            f"{state['prompt']}\n\n## Source files\nYou cannot open files. "
            f"The complete target source is included below.\n{code}"
        )
        return {"messages": [{"role": "user", "content": content}]}

    def assess(state: _State) -> dict:
        response = litellm.completion(
            model=state["model"],
            messages=state["messages"],
            timeout=state["timeout"],
            num_retries=NUM_RETRIES,
        )
        usage = _usage(litellm, response)
        return {
            "report": response.choices[0].message.content or "",
            "attempts": state["attempts"] + 1,
            "input_tokens": state["input_tokens"] + (usage.input_tokens or 0),
            "output_tokens": state["output_tokens"] + (usage.output_tokens or 0),
            "cost_usd": state["cost_usd"] + (usage.cost_usd or 0.0),
            "unpriced": state["unpriced"] or usage.cost_usd is None,
        }

    def request_fix(state: _State) -> dict:
        # Fresh, short conversation: the instructions (which carry the output
        # contract) plus the draft -- not the source files again.
        content = f"{state['prompt']}\n\n{FIX_REQUEST}{state['report']}"
        return {"messages": [{"role": "user", "content": content}]}

    def next_step(state: _State) -> str:
        if extract_overall_risk_rating(state["report"]) is not None or state["attempts"] >= MAX_ATTEMPTS:
            return END
        return "request_fix"

    graph = StateGraph(_State)
    graph.add_node("collect_files", collect)
    graph.add_node("assess", assess)
    graph.add_node("request_fix", request_fix)
    graph.add_edge(START, "collect_files")
    graph.add_edge("collect_files", "assess")
    graph.add_conditional_edges("assess", next_step, ["request_fix", END])
    graph.add_edge("request_fix", "assess")
    return graph.compile()


class ApiAdapter(AgentAdapter):
    name = "api"
    binary = "API key"  # label only: shown in `secfoo agents`

    def is_available(self) -> bool:
        return any(os.environ.get(k) for k in KEY_VARS)

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        return []  # required by the base class; there is no program to launch

    def run(self, prompt: str, *, workdir: Path, timeout: int | None = None) -> AgentResult:
        started = time.monotonic()
        _strip_key_whitespace()
        if not self.is_available():
            return self._result("binary_not_found", started, stderr=f"No API key set. Set one of: {', '.join(KEY_VARS)}")
        try:
            import litellm
            from langgraph.graph import END, START, StateGraph
        except ImportError:
            return self._result(
                "failed", started, stderr='litellm/langgraph are not installed. Run: pip install "secfoo[api]"'
            )
        try:
            final = build_graph(litellm, StateGraph, START, END).invoke({
                "prompt": prompt,
                "workdir": str(workdir),
                "model": os.environ.get("SECFOO_API_MODEL", DEFAULT_MODEL),
                "timeout": timeout or self.default_timeout_seconds,
                "messages": [],
                "report": "",
                "attempts": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": 0.0,
                "unpriced": False,
            })
        except Exception as exc:  # noqa: BLE001 -- any failure becomes a failed run with its message
            return self._result("failed", started, stderr=str(exc))
        usage = Usage(
            input_tokens=final["input_tokens"],
            output_tokens=final["output_tokens"],
            cost_usd=None if final["unpriced"] else final["cost_usd"],
        )
        report = final["report"]
        return self._result("success", started, stdout=report, report=report, usage=usage)

    def _result(
        self,
        status: Status,
        started: float,
        *,
        stdout: str = "",
        stderr: str = "",
        report: str = "",
        usage: Usage | None = None,
    ) -> AgentResult:
        usage = usage or Usage()
        return AgentResult(
            agent=self.name,
            exit_code=0 if status == "success" else None,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            timed_out=False,
            status=status,
            raw_report=report,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cost_usd=usage.cost_usd,
        )


def _strip_key_whitespace() -> None:
    """A key pasted with a trailing newline makes httpx reject the auth
    header, which LiteLLM reports only as a vague "Connection error"."""
    for key in KEY_VARS:
        value = os.environ.get(key)
        if value and value != value.strip():
            os.environ[key] = value.strip()


def _usage(litellm, response) -> Usage:
    """Token counts from the response; cost from LiteLLM's price table
    (None for a model LiteLLM has no price for)."""
    tokens = getattr(response, "usage", None)
    try:
        cost = litellm.completion_cost(completion_response=response)
    except Exception:  # noqa: BLE001 -- unknown model pricing shouldn't fail a successful run
        cost = None
    return Usage(
        input_tokens=getattr(tokens, "prompt_tokens", None),
        output_tokens=getattr(tokens, "completion_tokens", None),
        cost_usd=float(cost) if cost is not None else None,
    )
