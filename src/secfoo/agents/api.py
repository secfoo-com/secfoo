"""Agent that calls a model API directly (OpenAI, Anthropic, Gemini via LiteLLM).

Unlike the CLI adapters, the model can't open files itself, so the target's
source files are pasted into the prompt ("context stuffing", Tier A).
"""

from __future__ import annotations

import fnmatch
import os
import time
from pathlib import Path

from secfoo.agents.base import AgentAdapter, AgentResult, Status, Usage
from secfoo.skills.renderer import DEFAULT_EXCLUDE_PATHS

KEY_VARS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY")
DEFAULT_MODEL = "openai/gpt-4.1-mini"
MAX_FILE_BYTES = 200_000
MAX_TOTAL_CHARS = 2_000_000

DIR_PATTERNS = [p.rstrip("/") for p in DEFAULT_EXCLUDE_PATHS if p.endswith("/")]
FILE_PATTERNS = [p for p in DEFAULT_EXCLUDE_PATHS if not p.endswith("/")]


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
        except ImportError:
            return self._result(
                "failed", started, stderr='litellm is not installed. Run: pip install "secfoo[api]"'
            )
        try:
            code = collect_files(workdir)
            response = litellm.completion(
                model=os.environ.get("SECFOO_API_MODEL", DEFAULT_MODEL),
                messages=[{
                    "role": "user",
                    "content": f"{prompt}\n\n## Source files\nYou cannot open files. "
                    f"The complete target source is included below.\n{code}",
                }],
                timeout=timeout or self.default_timeout_seconds,
            )
            report = response.choices[0].message.content or ""
        except Exception as exc:  # noqa: BLE001 -- any failure becomes a failed run with its message
            return self._result("failed", started, stderr=str(exc))
        return self._result("success", started, stdout=report, report=report, usage=_usage(litellm, response))

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
