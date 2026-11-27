
from pathlib import Path

from secfoo.agents.base import AgentAdapter, AgentResult


class FakeAdapter(AgentAdapter):
    name = "fake"
    binary = "fake"

    def is_available(self) -> bool:
        # This adapter doesn't need an external executable.
        return True

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        # FakeAdapter doesn't launch a subprocess.
        raise NotImplementedError("FakeAdapter does not execute a command")

    def run(
        self,
        prompt: str,
        *,
        workdir: Path,
        timeout: int | None = None,
        prev_commit: str | None = None,
    ) -> AgentResult:
        report_path = (
            Path(__file__).resolve().parents[3]
            / "tests"
            / "fixtures"
            / "ci"
            / "fake-report.md"
        )

        raw_report = report_path.read_text(encoding="utf-8")

        return AgentResult(
            agent=self.name,
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
            timed_out=False,
            status="success",
            raw_report=raw_report,
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
        )