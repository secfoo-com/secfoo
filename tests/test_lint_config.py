"""ruff config: typer.Option / FastAPI Form defaults are not B008 findings."""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _ruff() -> list[str]:
    exe = shutil.which("ruff")
    if exe:
        return [exe]
    if importlib.util.find_spec("ruff") is None:
        pytest.skip("ruff is not installed (pip install -e '.[dev]')")
    return [sys.executable, "-m", "ruff"]


def test_typer_and_fastapi_defaults_are_not_flagged_by_b008():
    result = subprocess.run(
        [*_ruff(), "check", "src", "--select", "B008", "--output-format", "concise"],
        check=False,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
