"""Shared runner for the harnesses in this folder.

Each harness defines `check(data: bytes) -> None`: it feeds the bytes to one
parser and asserts that parser's contract (a result or its own clean error,
never any other exception). The same `check` runs three ways:

    python fuzz/fuzz_config.py WORK_DIR fuzz/corpus/config -max_total_time=60
        coverage-guided fuzzing with Atheris (Linux/macOS, `pip install atheris`)

    python fuzz/fuzz_config.py crash-<sha1> [more files or folders]
        without Atheris installed: replay inputs through `check` -- reproduce a
        CI crash on any platform, Windows included

    pytest tests/test_property_fuzz_targets.py
        Hypothesis drives `check`, and every corpus file is replayed, so the
        invariants and the reproducers of fixed crashes run on every platform
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

CORPUS_ROOT = Path(__file__).resolve().parent / "corpus"


def _replay(check: Callable[[bytes], None], targets: list[str]) -> int:
    paths: list[Path] = []
    for target in targets:
        path = Path(target)
        paths.extend(sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path])
    for path in paths:
        check(path.read_bytes())  # any exception propagates, with its traceback, like a fuzzer crash
    print(f"replayed {len(paths)} input(s) without a crash")
    return 0


def main(check: Callable[[bytes], None]) -> None:
    try:
        import atheris
    except ImportError:
        targets = [arg for arg in sys.argv[1:] if not arg.startswith("-")]
        if not targets:
            sys.exit("atheris is not installed: pass input files or folders to replay them, "
                     "or `pip install atheris` (Linux/macOS) to fuzz")
        sys.exit(_replay(check, targets))
    # Instrument after the harness imported its targets: everything loaded so
    # far (secfoo and the libraries it parses with) gets coverage feedback.
    atheris.instrument_all()
    atheris.Setup(sys.argv, check)
    atheris.Fuzz()
