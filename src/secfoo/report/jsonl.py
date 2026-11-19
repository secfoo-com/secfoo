"""Serialize exported structured findings as JSON Lines, without I/O.

One JSON object per line, keys sorted, so `secfoo findings export` output is
stable across runs and diffs cleanly. Kept beside sarif.py so both export
formats can be fuzzed directly (#121).
"""

from __future__ import annotations

import json


def findings_to_jsonl(records: list[dict]) -> str:
    """Every record as one line; "" for no records, else newline-terminated."""
    lines = [json.dumps(record, sort_keys=True) for record in records]
    return "\n".join(lines) + ("\n" if lines else "")
