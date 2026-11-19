"""Fuzz `secfoo findings export`: finding records -> SARIF 2.1.0 and JSONL.

Input: JSON Lines, one finding record per line -- the shape
`secfoo findings export --format jsonl` writes, so the seed corpus is real
exports. Each record is reduced to what a database row can hold (string,
number or null values; `skill_id` always a string; a well-formed `runtime`
block on SCA findings), because that's all the exporter ever receives.

Contract: for any such records,
- findings_to_sarif returns a document that validates against the SARIF
  2.1.0 schema, with one result per record and every ruleIndex pointing at
  its ruleId, with or without --runtime-priority;
- findings_to_jsonl writes one line per record that parses back to it;
- neither mutates the records.

    python fuzz/fuzz_sarif_export.py WORK fuzz/corpus/sarif_export -max_total_time=60
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from _common import main
from jsonschema import Draft7Validator, FormatChecker

from secfoo.report.jsonl import findings_to_jsonl
from secfoo.report.sarif import findings_to_sarif

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sarif-schema-2.1.0.json"
VALIDATOR = Draft7Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")), format_checker=FormatChecker())


def _scalar(value: object) -> bool:
    if isinstance(value, float):
        return not math.isnan(value)  # SQLite stores NaN as NULL; it never reaches the exporter
    return value is None or isinstance(value, (str, int))


def _runtime(value: object) -> dict | None:
    """RuntimeLookup.as_sarif() output: a state and route templates."""
    if not isinstance(value, dict) or not isinstance(value.get("state"), str):
        return None
    routes = value.get("routes", [])
    if not isinstance(routes, list) or not all(isinstance(r, dict) and isinstance(r.get("route"), str) for r in routes):
        return None
    return {"state": value["state"], "routes": [{"route": r["route"]} for r in routes]}


def records_from(data: bytes) -> list[dict]:
    records = []
    for line in data.decode("utf-8", errors="replace").split("\n"):
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(value, dict):
            continue
        record = {str(k): v for k, v in value.items() if _scalar(v)}
        record["skill_id"] = str(value.get("skill_id") or "sast")
        runtime = _runtime(value.get("runtime"))
        if runtime is not None:
            record["runtime"] = runtime
        records.append(record)
    return records


def check(data: bytes) -> None:
    records = records_from(data)
    before = json.dumps(records, sort_keys=True)

    for runtime_priority in (False, True):
        document = findings_to_sarif(records, runtime_priority=runtime_priority)
        written = json.loads(json.dumps(document, sort_keys=True))  # exactly what the CLI writes
        VALIDATOR.validate(written)
        run = written["runs"][0]
        rules, results = run["tool"]["driver"]["rules"], run["results"]
        assert len(results) == len(records)
        assert len({rule["id"] for rule in rules}) == len(rules)
        for result in results:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    text = findings_to_jsonl(records)
    lines = text.split("\n")[:-1] if text else []
    assert len(lines) == len(records)
    for line, record in zip(lines, records):
        assert json.loads(line) == json.loads(json.dumps(record))

    assert json.dumps(records, sort_keys=True) == before  # export never mutates its input


if __name__ == "__main__":
    main(check)
