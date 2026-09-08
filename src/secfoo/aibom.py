"""Parses AI-BOM (AI bill of materials) files attached to an assessment
into a model/tool inventory. This is secfoo's own pragmatic schema, not an
attempt to match an external standard -- see README/plan for the two
accepted shapes (JSON with "models"/"tools" arrays, or a flat CSV with a
"kind" column).
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class AIBOMParseError(ValueError):
    """Raised on malformed AI-BOM input -- never silently dropped rows."""


@dataclass(frozen=True)
class AIBOMSummary:
    models: list[dict[str, str | None]] = field(default_factory=list)
    tools: list[dict[str, str | None]] = field(default_factory=list)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _json_rows(entries: Any, key: str, provider_key: str) -> list[dict[str, str | None]]:
    if not isinstance(entries, list):
        raise AIBOMParseError(f"'{key}' must be an array")
    rows = []
    for entry in entries:
        if not isinstance(entry, dict) or not _clean(entry.get("name")):
            raise AIBOMParseError(f"each entry in '{key}' needs at least a non-empty 'name'")
        rows.append(
            {
                "name": _clean(entry.get("name")),
                "provider_or_type": _clean(entry.get(provider_key)),
                "version": _clean(entry.get("version")),
                "purpose": _clean(entry.get("purpose")),
            }
        )
    return rows


def _parse_json(text: str) -> AIBOMSummary:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AIBOMParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AIBOMParseError("expected a JSON object with 'models' and/or 'tools' arrays")
    return AIBOMSummary(
        models=_json_rows(data.get("models", []), "models", "provider"),
        tools=_json_rows(data.get("tools", []), "tools", "type"),
    )


def _parse_csv(text: str) -> AIBOMSummary:
    reader = csv.DictReader(text.splitlines())
    fieldnames = reader.fieldnames or []
    if "kind" not in fieldnames or "name" not in fieldnames:
        raise AIBOMParseError("CSV must have a header row with at least 'kind' and 'name' columns")

    models: list[dict[str, str | None]] = []
    tools: list[dict[str, str | None]] = []
    for row in reader:
        name = _clean(row.get("name"))
        if not name:
            continue
        kind = (row.get("kind") or "").strip().lower()
        item = {
            "name": name,
            "provider_or_type": _clean(row.get("provider_or_type")),
            "version": _clean(row.get("version")),
            "purpose": _clean(row.get("purpose")),
        }
        if kind == "model":
            models.append(item)
        elif kind == "tool":
            tools.append(item)
        else:
            raise AIBOMParseError(f"unknown 'kind' {row.get('kind')!r} on row for {name!r} -- must be 'model' or 'tool'")
    return AIBOMSummary(models=models, tools=tools)


def parse_ai_bom(path: Path) -> AIBOMSummary:
    text = path.read_text()
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _parse_json(text)
    if suffix == ".csv":
        return _parse_csv(text)
    raise AIBOMParseError(f"unsupported AI-BOM file type {suffix!r} -- expected .json or .csv")
