"""Documentation coverage parser and run reconciliation logic (#125).

Parses the Documentation Coverage table from agent report markdown and reconciles
the reported results against secfoo's ContextBrief entries. This module is
best-effort and will never raise an exception on malformed reports or unexpected input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secfoo.context_brief import ContextBrief

# Maximum number of coverage rows or records returned.
MAX_ROWS = 100
# Maximum character length for a source label or location.
MAX_SOURCE_CHARS = 300
# Maximum character length for a source type description.
MAX_TYPE_CHARS = 60
# Maximum character length for notes or details.
MAX_NOTES_CHARS = 500

_HEADING_RE = re.compile(r"^(#{1,6})\s*(.*)$")
_LEADING_NUM_RE = re.compile(r"^\d+[\.\)]?\s*")
_NOTES_KEYWORDS = ("notes", "details", "comment", "secrets found")
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_HTTPS_TOKEN_RE = re.compile(r"https://[^\s<>()\[\]|`'\"]+")
_TRAILING_PAREN_RE = re.compile(r"\s*\([^()]*\)\s*$")


@dataclass(frozen=True)
class CoverageRecord:
    source: str
    type: str
    reached: bool
    notes: str


def _clean_cell(cell: str) -> str:
    cleaned = re.sub(r"[`*]", "", cell)
    return " ".join(cleaned.split())


def _split_row(line: str) -> list[str]:
    cells: list[str] = []
    current: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == "\\" and i + 1 < n and line[i + 1] == "|":
            current.append("|")
            i += 2
        elif c == "|":
            cells.append("".join(current).strip())
            current = []
            i += 1
        else:
            current.append(c)
            i += 1
    cells.append("".join(current).strip())
    if cells and cells[0] == "":
        cells.pop(0)
    if cells and cells[-1] == "":
        cells.pop()
    return cells


def _is_separator_row(cells: list[str]) -> bool:
    if not cells:
        return False
    return all(cell and all(ch in "-: " for ch in cell) and "-" in cell for cell in cells)


def _sanitize_source_label(source: str) -> str:
    if not source.lower().startswith(("http://", "https://")):
        try:
            p = Path(source)
            if p.is_absolute():
                return p.name
        except (ValueError, TypeError, OSError):
            return source
    return source


def _get_cell(cells: list[str], idx: int | None) -> str:
    if idx is None or idx >= len(cells):
        return ""
    return cells[idx]


def parse_documentation_coverage(report_markdown: str) -> list[CoverageRecord]:
    """Parse the documentation coverage table from report markdown."""
    normalized = report_markdown.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")

    candidates: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        match = _HEADING_RE.match(line)
        if match:
            raw_text = match.group(2).strip(" \t*")
            clean_text = _LEADING_NUM_RE.sub("", raw_text).strip(" \t*").lower()
            if clean_text in {"documentation coverage", "documentation & confluence coverage"}:
                candidates.append((i, len(match.group(1))))

    if not candidates:
        return []

    for cand_idx, cand_level in candidates:
        table_lines: list[str] = []
        in_table = False
        for line in lines[cand_idx + 1:]:
            stripped = line.strip()
            if not in_table:
                match = _HEADING_RE.match(line)
                if match and len(match.group(1)) <= cand_level:
                    break
                if stripped.startswith("|"):
                    in_table = True
                    table_lines.append(stripped)
                else:
                    continue
            else:
                if not stripped or not stripped.startswith("|"):
                    break
                table_lines.append(stripped)

        if not table_lines:
            continue

        header_cells = _split_row(table_lines[0])
        headers = [re.sub(r"[`*]", "", h).strip().lower() for h in header_cells]

        source_idx: int | None = None
        reached_idx: int | None = None
        type_idx: int | None = None
        notes_idx: int | None = None

        for i, h in enumerate(headers):
            if source_idx is None and "source" in h:
                source_idx = i
            if reached_idx is None and h.startswith("reached"):
                reached_idx = i
            if type_idx is None and "type" in h:
                type_idx = i
            if notes_idx is None and any(kw in h for kw in _NOTES_KEYWORDS):
                notes_idx = i

        if source_idx is None or reached_idx is None:
            continue

        rows: list[CoverageRecord] = []
        for line in table_lines[1:]:
            cells = _split_row(line)
            if _is_separator_row(cells):
                continue

            source_cell = _clean_cell(_get_cell(cells, source_idx))
            if not source_cell:
                continue

            type_cell = _clean_cell(_get_cell(cells, type_idx))
            reached_cell = _clean_cell(_get_cell(cells, reached_idx))
            notes_cell = _clean_cell(_get_cell(cells, notes_idx))

            r_lower = reached_cell.lower()
            if r_lower.startswith("partial"):
                reached = False
                if notes_cell:
                    notes_cell = f"Partial: {notes_cell}"
                else:
                    extra = reached_cell[len("partial"):].lstrip(" -:,")
                    notes_cell = f"Partial: {extra}" if extra else "Partial"
            elif (
                r_lower.startswith(("yes", "true", "reached"))
                or bool(re.match(r"^y([^a-z]|$)", r_lower))
                or ("\u2713" in reached_cell or "\u2705" in reached_cell)
            ):
                reached = True
            else:
                reached = False

            rows.append(
                CoverageRecord(
                    source=source_cell[:MAX_SOURCE_CHARS],
                    type=type_cell[:MAX_TYPE_CHARS],
                    reached=reached,
                    notes=notes_cell[:MAX_NOTES_CHARS],
                )
            )
            if len(rows) >= MAX_ROWS:
                break

        if rows:
            return rows

    return []


def _normalize_key(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[`*]", "", s)
    s = s.strip()
    while s.startswith("<") and s.endswith(">"):
        s = s[1:-1].strip()
    s = s.replace("\\", "/")
    return s.rstrip("/")


def _row_keys(source_cell: str) -> set[str]:
    keys: set[str] = set()
    k_a = _normalize_key(source_cell)
    if k_a:
        keys.add(k_a)
    for match in _MARKDOWN_LINK_RE.finditer(source_cell):
        k_text = _normalize_key(match.group(1))
        k_target = _normalize_key(match.group(2))
        if k_text:
            keys.add(k_text)
        if k_target:
            keys.add(k_target)
    for match in _HTTPS_TOKEN_RE.finditer(source_cell):
        token = match.group(0).rstrip(".,;:")
        k_c = _normalize_key(token)
        if k_c:
            keys.add(k_c)
    cell_no_paren = _TRAILING_PAREN_RE.sub("", source_cell)
    k_d = _normalize_key(cell_no_paren)
    if k_d:
        keys.add(k_d)
    return keys


def coverage_for_run(
    brief: ContextBrief | None,
    report_markdown: str,
    *,
    run_succeeded: bool,
) -> list[CoverageRecord]:
    """Reconcile context brief entries with parsed documentation coverage."""
    if brief is None:
        return []

    rows = parse_documentation_coverage(report_markdown) if report_markdown else []
    used_row_indices: set[int] = set()
    matched_rows: dict[int, int] = {}

    row_keys_list = [_row_keys(row.source) for row in rows]

    # Exact matching only: match entries in order; each row is used at most once
    for index, entry in enumerate(brief.entries):
        norm_label = _normalize_key(entry.label)
        if not norm_label:
            continue
        for r_idx, keys in enumerate(row_keys_list):
            if r_idx in used_row_indices:
                continue
            if norm_label in keys:
                matched_rows[index] = r_idx
                used_row_indices.add(r_idx)
                break

    records: list[CoverageRecord] = []
    for index, entry in enumerate(brief.entries):
        label = entry.label
        matched_idx = matched_rows.get(index)
        row = rows[matched_idx] if matched_idx is not None else None

        if entry.reached is None:
            if not run_succeeded:
                rec_reached = False
                rec_notes = "run did not complete"
            elif row is not None:
                rec_reached = row.reached
                rec_notes = row.notes
            else:
                rec_reached = False
                rec_notes = "not reported by the agent"
        else:
            if entry.reached is False:
                rec_reached = False
                rec_notes = entry.note or "not read by secfoo"
            else:
                rec_reached = True
                rec_notes = row.notes if (row is not None and row.notes) else entry.note

        records.append(
            CoverageRecord(
                source=_sanitize_source_label(label)[:MAX_SOURCE_CHARS],
                type=entry.type_label[:MAX_TYPE_CHARS],
                reached=rec_reached,
                notes=rec_notes[:MAX_NOTES_CHARS],
            )
        )

    if run_succeeded:
        for r_idx, row in enumerate(rows):
            if r_idx not in used_row_indices:
                extra_type = row.type if row.type else "reported by the agent"
                records.append(
                    CoverageRecord(
                        source=_sanitize_source_label(row.source)[:MAX_SOURCE_CHARS],
                        type=extra_type[:MAX_TYPE_CHARS],
                        reached=row.reached,
                        notes=row.notes[:MAX_NOTES_CHARS],
                    )
                )

    return records[:MAX_ROWS]
