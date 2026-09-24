"""Hash a small window of source around a reported line for stable SAST identity.

Used by report/sast.py fingerprinting so two distinct issues in the same file
(CWE + path) stay separate even when the agent paraphrases titles, while the
same underlying code region keeps a stable key across rescans.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

# Lines before/after the reported line (inclusive window).
_CONTEXT_LINES = 4

# Collapse horizontal whitespace so formatting-only edits don't churn the hash.
_WS_RE = re.compile(r"[ \t]+")


def _normalize_snippet_line(line: str) -> str:
    return _WS_RE.sub(" ", line.rstrip())


def hash_code_region(workdir: Path, file_path: str, line: str | int | None) -> str | None:
    """Return SHA-256 hex of normalized source around `line`, or None if unavailable."""
    if line is None:
        return None
    try:
        center = int(str(line).strip())
    except ValueError:
        return None
    if center < 1:
        return None

    rel = file_path.strip().lstrip("./")
    if not rel or rel.startswith("..") or "/../" in rel:
        return None

    root = workdir.resolve()
    target = (root / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return None
    if not target.is_file():
        return None

    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if "\x00" in text:
        return None

    lines = text.splitlines()
    start = max(center - 1 - _CONTEXT_LINES, 0)
    end = min(center - 1 + _CONTEXT_LINES + 1, len(lines))
    if start >= len(lines):
        return None

    window = "\n".join(_normalize_snippet_line(line) for line in lines[start:end])
    if not window.strip():
        return None
    return hashlib.sha256(window.encode("utf-8")).hexdigest()
