"""Display helpers for per-run AI spend, shared by the CLI and dashboard.

None means the agent didn't report the value (Cursor and Antigravity print
plain text only), so it renders as "-" rather than a misleading $0.00.
"""

from __future__ import annotations


def format_cost(value: float | None) -> str:
    if value is None:
        return "-"
    if 0 < value < 0.01:
        return "<$0.01"
    return f"${value:,.2f}"


def format_tokens(value: int | None) -> str:
    if value is None:
        return "-"
    return f"{value:,}"
