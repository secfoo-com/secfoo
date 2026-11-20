"""Resolves combined documentation context and Confluence URLs for a run (#125).

Bridges CLI and Web entry points into execute_runs, producing both the full
list of ContextSource objects and the list of classified Confluence URLs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from secfoo.context_brief import classify_url
from secfoo.context_sources import ContextSource, resolve_context_sources

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from secfoo.settings import MCPServerConfig


@dataclass(frozen=True)
class RunContext:
    """Resolved context sources and Confluence URLs for an assessment run."""

    sources: list[ContextSource]
    confluence_urls: list[str]


def resolve_run_context(
    *,
    defaults_context: Sequence[str],
    confluence_values: Sequence[str],
    context_values: Sequence[str],
    target_dir: Path | None,
    mcp_servers: Sequence[MCPServerConfig],
) -> RunContext:
    """Resolve context sources and classify Confluence URLs for a run.

    Calls resolve_context_sources to validate and deduplicate sources. A URL
    source is included in confluence_urls if it was supplied via legacy
    confluence_values or classified as "confluence" via host/path heuristics
    or configured MCP server hosts.
    """
    sources = resolve_context_sources(
        from_config=list(defaults_context),
        from_confluence_flag=list(confluence_values),
        from_context_flag=list(context_values),
        target_dir=target_dir,
    )

    legacy_confluence = {val.strip() for val in confluence_values if val.strip()}
    servers_list = list(mcp_servers)

    confluence_urls: list[str] = []
    for source in sources:
        if source.kind != "url":
            continue
        if source.raw.strip() in legacy_confluence or classify_url(source.location, servers_list) == "confluence":
            confluence_urls.append(source.location)

    return RunContext(sources=sources, confluence_urls=confluence_urls)
