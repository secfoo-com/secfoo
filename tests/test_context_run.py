from __future__ import annotations

import pytest

from secfoo.context_run import RunContext, resolve_run_context
from secfoo.context_sources import ContextSourceError
from secfoo.settings import MCPServerConfig


def test_empty_inputs_return_empty_run_context():
    ctx = resolve_run_context(
        defaults_context=[],
        confluence_values=[],
        context_values=[],
        target_dir=None,
        mcp_servers=[],
    )
    assert isinstance(ctx, RunContext)
    assert ctx.sources == []
    assert ctx.confluence_urls == []


def test_legacy_confluence_flag_populates_confluence_urls():
    url = "https://wiki.example.com/custom-page"
    ctx = resolve_run_context(
        defaults_context=[],
        confluence_values=[url],
        context_values=[],
        target_dir=None,
        mcp_servers=[],
    )
    assert len(ctx.sources) == 1
    assert ctx.sources[0].location == url
    assert ctx.confluence_urls == [url]


def test_classified_confluence_url_populates_confluence_urls():
    atlassian_url = "https://acme.atlassian.net/wiki/spaces/SEC/pages/123"
    ctx = resolve_run_context(
        defaults_context=[],
        confluence_values=[],
        context_values=[atlassian_url],
        target_dir=None,
        mcp_servers=[],
    )
    assert len(ctx.sources) == 1
    assert ctx.confluence_urls == [atlassian_url]


def test_mcp_host_matched_confluence_url_populates_confluence_urls():
    internal_url = "https://wiki.internal.corp/display/SEC/Design"
    servers = [
        MCPServerConfig(
            name="atlassian-mcp",
            command="npx",
            args=["atlassian-mcp"],
            hosts=["wiki.internal.corp"],
        )
    ]
    ctx = resolve_run_context(
        defaults_context=[],
        confluence_values=[],
        context_values=[internal_url],
        target_dir=None,
        mcp_servers=servers,
    )
    assert ctx.confluence_urls == [internal_url]


def test_non_confluence_url_not_in_confluence_urls():
    jira_url = "https://acme.atlassian.net/browse/SEC-101"
    github_url = "https://github.com/org/repo"
    servers = [
        MCPServerConfig(
            name="jira-mcp",
            command="npx",
            args=["jira-mcp"],
            hosts=["acme.atlassian.net"],
        )
    ]
    ctx = resolve_run_context(
        defaults_context=[jira_url],
        confluence_values=[],
        context_values=[github_url],
        target_dir=None,
        mcp_servers=servers,
    )
    assert len(ctx.sources) == 2
    assert ctx.confluence_urls == []


def test_local_files_and_folders_not_in_confluence_urls(tmp_path):
    doc = tmp_path / "design.md"
    doc.write_text("design", encoding="utf-8")
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "arch.md").write_text("arch", encoding="utf-8")

    ctx = resolve_run_context(
        defaults_context=[str(doc)],
        confluence_values=[],
        context_values=[str(folder)],
        target_dir=None,
        mcp_servers=[],
    )
    assert len(ctx.sources) == 2
    assert ctx.confluence_urls == []


def test_deduplication_and_order_across_inputs():
    url_a = "https://acme.atlassian.net/wiki/spaces/A"
    url_b = "https://acme.atlassian.net/wiki/spaces/B"
    url_c = "https://acme.atlassian.net/wiki/spaces/C"

    ctx = resolve_run_context(
        defaults_context=[url_a],
        confluence_values=[url_b],
        context_values=[url_a, url_c],
        target_dir=None,
        mcp_servers=[],
    )
    assert [s.location for s in ctx.sources] == [url_a, url_b, url_c]
    assert ctx.confluence_urls == [url_a, url_b, url_c]


def test_error_propagates_on_invalid_source(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    inside_doc = target / "inside.md"
    inside_doc.write_text("x", encoding="utf-8")

    with pytest.raises(ContextSourceError, match="inside the scanned target"):
        resolve_run_context(
            defaults_context=[],
            confluence_values=[],
            context_values=[str(inside_doc)],
            target_dir=target,
            mcp_servers=[],
        )
