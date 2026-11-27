"""A tiny stdio MCP server for the api agent's tool-loop tests (#123).

Run as a script: `python fake_mcp_server.py`. One read-only tool, one write
tool, and one tool without annotations.
"""

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

server = FastMCP("fake-docs")


@server.tool(annotations=ToolAnnotations(readOnlyHint=True))
def confluence_get_page(url: str) -> str:
    """Return the body of a Confluence page."""
    return f"Page {url}: every internal service must use mTLS."


@server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
def confluence_update_page(url: str, body: str) -> str:
    """Overwrite a Confluence page."""
    return "updated"


@server.tool()
def jira_search(query: str) -> str:
    """Search Jira issues (no annotations)."""
    return f"no issues match {query}"


if __name__ == "__main__":
    server.run()
