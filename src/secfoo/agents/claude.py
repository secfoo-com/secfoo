from __future__ import annotations

import json
from pathlib import Path

from secfoo.agents.base import AgentAdapter
from secfoo.mcp import write_claude_mcp_config
from secfoo.settings import load_config

# Minimal read-only tool grant: the assessment only needs to read the
# target and look at git history/diffs, never to edit anything.
ALLOWED_TOOLS = "Read,Grep,Glob,Bash(git log:*),Bash(git diff:*)"


class ClaudeAdapter(AgentAdapter):
    name = "claude"
    binary = "claude"
    default_timeout_seconds = 1800

    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        # MCP servers from ~/.secfoo/config.toml are injected here, scoped
        # to just this invocation (claude's --mcp-config), never touching
        # the user's own global Claude config.
        mcp_servers = load_config().mcp_servers
        mcp_config_path = write_claude_mcp_config(mcp_servers)

        # `mcp__<server-name>` (server-level, no tool suffix) grants every
        # tool that server exposes -- verified directly: without this, a
        # configured MCP server is loaded but every tool call on it is
        # silently denied (shows up in the report as "permission grant was
        # not available"), which looks identical to the server not being
        # connected at all unless you go dig through stderr.
        allowed_tools = ALLOWED_TOOLS
        if mcp_config_path:
            allowed_tools += "," + ",".join(f"mcp__{server.name}" for server in mcp_servers)

        cmd = [
            self.binary,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--allowedTools",
            allowed_tools,
            "--permission-mode",
            "default",
        ]
        if mcp_config_path:
            cmd += ["--mcp-config", str(mcp_config_path)]
        return cmd

    def extract_report(self, stdout: str) -> str:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return stdout
        return payload.get("result", stdout)
