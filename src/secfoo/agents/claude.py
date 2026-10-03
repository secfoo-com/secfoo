from __future__ import annotations

import json
from pathlib import Path

from secfoo.agents.base import AgentAdapter, Usage
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

    def extract_usage(self, stdout: str) -> Usage:
        # `--output-format json` reports total_cost_usd plus a usage block.
        # On a subscription login the cost is claude's API-price estimate,
        # not an amount actually billed.
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return Usage()
        if not isinstance(payload, dict):
            return Usage()
        usage = payload.get("usage") or {}
        input_tokens = sum(
            usage.get(key) or 0
            for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
        )
        cost = payload.get("total_cost_usd")
        return Usage(
            input_tokens=input_tokens if usage else None,
            output_tokens=usage.get("output_tokens"),
            cost_usd=float(cost) if cost is not None else None,
        )
