"""Bridges secfoo's portable MCP server config (settings.py) to each agent
CLI's own mechanism for it. These differ a lot by CLI (verified directly
against each `--help` output, Aug 2026):

- claude: supports `--mcp-config <file>`, which loads servers scoped to just
  that one invocation -- no global state touched. Handled automatically by
  ClaudeAdapter on every run; no explicit sync step needed.
- gemini: has a `gemini mcp add <name> <commandOrUrl> ...` subcommand that
  registers a server persistently (user or project scope). No per-invocation
  file flag exists, so this must be done once via `secfoo mcp sync`.
- agent (Cursor): has no `mcp add` subcommand at all -- servers are defined
  by editing `~/.cursor/mcp.json` directly, then approved via
  `agent mcp enable <name>`. `secfoo mcp sync` does that merge.
- codex: reads `~/.codex/config.toml` (`[mcp_servers.<name>]`). secfoo does not
  use per-run `-c` overrides: command, URL and header values would appear in the
  process table (`ps`). `secfoo mcp sync` instead merges them into config.toml
  (comments and formatting preserved) with 0600 permissions.
- agy (Antigravity): agy 1.5.3 exposes an `agy mcp` subcommand, but secfoo does
  not yet automate syncing with agy's configuration. `secfoo mcp sync --agent agy`
  refuses with a clear error.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import tomlkit
from tomlkit.exceptions import TOMLKitError

from secfoo.config import STORE_DIR, write_private_text
from secfoo.settings import MCPServerConfig

CLAUDE_MCP_CONFIG_PATH = STORE_DIR / "claude-mcp-config.json"
CURSOR_MCP_CONFIG_PATH = Path.home() / ".cursor" / "mcp.json"
CODEX_CONFIG_PATH = Path.home() / ".codex" / "config.toml"

SYNC_SUPPORTED_AGENTS = {"gemini", "agent", "codex"}


@dataclass
class SyncResult:
    server_name: str
    ok: bool
    message: str


@dataclass(frozen=True)
class AgentMCPSupport:
    agent_id: str
    mechanism: str  # "per-run" | "sync" | "none"
    guidance: str


CANONICAL_MCP_SUPPORT: dict[str, AgentMCPSupport] = {
    "claude": AgentMCPSupport(
        agent_id="claude",
        mechanism="per-run",
        guidance="Automatic on every `secfoo run` (--mcp-config, scoped to invocation; global config untouched)",
    ),
    "agent": AgentMCPSupport(
        agent_id="agent",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent agent` once to register persistently in ~/.cursor/mcp.json",
    ),
    "gemini": AgentMCPSupport(
        agent_id="gemini",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent gemini` once to register persistently via `gemini mcp add`",
    ),
    "codex": AgentMCPSupport(
        agent_id="codex",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent codex` once to register persistently in ~/.codex/config.toml",
    ),
    "copilot": AgentMCPSupport(
        agent_id="copilot",
        mechanism="none",
        guidance="Not yet automated in secfoo mcp sync (planned for follow-up)",
    ),
    "opencode": AgentMCPSupport(
        agent_id="opencode",
        mechanism="none",
        guidance="Not yet automated in secfoo mcp sync (planned for follow-up)",
    ),
    "droid": AgentMCPSupport(
        agent_id="droid",
        mechanism="none",
        guidance="Not yet automated in secfoo mcp sync (planned for follow-up)",
    ),
    "devin": AgentMCPSupport(
        agent_id="devin",
        mechanism="none",
        guidance="Not yet automated in secfoo mcp sync (planned for follow-up)",
    ),
    "agy": AgentMCPSupport(
        agent_id="agy",
        mechanism="none",
        guidance="agy 1.5.3 exposes an 'agy mcp' subcommand, but secfoo does not yet automate syncing with agy",
    ),
    "api": AgentMCPSupport(
        agent_id="api",
        mechanism="none",
        guidance="API adapter invokes LLMs directly without a CLI agent or MCP client",
    ),
}


def format_mcp_support_text() -> str:
    """Returns a readable summary of MCP support across all agents."""
    lines = []
    for agent_id in sorted(CANONICAL_MCP_SUPPORT):
        support = CANONICAL_MCP_SUPPORT[agent_id]
        lines.append(f"- {agent_id} ({support.mechanism}): {support.guidance}")
    return "\n".join(lines)


def effective_servers(configured: list[MCPServerConfig]) -> list[MCPServerConfig]:
    """The user's own [[mcp_servers]] plus the default secfoo-memory
    server when memory is on (memory.memory_server). A user-defined server
    with the same name wins -- that is how a self-hosted enterprise memory
    service, or a staging URL, replaces the default."""
    from secfoo import memory

    servers = list(configured)
    default = memory.memory_server()
    if default is not None and all(server.name != default.name for server in servers):
        servers.append(default)
    return servers


def _server_to_standard_shape(server: MCPServerConfig) -> dict:
    """The de facto standard mcpServers entry shape shared by Claude Code,
    VS Code, and Cursor's own config files."""
    if server.command:
        entry: dict = {"command": server.command, "args": list(server.args)}
        if server.env:
            entry["env"] = dict(server.env)
        return entry
    entry = {"type": server.transport, "url": server.url}
    if server.headers:
        entry["headers"] = dict(server.headers)
    return entry


# ---------- claude: ephemeral, per-invocation ----------


def write_claude_mcp_config(servers: list[MCPServerConfig]) -> Path | None:
    """Writes ~/.secfoo/claude-mcp-config.json from the configured servers,
    for use with `claude --mcp-config <path>`. Returns None (and writes
    nothing) if no servers are configured, so the adapter can skip the flag
    entirely.
    """
    if not servers:
        return None
    payload = {"mcpServers": {s.name: _server_to_standard_shape(s) for s in servers}}
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    # Header values (the secfoo-memory bearer key, or any user server's
    # auth header) are secrets -- same 0600 as cloud.toml/memory.toml.
    write_private_text(CLAUDE_MCP_CONFIG_PATH, json.dumps(payload, indent=2))
    return CLAUDE_MCP_CONFIG_PATH


# ---------- gemini: persistent, via `gemini mcp add` ----------

_GEMINI_LIST_NAME_RE = re.compile(r"^[^\sA-Za-z0-9]*\s*([^\s:]+):")


def _run_cli(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """subprocess.run, launching exactly the binary shutil.which found.
    Popen ignores PATHEXT on Windows, so a bare "gemini" never finds npm's
    `gemini.cmd` shim and raises FileNotFoundError even when the CLI is
    installed (same fix as BaseAdapter.run)."""
    resolved = shutil.which(cmd[0]) or cmd[0]
    return subprocess.run([resolved, *cmd[1:]], capture_output=True, text=True, timeout=30, check=False)


def _gemini_existing_names() -> set[str]:
    proc = _run_cli(["gemini", "mcp", "list"])
    names = set()
    for line in proc.stdout.splitlines():
        match = _GEMINI_LIST_NAME_RE.match(line.strip())
        if match:
            names.add(match.group(1))
    return names


def _gemini_add_command(server: MCPServerConfig) -> list[str]:
    target = server.url if server.url else server.command
    cmd = ["gemini", "mcp", "add", "--scope", "user", server.name, target]
    if server.command:
        cmd += list(server.args)
    if server.transport != "stdio":
        cmd += ["-t", server.transport]
    for key, value in server.env.items():
        cmd += ["-e", f"{key}={value}"]
    for key, value in server.headers.items():
        cmd += ["-H", f"{key}: {value}"]
    return cmd


def sync_gemini(servers: list[MCPServerConfig]) -> list[SyncResult]:
    if shutil.which("gemini") is None:
        return [SyncResult("*", False, "gemini isn't installed (not found on PATH)")]
    existing = _gemini_existing_names()
    results = []
    for server in servers:
        if server.name in existing:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        proc = _run_cli(_gemini_add_command(server))
        if proc.returncode == 0:
            results.append(SyncResult(server.name, True, "added"))
        else:
            results.append(SyncResult(server.name, False, proc.stderr.strip() or proc.stdout.strip()))
    return results


# ---------- agent (Cursor): persistent, via ~/.cursor/mcp.json merge ----------


def sync_cursor(servers: list[MCPServerConfig]) -> list[SyncResult]:
    if shutil.which("agent") is None:
        return [SyncResult("*", False, "agent isn't installed (not found on PATH)")]
    CURSOR_MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    root: dict = {}
    existing: dict = {}
    if CURSOR_MCP_CONFIG_PATH.exists():
        try:
            root = json.loads(CURSOR_MCP_CONFIG_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return [SyncResult("*", False, f"{CURSOR_MCP_CONFIG_PATH} is not valid JSON: {exc}")]
        if not isinstance(root, dict):
            return [SyncResult("*", False, f"{CURSOR_MCP_CONFIG_PATH} is not a JSON object")]
        mcp_servers = root.get("mcpServers", {})
        if not isinstance(mcp_servers, dict):
            return [SyncResult("*", False, f"{CURSOR_MCP_CONFIG_PATH} has a non-object mcpServers value")]
        existing = mcp_servers

    results = []
    newly_added: list[str] = []
    for server in servers:
        if server.name in existing:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        existing[server.name] = _server_to_standard_shape(server)
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {CURSOR_MCP_CONFIG_PATH}"))

    if newly_added:
        root["mcpServers"] = existing
        # Same 0600 as claude-mcp-config.json: env and header values are secrets.
        write_private_text(CURSOR_MCP_CONFIG_PATH, json.dumps(root, indent=2))
        for name in newly_added:
            proc = _run_cli(["agent", "mcp", "enable", name])
            if proc.returncode != 0:
                for result in results:
                    if result.server_name == name:
                        result.ok = False
                        result.message += f" (enable failed: {proc.stderr.strip()})"
    elif os.name == "posix":
        # Nothing new to write, but an older secfoo may have left our
        # servers' secrets in a 0644 file: tighten it on this re-run too.
        try:
            CURSOR_MCP_CONFIG_PATH.chmod(0o600)
        except OSError:
            pass  # e.g. not our file; the sync itself still succeeded
    return results


# ---------- codex: persistent, via ~/.codex/config.toml merge ----------


def sync_codex(servers: list[MCPServerConfig]) -> list[SyncResult]:
    if shutil.which("codex") is None:
        return [SyncResult("*", False, "codex isn't installed (not found on PATH)")]

    doc = tomlkit.document()
    if CODEX_CONFIG_PATH.exists():
        try:
            content = CODEX_CONFIG_PATH.read_text(encoding="utf-8")
            parsed = tomlkit.parse(content)
        except (TOMLKitError, OSError) as exc:
            return [SyncResult("*", False, f"{CODEX_CONFIG_PATH} is not valid TOML: {exc}")]
        if not isinstance(parsed, dict):
            return [SyncResult("*", False, f"{CODEX_CONFIG_PATH} is not a TOML table")]
        doc = parsed

    mcp_servers = doc.get("mcp_servers")
    if mcp_servers is None:
        mcp_servers = tomlkit.table()
        doc["mcp_servers"] = mcp_servers
    elif not isinstance(mcp_servers, dict):
        return [SyncResult("*", False, f"{CODEX_CONFIG_PATH} has a non-table mcp_servers entry")]

    results = []
    newly_added: list[str] = []
    for server in servers:
        if server.name in mcp_servers:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue

        if server.command:
            server_tbl = tomlkit.table()
            server_tbl["command"] = server.command
            server_tbl["args"] = list(server.args)
            if server.env:
                env_tbl = tomlkit.table()
                for k, v in server.env.items():
                    env_tbl[k] = v
                server_tbl["env"] = env_tbl
            mcp_servers[server.name] = server_tbl
            newly_added.append(server.name)
            results.append(SyncResult(server.name, True, f"added to {CODEX_CONFIG_PATH}"))
        elif server.url:
            if server.transport == "sse":
                results.append(
                    SyncResult(
                        server.name,
                        False,
                        "Codex does not support SSE transport for remote MCP servers (only streamable-HTTP is supported)",
                    )
                )
                continue
            server_tbl = tomlkit.table()
            server_tbl["url"] = server.url
            if server.headers:
                headers_tbl = tomlkit.table()
                for k, v in server.headers.items():
                    headers_tbl[k] = v
                server_tbl["http_headers"] = headers_tbl
            mcp_servers[server.name] = server_tbl
            newly_added.append(server.name)
            results.append(SyncResult(server.name, True, f"added to {CODEX_CONFIG_PATH}"))
        else:
            results.append(SyncResult(server.name, False, "server must define either 'command' or 'url'"))

    if newly_added:
        write_private_text(CODEX_CONFIG_PATH, tomlkit.dumps(doc))
    elif os.name == "posix":
        try:
            CODEX_CONFIG_PATH.resolve().chmod(0o600)
        except OSError:
            pass
    return results


def sync(agent_id: str, servers: list[MCPServerConfig]) -> list[SyncResult]:
    if agent_id == "gemini":
        return sync_gemini(servers)
    if agent_id == "agent":
        return sync_cursor(servers)
    if agent_id == "codex":
        return sync_codex(servers)
    raise ValueError(
        f"secfoo mcp sync isn't supported for {agent_id!r}.\n\n"
        f"Agent MCP support:\n\n"
        f"{format_mcp_support_text()}"
    )
