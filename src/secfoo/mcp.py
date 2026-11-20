r"""Bridges secfoo's portable MCP server config (settings.py) to each agent
CLI's own mechanism for it. These differ a lot by CLI (verified directly
against each CLI's configuration capabilities, Nov 2026):

- claude: supports `--mcp-config <file>` and `--strict-mcp-config`, which loads
  servers scoped to just that one invocation -- no global state touched. Handled
  automatically by ClaudeAdapter on every run; no explicit sync step needed.
- gemini: has a `gemini mcp add <name> <commandOrUrl> ...` subcommand that
  registers a server persistently (user or project scope). No per-invocation
  file flag exists, so this must be done once via `secfoo mcp sync`.
- agent (Cursor): has no `mcp add` subcommand -- servers are defined by editing
  `~/.cursor/mcp.json` directly, then approved via `agent mcp enable <name>`.
  `secfoo mcp sync --agent agent` merges them into `~/.cursor/mcp.json`.
- codex: reads `~/.codex/config.toml` (`[mcp_servers.<name>]`). `secfoo mcp sync
  --agent codex` merges servers into `~/.codex/config.toml` without clobbering
  other settings.
- copilot: reads `~/.copilot/mcp-config.json` (`mcpServers` with `"type": "local"|"http"`).
  `secfoo mcp sync --agent copilot` registers them persistently.
- opencode: reads `~/.config/opencode/opencode.json` (`"mcp": { ... }`). `secfoo mcp
  sync --agent opencode` registers them persistently.
- droid: reads `~/.factory/mcp.json` (`mcpServers`). `secfoo mcp sync --agent droid`
  merges them into `~/.factory/mcp.json`.
- devin: reads `~/.config/devin/mcp_config.json` (or `%APPDATA%\devin\mcp_config.json` on Windows).
  `secfoo mcp sync --agent devin` merges them persistently.
- agy (Antigravity): no MCP subcommand or flag exposed by the CLI for non-interactive
  review runs as of 2026-11-20 (verified against Antigravity CLI 2.0). Refuses with
  the support matrix.
- api: calls model APIs directly via LiteLLM/LangGraph; no tool-use loop for MCP servers.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from secfoo.config import STORE_DIR
from secfoo.settings import MCPServerConfig

CLAUDE_MCP_CONFIG_PATH = STORE_DIR / "claude-mcp-config.json"
CURSOR_MCP_CONFIG_PATH = Path.home() / ".cursor" / "mcp.json"
CODEX_MCP_CONFIG_PATH = Path.home() / ".codex" / "config.toml"
COPILOT_MCP_CONFIG_PATH = Path.home() / ".copilot" / "mcp-config.json"
OPENCODE_MCP_CONFIG_PATH = Path.home() / ".config" / "opencode" / "opencode.json"
DROID_MCP_CONFIG_PATH = Path.home() / ".factory" / "mcp.json"


def _default_devin_path() -> Path:
    if os.name == "nt" and "APPDATA" in os.environ:
        return Path(os.environ["APPDATA"]) / "devin" / "mcp_config.json"
    return Path.home() / ".config" / "devin" / "mcp_config.json"


DEVIN_MCP_CONFIG_PATH = _default_devin_path()

SYNC_SUPPORTED_AGENTS = {"gemini", "agent", "codex", "copilot", "opencode", "droid", "devin"}


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
        guidance=(
            "Automatic on every `secfoo run` (`--mcp-config`, scoped to that invocation only — "
            "your global Claude config is never touched). These are the only MCP servers loaded "
            "during a scan (`--strict-mcp-config`): servers from your global Claude config or "
            "from the target's `.mcp.json` are not started"
        ),
    ),
    "agent": AgentMCPSupport(
        agent_id="agent",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent agent` once to register persistently in `~/.cursor/mcp.json`",
    ),
    "gemini": AgentMCPSupport(
        agent_id="gemini",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent gemini` once to register persistently via `gemini mcp add`",
    ),
    "codex": AgentMCPSupport(
        agent_id="codex",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent codex` once to merge persistently into `~/.codex/config.toml` without clobbering other settings",
    ),
    "copilot": AgentMCPSupport(
        agent_id="copilot",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent copilot` once to register persistently in `~/.copilot/mcp-config.json`",
    ),
    "opencode": AgentMCPSupport(
        agent_id="opencode",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent opencode` once to register persistently in `~/.config/opencode/opencode.json`",
    ),
    "droid": AgentMCPSupport(
        agent_id="droid",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent droid` once to register persistently in `~/.factory/mcp.json`",
    ),
    "devin": AgentMCPSupport(
        agent_id="devin",
        mechanism="sync",
        guidance="Run `secfoo mcp sync --agent devin` once to register persistently in `~/.config/devin/mcp_config.json` (%APPDATA%\\devin\\mcp_config.json on Windows)",
    ),
    "agy": AgentMCPSupport(
        agent_id="agy",
        mechanism="none",
        guidance="Not supported — the `agy` CLI has no MCP configuration mechanism as of 2026-11-20 (verified against Antigravity CLI 2.0)",
    ),
    "api": AgentMCPSupport(
        agent_id="api",
        mechanism="none",
        guidance="Not supported — the `api` agent calls model APIs directly and has no tool-use loop for MCP servers",
    ),
}


def parse_mcp_support_from_reference_md(text: str) -> dict[str, AgentMCPSupport]:
    in_section = False
    matrix: dict[str, AgentMCPSupport] = {}
    for line in text.splitlines():
        if "How MCP servers reach each agent varies" in line:
            in_section = True
            continue
        if in_section:
            stripped = line.strip()
            if matrix and (stripped.startswith("```") or (stripped.startswith("#") and not stripped.startswith("###"))):
                break
            if stripped.startswith("|") and not stripped.startswith("|---"):
                parts = [p.strip() for p in stripped.split("|")[1:-1]]
                if len(parts) >= 3 and parts[0] != "Agent":
                    raw_id = parts[0]
                    match = re.search(r"`([^`]+)`", raw_id)
                    agent_id = match.group(1).split()[0] if match else raw_id.split()[0]
                    mechanism = parts[1].strip()
                    guidance = parts[2].strip()
                    matrix[agent_id] = AgentMCPSupport(agent_id=agent_id, mechanism=mechanism, guidance=guidance)
    return matrix


def get_mcp_support_matrix() -> dict[str, AgentMCPSupport]:
    ref_md = Path(__file__).resolve().parents[2] / "docs" / "REFERENCE.md"
    if ref_md.exists():
        try:
            parsed = parse_mcp_support_from_reference_md(ref_md.read_text(encoding="utf-8"))
            if parsed:
                return parsed
        except (OSError, UnicodeDecodeError, ValueError):
            return CANONICAL_MCP_SUPPORT
    return CANONICAL_MCP_SUPPORT


def format_mcp_support_table() -> str:
    matrix = get_mcp_support_matrix()
    header = "| Agent | Mechanism | Guidance |\n|---|---|---|"
    rows = [f"| `{item.agent_id}` | {item.mechanism} | {item.guidance} |" for item in matrix.values()]
    return "\n".join([header] + rows)


def agent_mcp_mechanism(agent_id: str) -> str:
    matrix = get_mcp_support_matrix()
    if agent_id in matrix:
        return matrix[agent_id].mechanism
    return "none"


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
    VS Code, Cursor, Droid, and Devin."""
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
    CLAUDE_MCP_CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # Header values (the secfoo-memory bearer key, or any user server's
    # auth header) are secrets -- same 0600 as cloud.toml/memory.toml.
    try:
        CLAUDE_MCP_CONFIG_PATH.chmod(0o600)
    except OSError:
        pass
    return CLAUDE_MCP_CONFIG_PATH


# ---------- gemini: persistent, via `gemini mcp add` ----------

_GEMINI_LIST_NAME_RE = re.compile(r"^[^\sA-Za-z0-9]*\s*([^\s:]+):")


def _gemini_existing_names() -> set[str]:
    proc = subprocess.run(["gemini", "mcp", "list"], capture_output=True, text=True, timeout=30, check=False)
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
    existing = _gemini_existing_names()
    results = []
    for server in servers:
        if server.name in existing:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        proc = subprocess.run(_gemini_add_command(server), capture_output=True, text=True, timeout=30, check=False)
        if proc.returncode == 0:
            results.append(SyncResult(server.name, True, "added"))
        else:
            results.append(SyncResult(server.name, False, proc.stderr.strip() or proc.stdout.strip()))
    return results


# ---------- agent (Cursor): persistent, via ~/.cursor/mcp.json merge ----------


def sync_cursor(servers: list[MCPServerConfig]) -> list[SyncResult]:
    CURSOR_MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing_root: dict = {}
    existing: dict = {}
    if CURSOR_MCP_CONFIG_PATH.exists():
        try:
            existing_root = json.loads(CURSOR_MCP_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(existing_root, dict):
                existing = existing_root.get("mcpServers", {})
                if not isinstance(existing, dict):
                    existing = {}
        except (json.JSONDecodeError, OSError) as exc:
            return [SyncResult("*", False, f"{CURSOR_MCP_CONFIG_PATH} is not valid JSON: {exc}")]

    results = []
    newly_added: list[str] = []
    for server in servers:
        shape = _server_to_standard_shape(server)
        if server.name in existing and existing[server.name] == shape:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        existing[server.name] = shape
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {CURSOR_MCP_CONFIG_PATH}"))

    if newly_added:
        existing_root["mcpServers"] = existing
        CURSOR_MCP_CONFIG_PATH.write_text(json.dumps(existing_root, indent=2), encoding="utf-8")
        for name in newly_added:
            proc = subprocess.run(["agent", "mcp", "enable", name], capture_output=True, text=True, timeout=30, check=False)
            if proc.returncode != 0:
                for result in results:
                    if result.server_name == name:
                        result.ok = False
                        result.message += f" (enable failed: {proc.stderr.strip()})"
    return results


# ---------- codex: persistent, via ~/.codex/config.toml merge ----------


def _toml_key(key: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]+", key):
        return key
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _dump_toml_val(val: object) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        escaped = val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    if isinstance(val, (list, tuple)):
        return "[" + ", ".join(_dump_toml_val(x) for x in val) + "]"
    if isinstance(val, dict):
        return "{ " + ", ".join(f"{_toml_key(k)} = {_dump_toml_val(v)}" for k, v in val.items()) + " }"
    raise TypeError(f"Unsupported TOML value type: {type(val)}")


def _dumps_toml(data: dict) -> str:
    lines = []
    # 1. Top-level scalars/lists/inline-tables
    for k, v in data.items():
        if not isinstance(v, dict):
            lines.append(f"{_toml_key(k)} = {_dump_toml_val(v)}")
    # 2. Tables & subtables
    for k, v in data.items():
        if isinstance(v, dict):
            scalars = {sk: sv for sk, sv in v.items() if not isinstance(sv, dict)}
            nested = {sk: sv for sk, sv in v.items() if isinstance(sv, dict)}
            if scalars:
                lines.append(f"\n[{_toml_key(k)}]")
                for sk, sv in scalars.items():
                    lines.append(f"{_toml_key(sk)} = {_dump_toml_val(sv)}")
            for sub_k, sub_v in nested.items():
                lines.append(f"\n[{_toml_key(k)}.{_toml_key(sub_k)}]")
                for sk, sv in sub_v.items():
                    lines.append(f"{_toml_key(sk)} = {_dump_toml_val(sv)}")
    return "\n".join(lines).strip() + "\n"


def _server_to_codex_shape(server: MCPServerConfig) -> dict:
    if server.command:
        entry: dict = {"command": server.command, "args": list(server.args)}
        if server.env:
            entry["env"] = dict(server.env)
        return entry
    entry = {"url": server.url}
    if server.transport != "stdio":
        entry["transport"] = server.transport
    if server.headers:
        entry["headers"] = dict(server.headers)
    return entry


def sync_codex(servers: list[MCPServerConfig]) -> list[SyncResult]:
    CODEX_MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if CODEX_MCP_CONFIG_PATH.exists():
        try:
            existing = tomllib.loads(CODEX_MCP_CONFIG_PATH.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            return [SyncResult("*", False, f"{CODEX_MCP_CONFIG_PATH} is not valid TOML: {exc}")]

    mcp_servers = existing.setdefault("mcp_servers", {})
    if not isinstance(mcp_servers, dict):
        mcp_servers = {}
        existing["mcp_servers"] = mcp_servers

    results = []
    newly_added: list[str] = []
    for server in servers:
        shape = _server_to_codex_shape(server)
        if server.name in mcp_servers and mcp_servers[server.name] == shape:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        mcp_servers[server.name] = shape
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {CODEX_MCP_CONFIG_PATH}"))

    if newly_added:
        CODEX_MCP_CONFIG_PATH.write_text(_dumps_toml(existing), encoding="utf-8")
    return results


# ---------- copilot: persistent, via ~/.copilot/mcp-config.json merge ----------


def _server_to_copilot_shape(server: MCPServerConfig) -> dict:
    if server.command:
        entry: dict = {
            "type": "local",
            "command": server.command,
            "args": list(server.args),
            "tools": ["*"],
        }
        if server.env:
            entry["env"] = dict(server.env)
        return entry
    entry = {
        "type": "http" if server.transport in ("http", "sse") else server.transport,
        "url": server.url,
        "tools": ["*"],
    }
    if server.headers:
        entry["headers"] = dict(server.headers)
    return entry


def sync_copilot(servers: list[MCPServerConfig]) -> list[SyncResult]:
    COPILOT_MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing_root: dict = {}
    existing: dict = {}
    if COPILOT_MCP_CONFIG_PATH.exists():
        try:
            existing_root = json.loads(COPILOT_MCP_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(existing_root, dict):
                existing = existing_root.get("mcpServers", {})
                if not isinstance(existing, dict):
                    existing = {}
        except (json.JSONDecodeError, OSError) as exc:
            return [SyncResult("*", False, f"{COPILOT_MCP_CONFIG_PATH} is not valid JSON: {exc}")]

    results = []
    newly_added: list[str] = []
    for server in servers:
        shape = _server_to_copilot_shape(server)
        if server.name in existing and existing[server.name] == shape:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        existing[server.name] = shape
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {COPILOT_MCP_CONFIG_PATH}"))

    if newly_added:
        existing_root["mcpServers"] = existing
        COPILOT_MCP_CONFIG_PATH.write_text(json.dumps(existing_root, indent=2), encoding="utf-8")
    return results


# ---------- opencode: persistent, via ~/.config/opencode/opencode.json merge ----------


def _server_to_opencode_shape(server: MCPServerConfig) -> dict:
    if server.command:
        entry: dict = {
            "type": "local",
            "command": [server.command, *server.args],
            "enabled": True,
        }
        if server.env:
            entry["environment"] = dict(server.env)
        return entry
    entry = {
        "type": "remote",
        "url": server.url,
        "enabled": True,
    }
    if server.headers:
        entry["headers"] = dict(server.headers)
    return entry


def sync_opencode(servers: list[MCPServerConfig]) -> list[SyncResult]:
    OPENCODE_MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing_root: dict = {}
    existing: dict = {}
    if OPENCODE_MCP_CONFIG_PATH.exists():
        try:
            existing_root = json.loads(OPENCODE_MCP_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(existing_root, dict):
                existing = existing_root.get("mcp", {})
                if not isinstance(existing, dict):
                    existing = {}
        except (json.JSONDecodeError, OSError) as exc:
            return [SyncResult("*", False, f"{OPENCODE_MCP_CONFIG_PATH} is not valid JSON: {exc}")]

    results = []
    newly_added: list[str] = []
    for server in servers:
        shape = _server_to_opencode_shape(server)
        if server.name in existing and existing[server.name] == shape:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        existing[server.name] = shape
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {OPENCODE_MCP_CONFIG_PATH}"))

    if newly_added:
        existing_root["mcp"] = existing
        OPENCODE_MCP_CONFIG_PATH.write_text(json.dumps(existing_root, indent=2), encoding="utf-8")
    return results


# ---------- droid: persistent, via ~/.factory/mcp.json merge ----------


def sync_droid(servers: list[MCPServerConfig]) -> list[SyncResult]:
    DROID_MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing_root: dict = {}
    existing: dict = {}
    if DROID_MCP_CONFIG_PATH.exists():
        try:
            existing_root = json.loads(DROID_MCP_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(existing_root, dict):
                existing = existing_root.get("mcpServers", {})
                if not isinstance(existing, dict):
                    existing = {}
        except (json.JSONDecodeError, OSError) as exc:
            return [SyncResult("*", False, f"{DROID_MCP_CONFIG_PATH} is not valid JSON: {exc}")]

    results = []
    newly_added: list[str] = []
    for server in servers:
        shape = _server_to_standard_shape(server)
        if server.name in existing and existing[server.name] == shape:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        existing[server.name] = shape
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {DROID_MCP_CONFIG_PATH}"))

    if newly_added:
        existing_root["mcpServers"] = existing
        DROID_MCP_CONFIG_PATH.write_text(json.dumps(existing_root, indent=2), encoding="utf-8")
    return results


# ---------- devin: persistent, via mcp_config.json merge ----------


def sync_devin(servers: list[MCPServerConfig]) -> list[SyncResult]:
    DEVIN_MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing_root: dict = {}
    existing: dict = {}
    if DEVIN_MCP_CONFIG_PATH.exists():
        try:
            existing_root = json.loads(DEVIN_MCP_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(existing_root, dict):
                existing = existing_root.get("mcpServers", {})
                if not isinstance(existing, dict):
                    existing = {}
        except (json.JSONDecodeError, OSError) as exc:
            return [SyncResult("*", False, f"{DEVIN_MCP_CONFIG_PATH} is not valid JSON: {exc}")]

    results = []
    newly_added: list[str] = []
    for server in servers:
        shape = _server_to_standard_shape(server)
        if server.name in existing and existing[server.name] == shape:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        existing[server.name] = shape
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {DEVIN_MCP_CONFIG_PATH}"))

    if newly_added:
        existing_root["mcpServers"] = existing
        DEVIN_MCP_CONFIG_PATH.write_text(json.dumps(existing_root, indent=2), encoding="utf-8")
    return results


def sync(agent_id: str, servers: list[MCPServerConfig]) -> list[SyncResult]:
    if agent_id == "gemini":
        return sync_gemini(servers)
    if agent_id == "agent":
        return sync_cursor(servers)
    if agent_id == "codex":
        return sync_codex(servers)
    if agent_id == "copilot":
        return sync_copilot(servers)
    if agent_id == "opencode":
        return sync_opencode(servers)
    if agent_id == "droid":
        return sync_droid(servers)
    if agent_id == "devin":
        return sync_devin(servers)
    raise ValueError(
        f"secfoo mcp sync isn't supported for {agent_id!r}.\n\n"
        f"Agent MCP support matrix (from docs/REFERENCE.md):\n\n"
        f"{format_mcp_support_table()}"
    )
