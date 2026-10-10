"""Client side of secfoo-memory: the hosted service an agent can query
for known vulnerability patterns (`lookup_patterns`), remediation
guidance (`get_remediation`) and known false-positive shapes
(`check_false_positive`) while it runs an assessment.

This module never talks to those tools itself -- the agent does, over
MCP. secfoo's only jobs here are:

- holding the user's own memory API key (~/.secfoo/memory.toml, written
  by `secfoo memory signup/login`, chmod 0600),
- registering the service as a default MCP server (`memory_server()`,
  merged into the configured servers by mcp.effective_servers), and
- telling the prompt renderer whether to include the memory guidance.

What the agent sends is a short, code-free description of a construct
plus language/framework/CWE -- never source code. The service rejects
anything that looks like code, so that promise is enforced server-side,
not just requested in the prompt.

Opting out: `[memory] enabled = false` in config.toml, `secfoo run
--no-memory`, or SECFOO_MEMORY=off in the environment.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from secfoo.config import STORE_DIR
from secfoo.settings import MCPServerConfig

# A dedicated file, same rationale as cloud.toml (see config.py): fully
# owned by `secfoo memory`, safe to overwrite wholesale, holds a secret.
MEMORY_CONFIG_PATH = STORE_DIR / "memory.toml"
DEFAULT_MEMORY_URL = "https://memory.secfoo.com"
MCP_ENDPOINT = "/mcp"
SERVER_NAME = "secfoo-memory"
REQUEST_TIMEOUT_SECONDS = 15
ENV_TOGGLE = "SECFOO_MEMORY"

# Agents whose CLI can actually reach an MCP server secfoo registers:
# claude via --mcp-config on every run, gemini/agent (Cursor) after a one-
# time `secfoo mcp sync`. The api agent has no tool loop at all, and agy /
# codex / copilot aren't wired up for MCP here -- prompting those to "call
# the memory tools" would only produce a Coverage Notes complaint.
MEMORY_CAPABLE_AGENTS = frozenset({"claude", "gemini", "agent"})

_OFF_VALUES = {"0", "off", "false", "no", "disabled"}


class MemoryServiceError(RuntimeError):
    pass


@dataclass(frozen=True)
class MemoryConfig:
    api_key: str
    url: str = DEFAULT_MEMORY_URL


def _toml_escape(value: str) -> str:
    if "\n" in value or "\r" in value:
        raise MemoryServiceError("memory config values must not contain newlines")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def load_memory_config(path: Path | None = None) -> MemoryConfig | None:
    """None when no memory key is configured -- memory is optional."""
    path = path or MEMORY_CONFIG_PATH
    if not path.exists():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise MemoryServiceError(f"{path}: invalid TOML: {exc}") from exc
    api_key = data.get("api_key")
    if not api_key:
        raise MemoryServiceError(f"{path}: missing api_key")
    return MemoryConfig(api_key=api_key, url=data.get("url") or DEFAULT_MEMORY_URL)


def save_memory_config(config: MemoryConfig, path: Path | None = None) -> None:
    path = path or MEMORY_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'api_key = "{_toml_escape(config.api_key)}"\nurl = "{_toml_escape(config.url)}"\n',
        encoding="utf-8",
    )
    path.chmod(0o600)


def delete_memory_config(path: Path | None = None) -> None:
    (path or MEMORY_CONFIG_PATH).unlink(missing_ok=True)


def disabled_by_env() -> bool:
    return os.environ.get(ENV_TOGGLE, "").strip().lower() in _OFF_VALUES


def disable_for_this_process() -> None:
    """What `secfoo run --no-memory` does: an env var rather than a flag
    threaded through every layer, because the adapters build their MCP
    config deep inside AgentAdapter.run on worker threads -- this way the
    prompt renderer and every adapter see the same decision."""
    os.environ[ENV_TOGGLE] = "off"


def _enabled_in_config() -> bool:
    from secfoo.settings import ConfigError, load_config

    try:
        return load_config().memory_enabled
    except ConfigError:
        # A broken config.toml surfaces through every other command that
        # reads it; memory just stays off rather than failing a run here.
        return False


def memory_server(config: MemoryConfig | None = None) -> MCPServerConfig | None:
    """The secfoo-memory MCP server entry, or None when memory is off: no
    key configured, disabled in config.toml, or SECFOO_MEMORY=off."""
    if disabled_by_env():
        return None
    try:
        config = config or load_memory_config()
    except MemoryServiceError:
        return None
    if config is None or not _enabled_in_config():
        return None
    return MCPServerConfig(
        name=SERVER_NAME,
        url=config.url.rstrip("/") + MCP_ENDPOINT,
        transport="http",
        headers={"Authorization": f"Bearer {config.api_key}"},
    )


def is_active_for_agent(agent_id: str) -> bool:
    return agent_id in MEMORY_CAPABLE_AGENTS and memory_server() is not None


# ---------- account endpoints (signup / whoami), plain HTTPS JSON ----------


def _request(url: str, *, payload: dict | None = None, api_key: str | None = None) -> dict:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310  # nosec B310 -- user-configured memory URL, same trust as MCP settings
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail).get("detail", detail)
        except (json.JSONDecodeError, AttributeError):
            pass
        raise MemoryServiceError(f"secfoo-memory returned {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise MemoryServiceError(f"Could not reach secfoo-memory: {exc.reason}") from exc


def request_signup(email: str, *, url: str = DEFAULT_MEMORY_URL) -> dict:
    """Asks the service to email a one-time verification code to `email`."""
    return _request(f"{url.rstrip('/')}/v1/signup", payload={"email": email})


def verify_signup(email: str, code: str, *, url: str = DEFAULT_MEMORY_URL) -> str:
    """Exchanges the emailed code for a free-tier API key."""
    response = _request(f"{url.rstrip('/')}/v1/signup/verify", payload={"email": email, "code": code})
    api_key = response.get("api_key")
    if not api_key:
        raise MemoryServiceError("secfoo-memory did not return an API key")
    return api_key


def whoami(config: MemoryConfig) -> dict:
    """{"plan": ..., "daily_quota": ..., "used_today": ...} for this key."""
    return _request(f"{config.url.rstrip('/')}/v1/whoami", api_key=config.api_key)
