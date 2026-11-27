"""MCP client for the `api` agent (#123).

The CLI adapters hand MCP servers to the agent's own CLI. The `api` agent
has no CLI, so it connects to the servers itself, using the official `mcp`
SDK, and offers their tools to the model as LiteLLM function tools.

Read-only by construction: a tool is offered to the model only when the
server annotates it `readOnlyHint: true`, or when the server's
`[[mcp_servers]]` entry lists it by name in `tools = [...]` (an explicit
allowlist, which then replaces the annotation check for that server).
Anything else is never sent to the model, so it cannot be called.

The SDK is async, while the LangGraph graph runs synchronously. One worker
thread owns an event loop and a single task that opens every session, serves
tool calls from a queue, and closes the sessions again -- the SDK's
transports are anyio task groups, which must be entered and left by the same
task.
"""

from __future__ import annotations

import asyncio
import builtins
import concurrent.futures
import json
import re
import threading
from contextlib import AsyncExitStack
from dataclasses import dataclass

from secfoo.settings import MCPServerConfig

CONNECT_TIMEOUT_SECONDS = 60
CALL_TIMEOUT_SECONDS = 60
MAX_DESCRIPTION_CHARS = 1024
_NAME_RE = re.compile(r"[^A-Za-z0-9_-]")
_MAX_NAME = 64  # OpenAI's limit for a function name


def _worker_stop_errors() -> tuple[type[BaseException], ...]:
    """What can end the worker thread's event loop without ending the run.

    Besides ordinary exceptions, the SDK's anyio transports can surface a
    cancellation, or a BaseExceptionGroup wrapping one, out of asyncio.run().
    KeyboardInterrupt and SystemExit are deliberately not listed.
    """
    errors: list[type[BaseException]] = [Exception, asyncio.CancelledError]
    group = getattr(builtins, "BaseExceptionGroup", None)  # Python 3.11+
    if group is None:
        try:  # Python 3.10: anyio depends on the backport
            from exceptiongroup import BaseExceptionGroup as group
        except ImportError:
            group = None
    if group is not None:
        errors.append(group)
    return tuple(errors)


_WORKER_STOP_ERRORS = _worker_stop_errors()


@dataclass(frozen=True)
class ExposedTool:
    name: str  # what the model calls: "<server>__<tool>", sanitised
    server: str
    tool: str
    spec: dict  # LiteLLM / OpenAI function-tool definition


def is_exposed(tool, server: MCPServerConfig) -> bool:
    """Whether `tool` (an mcp.types.Tool) may be offered to the model."""
    if server.tools:
        return tool.name in server.tools
    annotations = getattr(tool, "annotations", None)
    return getattr(annotations, "readOnlyHint", None) is True


def exposed_name(server: str, tool: str, taken: set[str] | dict) -> str:
    base = _NAME_RE.sub("_", f"{server}__{tool}")[:_MAX_NAME]
    name, n = base, 2
    while name in taken:
        suffix = f"_{n}"
        name = base[: _MAX_NAME - len(suffix)] + suffix
        n += 1
    return name


def tool_spec(name: str, tool, server: str) -> dict:
    schema = getattr(tool, "inputSchema", None)
    if not isinstance(schema, dict) or schema.get("type") != "object":
        schema = {"type": "object", "properties": {}}
    description = f"[{server}] {(getattr(tool, 'description', None) or '').strip()}".strip()
    return {
        "type": "function",
        "function": {"name": name, "description": description[:MAX_DESCRIPTION_CHARS], "parameters": schema},
    }


def result_text(result) -> str:
    """The text of an mcp.types.CallToolResult. Non-text content (images,
    binary resources) is replaced by a marker rather than sent on."""
    parts: list[str] = []
    for item in getattr(result, "content", None) or []:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            parts.append(text)
            continue
        resource_text = getattr(getattr(item, "resource", None), "text", None)
        if isinstance(resource_text, str):
            parts.append(resource_text)
            continue
        parts.append(f"[{getattr(item, 'type', 'non-text')} content omitted]")
    structured = getattr(result, "structuredContent", None)
    if not parts and structured is not None:
        parts.append(json.dumps(structured, ensure_ascii=False, default=str))
    text = "\n".join(parts)
    if getattr(result, "isError", False):
        return "The tool reported an error: " + text
    return text


def _describe(exc: BaseException) -> str:
    # anyio wraps transport failures in an ExceptionGroup; name the cause.
    inner = getattr(exc, "exceptions", None)
    if inner:
        return _describe(inner[0])
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


async def _connect(stack: AsyncExitStack, server: MCPServerConfig, timeout: float):
    from datetime import timedelta

    from mcp import ClientSession

    headers = dict(server.headers) or None
    if server.command:
        from mcp import StdioServerParameters
        from mcp.client.stdio import get_default_environment, stdio_client

        env = {**get_default_environment(), **server.env} if server.env else None
        params = StdioServerParameters(command=server.command, args=list(server.args), env=env)
        read, write = await stack.enter_async_context(stdio_client(params))
    elif server.transport == "sse":
        from mcp.client.sse import sse_client

        read, write = await stack.enter_async_context(sse_client(server.url, headers=headers))
    else:
        from mcp.client.streamable_http import streamablehttp_client

        read, write, _ = await stack.enter_async_context(streamablehttp_client(server.url, headers=headers))
    # The session's read timeout bounds initialize, list_tools and every
    # call_tool: a server that stops answering can't hang the run.
    session = await stack.enter_async_context(
        ClientSession(read, write, read_timeout_seconds=timedelta(seconds=timeout))
    )
    await session.initialize()
    return session


async def _list_tools(session) -> list:
    tools: list = []
    cursor = None
    for _ in range(50):  # pagination, bounded
        result = await (session.list_tools(cursor=cursor) if cursor else session.list_tools())
        tools.extend(result.tools)
        cursor = getattr(result, "nextCursor", None)
        if not cursor:
            break
    return tools


async def _close_quietly(stack: AsyncExitStack) -> None:
    try:
        await stack.aclose()
    except Exception:  # noqa: BLE001 -- a server that dies on shutdown must not fail the run
        pass


class McpToolbox:
    """Connects to `servers`, keeps the read-only tools, and runs calls.

    Use as a context manager. A server that can't be reached is skipped and
    named in `errors`; the run goes on with the others.
    """

    def __init__(
        self,
        servers: list[MCPServerConfig],
        *,
        connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
        call_timeout: float = CALL_TIMEOUT_SECONDS,
    ) -> None:
        self._servers = list(servers)
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout
        self.tools: dict[str, ExposedTool] = {}
        self.hidden: list[str] = []  # "server/tool" not offered (not read-only)
        self.errors: list[str] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.Queue | None = None
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def specs(self) -> list[dict]:
        return [tool.spec for tool in self.tools.values()]

    def __enter__(self) -> McpToolbox:
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def start(self) -> None:
        import mcp  # noqa: F401 -- ImportError here, in the caller's thread

        self._thread = threading.Thread(target=self._thread_main, name="secfoo-mcp", daemon=True)
        self._thread.start()
        limit = self._connect_timeout * max(1, len(self._servers)) + 10
        if not self._ready.wait(limit):
            self.errors.append(f"MCP servers did not start within {limit:.0f}s")

    def call(self, name: str, arguments: dict) -> str:
        tool = self.tools[name]
        if self._loop is None or self._queue is None or self._thread is None or not self._thread.is_alive():
            raise RuntimeError("the MCP client is not running")
        future: concurrent.futures.Future = concurrent.futures.Future()
        self._loop.call_soon_threadsafe(self._queue.put_nowait, (future, tool.server, tool.tool, arguments))
        return future.result(timeout=self._call_timeout + 5)

    def close(self) -> None:
        thread = self._thread
        if thread is None or not thread.is_alive() or self._loop is None or self._queue is None:
            return
        try:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
        except RuntimeError:
            return  # loop already closed
        thread.join(timeout=15)

    # ---------- worker thread ----------

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._main())
        except _WORKER_STOP_ERRORS as exc:  # a transport crash ends tool use, not the run
            self.errors.append(f"MCP client stopped: {_describe(exc)}")
        finally:
            self._ready.set()

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue()
        sessions: dict = {}
        tools: dict[str, ExposedTool] = {}
        async with AsyncExitStack() as stack:
            for server in self._servers:
                server_stack = AsyncExitStack()
                try:
                    session = await _connect(server_stack, server, self._connect_timeout)
                    listed = await _list_tools(session)
                except Exception as exc:  # noqa: BLE001 -- skip this server, keep the others
                    await _close_quietly(server_stack)
                    self.errors.append(f"{server.name}: could not connect ({_describe(exc)})")
                    continue
                stack.push_async_callback(_close_quietly, server_stack)
                sessions[server.name] = session
                for tool in listed:
                    if not is_exposed(tool, server):
                        self.hidden.append(f"{server.name}/{tool.name}")
                        continue
                    name = exposed_name(server.name, tool.name, tools)
                    tools[name] = ExposedTool(name, server.name, tool.name, tool_spec(name, tool, server.name))
            self.tools = tools
            self._ready.set()
            while True:
                item = await self._queue.get()
                if item is None:
                    break
                future, server_name, tool_name, arguments = item
                if not future.set_running_or_notify_cancel():
                    continue
                try:
                    result = await sessions[server_name].call_tool(tool_name, arguments)
                except Exception as exc:  # noqa: BLE001 -- reported back to the model as the tool result
                    future.set_exception(exc)
                else:
                    future.set_result(result_text(result))
