"""secfoo-memory client: key storage, the default MCP server, opt-outs,
the account endpoints, and how a run picks all of it up."""

from __future__ import annotations

import json
import stat
import urllib.error
from io import BytesIO

import pytest

from secfoo import mcp, memory
from secfoo.agents.base import AgentAdapter, AgentResult
from secfoo.agents.claude import ClaudeAdapter
from secfoo.runner import execute_runs
from secfoo.settings import MCPServerConfig
from secfoo.skills.loader import load_skill
from secfoo.skills.renderer import TargetContext, render_prompt
from secfoo.stack import Stack
from secfoo.storage.repository import RunRepository


@pytest.fixture
def user_config(tmp_path, monkeypatch):
    """Points config.toml at a temp file; returns a writer for it."""
    path = tmp_path / "config.toml"
    monkeypatch.setattr("secfoo.settings.CONFIG_PATH", path)

    def _write(text: str) -> None:
        path.write_text(text, encoding="utf-8")

    return _write


@pytest.fixture
def memory_key():
    memory.save_memory_config(memory.MemoryConfig(api_key="sfm_free_test", url="https://mem.example"))


# ---------- config file ----------


def test_save_and_load_round_trip_with_private_permissions(tmp_path):
    path = tmp_path / "m.toml"
    memory.save_memory_config(memory.MemoryConfig(api_key='k"ey', url="https://x"), path)
    assert memory.load_memory_config(path) == memory.MemoryConfig(api_key='k"ey', url="https://x")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_load_returns_none_without_a_file_and_rejects_a_keyless_one(tmp_path):
    assert memory.load_memory_config(tmp_path / "missing.toml") is None
    bad = tmp_path / "bad.toml"
    bad.write_text('url = "https://x"\n', encoding="utf-8")
    with pytest.raises(memory.MemoryServiceError, match="missing api_key"):
        memory.load_memory_config(bad)


def test_newlines_are_refused_rather_than_written_into_toml(tmp_path):
    with pytest.raises(memory.MemoryServiceError):
        memory.save_memory_config(memory.MemoryConfig(api_key="a\nb"), tmp_path / "m.toml")


# ---------- default MCP server + opt-outs ----------


def test_no_key_means_no_server(user_config):
    assert memory.memory_server() is None
    assert mcp.effective_servers([]) == []


def test_key_gives_an_http_server_with_a_bearer_header(user_config, memory_key):
    server = memory.memory_server()
    assert server == MCPServerConfig(
        name="secfoo-memory",
        url="https://mem.example/mcp",
        transport="http",
        headers={"Authorization": "Bearer sfm_free_test"},
    )


def test_env_and_config_opt_outs(user_config, memory_key, monkeypatch):
    monkeypatch.setenv("SECFOO_MEMORY", "off")
    assert memory.memory_server() is None
    monkeypatch.delenv("SECFOO_MEMORY")
    user_config("[memory]\nenabled = false\n")
    assert memory.memory_server() is None
    user_config("[memory]\nenabled = true\n")
    assert memory.memory_server() is not None


def test_a_broken_config_toml_keeps_memory_off(user_config, memory_key):
    user_config("[memory]\nenabled = 'yes'\n")
    assert memory.memory_server() is None


def test_effective_servers_appends_default_but_user_entry_with_same_name_wins(user_config, memory_key):
    other = MCPServerConfig(name="other", command="x")
    assert [s.name for s in mcp.effective_servers([other])] == ["other", "secfoo-memory"]
    self_hosted = MCPServerConfig(name="secfoo-memory", url="https://memory.internal/mcp", transport="http")
    assert mcp.effective_servers([self_hosted]) == [self_hosted]


def test_capable_agents(user_config, memory_key):
    assert memory.is_active_for_agent("claude")
    assert memory.is_active_for_agent("gemini")
    assert not memory.is_active_for_agent("api")
    assert not memory.is_active_for_agent("agy")


def test_claude_command_includes_memory_server_and_writes_a_private_config(
    user_config, memory_key, tmp_path, monkeypatch
):
    config_path = tmp_path / "claude-mcp-config.json"
    monkeypatch.setattr(mcp, "STORE_DIR", tmp_path)
    monkeypatch.setattr(mcp, "CLAUDE_MCP_CONFIG_PATH", config_path)

    cmd = ClaudeAdapter().build_command("p", workdir=tmp_path)

    allowed = cmd[cmd.index("--allowedTools") + 1]
    assert "mcp__secfoo-memory" in allowed
    assert cmd[cmd.index("--mcp-config") + 1] == str(config_path)
    payload = json.loads(config_path.read_text())
    assert payload["mcpServers"]["secfoo-memory"]["headers"] == {"Authorization": "Bearer sfm_free_test"}
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


# ---------- prompt guidance ----------


def _render(memory_enabled: bool, stack: Stack | None = None, depth: str = "quick") -> str:
    target = TargetContext(kind="local", local_path=__import__("pathlib").Path("/tmp/t"), display_source="/tmp/t")
    return render_prompt(load_skill("sast"), target, depth=depth, memory_enabled=memory_enabled, stack=stack)


def test_memory_guidance_only_when_enabled():
    assert "secfoo-memory" not in _render(False)
    prompt = _render(True, Stack(languages=["python", "javascript"], frameworks={"python": ["django"]}))
    assert "## Pattern memory (secfoo-memory tools)" in prompt
    assert "Never send code" in prompt
    assert "- language `python`, framework one of: `django`" in prompt
    assert "- language `javascript`, framework `none`" in prompt
    assert "about 5 calls" in prompt
    # Guidance sits before the output contract, which must stay last.
    assert prompt.index("Pattern memory") < prompt.index("## Required output format")


def test_memory_guidance_budget_and_unknown_stack():
    prompt = _render(True, None, depth="standard")
    assert "about 10 calls" in prompt
    assert "Detected stack: not determined" in prompt


def test_contracts_ask_for_a_code_free_construct_regardless_of_memory():
    assert "- **Construct:**" in _render(False)
    target = TargetContext(kind="local", local_path=__import__("pathlib").Path("/tmp/t"), display_source="/tmp/t")
    for skill_id in ("sca-reachability", "secret-scanning"):
        assert "- **Construct:**" in render_prompt(load_skill(skill_id), target)


# ---------- runner integration ----------


class _CapturingAdapter(AgentAdapter):
    name = "fake"
    binary = "fake-binary"
    default_timeout_seconds = 30
    prompts: list[str] = []

    def build_command(self, prompt, *, workdir):
        return ["fake-binary"]

    def is_available(self) -> bool:
        return True

    def run(self, prompt, *, workdir, timeout=None):
        _CapturingAdapter.prompts.append(prompt)
        return AgentResult(
            agent=self.name, exit_code=0, stdout="ok", stderr="", duration_seconds=0.1,
            timed_out=False, status="success", raw_report=SECRET_REPORT,
        )


SECRET_REPORT = """\
# Secret Scanning Report

## 3. Findings Register
| ID | Secret type | Location | Source | Validity | Severity |
|----|-------------|----------|--------|----------|----------|
| S1 | API token | `settings.py:2` | code | Looks live | High |

## 4. Detailed Findings

### [HIGH] S1: API token in settings.py
- **Evidence:** TOKENJ4F...
- **Construct:** third-party API token assigned to a module-level constant in the settings module
- **Remediation:** Rotate it.
"""


def _patch(monkeypatch, tmp_path):
    _CapturingAdapter.prompts = []
    monkeypatch.setattr("secfoo.runner.run_dir", lambda run_uuid: tmp_path / "reports" / run_uuid)
    monkeypatch.setattr("secfoo.runner.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.runner.get_adapter", lambda agent_id: _CapturingAdapter())
    monkeypatch.setattr("secfoo.runner._try_cloud_sync", lambda repo, run_uuid: None)


def _target(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "settings.py").write_text("import os\nTOKEN = 'x'\n", encoding="utf-8")
    (target / "requirements.txt").write_text("flask\n", encoding="utf-8")
    return target


def test_run_with_memory_on_records_flag_prompt_and_stack(user_config, memory_key, tmp_path, monkeypatch):
    _patch(monkeypatch, tmp_path)
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    outcomes = execute_runs(
        skill_ids=["secret-scanning"], target=str(_target(tmp_path)), confluence_urls=[], agent_id="claude", repo=repo
    )
    run = repo.get_run(outcomes[0].run_uuid)
    findings = repo.list_secret_findings(status="open")
    repo.close()

    assert run.memory_enabled == 1
    assert "Pattern memory" in _CapturingAdapter.prompts[0]
    assert "- language `python`, framework one of: `flask`" in _CapturingAdapter.prompts[0]
    assert len(findings) == 1
    assert findings[0].language == "python"
    assert findings[0].framework == "flask"
    assert findings[0].construct.startswith("third-party API token")
    assert findings[0].code_region_hash is not None


def test_run_with_no_memory_env_or_incapable_agent_stays_off(user_config, memory_key, tmp_path, monkeypatch):
    _patch(monkeypatch, tmp_path)
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    target = str(_target(tmp_path))

    memory.disable_for_this_process()  # what `secfoo run --no-memory` does
    disabled = execute_runs(skill_ids=["sast"], target=target, confluence_urls=[], agent_id="claude", repo=repo)
    monkeypatch.delenv("SECFOO_MEMORY")
    no_tool_loop = execute_runs(skill_ids=["sast"], target=target, confluence_urls=[], agent_id="api", repo=repo)

    assert repo.get_run(disabled[0].run_uuid).memory_enabled == 0
    assert repo.get_run(no_tool_loop[0].run_uuid).memory_enabled == 0
    repo.close()
    assert all("Pattern memory" not in prompt for prompt in _CapturingAdapter.prompts)


# ---------- account endpoints ----------


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_signup_verify_and_whoami_hit_the_right_endpoints(monkeypatch):
    calls = []

    def _fake(request, timeout=None):
        calls.append((request.full_url, request.data, request.headers.get("Authorization")))
        if request.full_url.endswith("/verify"):
            return _FakeResponse({"api_key": "sfm_free_new"})
        if request.full_url.endswith("/whoami"):
            return _FakeResponse({"plan": "free", "daily_quota": 200, "used_today": 3})
        return _FakeResponse({"status": "code_sent"})

    monkeypatch.setattr("secfoo.memory.urllib.request.urlopen", _fake)
    memory.request_signup("a@b.co", url="https://m.example/")
    key = memory.verify_signup("a@b.co", "123456", url="https://m.example")
    info = memory.whoami(memory.MemoryConfig(api_key=key, url="https://m.example"))

    assert key == "sfm_free_new"
    assert info["plan"] == "free"
    assert calls[0][0] == "https://m.example/v1/signup"
    assert json.loads(calls[1][1]) == {"email": "a@b.co", "code": "123456"}
    assert calls[2][2] == "Bearer sfm_free_new"


def test_http_errors_surface_the_service_detail(monkeypatch):
    def _fake(request, timeout=None):
        raise urllib.error.HTTPError(
            request.full_url, 429, "Too Many", {}, BytesIO(b'{"detail": "daily quota exhausted"}')
        )

    monkeypatch.setattr("secfoo.memory.urllib.request.urlopen", _fake)
    with pytest.raises(memory.MemoryServiceError, match="429: daily quota exhausted"):
        memory.whoami(memory.MemoryConfig(api_key="k"))


def test_verify_without_a_key_in_the_response_is_an_error(monkeypatch):
    monkeypatch.setattr("secfoo.memory.urllib.request.urlopen", lambda request, timeout=None: _FakeResponse({}))
    with pytest.raises(memory.MemoryServiceError, match="did not return an API key"):
        memory.verify_signup("a@b.co", "1")
