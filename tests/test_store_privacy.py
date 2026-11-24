"""The local store and secret-bearing files are owner-only; the default config runs nothing."""
from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from secfoo import cloud, config, mcp, memory
from secfoo.settings import MCPServerConfig

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10
    import tomli as tomllib

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def store(tmp_path, monkeypatch):
    root = tmp_path / "store"
    monkeypatch.setattr(config, "STORE_DIR", root)
    monkeypatch.setattr(config, "REPORTS_DIR", root / "reports")
    monkeypatch.setattr(config, "TMP_DIR", root / "tmp")
    monkeypatch.setattr(config, "ATTACHMENTS_DIR", root / "attachments")
    return root


@posix_only
def test_a_new_store_is_owner_only(store):
    config.ensure_store_dirs()
    assert _mode(store) == 0o700


@posix_only
def test_an_existing_world_readable_store_is_tightened(store):
    """Stores created by earlier versions were 0755: reports (scanned source,
    findings) readable by every local user."""
    store.mkdir(mode=0o755)
    store.chmod(0o755)
    config.ensure_store_dirs()
    assert _mode(store) == 0o700


@posix_only
def test_write_private_text_creates_0600_and_tightens_an_existing_file(tmp_path):
    fresh = tmp_path / "a" / "fresh.toml"
    config.write_private_text(fresh, "k = 1\n")
    assert _mode(fresh) == 0o600 and fresh.read_text() == "k = 1\n"
    old = tmp_path / "old.toml"
    old.write_text("api_key = 'previous'\nextra = 'longer content that must be truncated'\n")
    old.chmod(0o644)
    config.write_private_text(old, "api_key = 'new'\n")
    assert _mode(old) == 0o600 and old.read_text() == "api_key = 'new'\n"


def test_write_private_text_atomic_no_temp_residue(tmp_path):
    dest = tmp_path / "secret.toml"
    config.write_private_text(dest, "hello = 'world'\n")
    assert dest.read_text() == "hello = 'world'\n"
    # Ensure no lingering .tmp files exist in dest.parent
    tmp_files = list(tmp_path.glob(".*tmp*"))
    assert tmp_files == []


@posix_only
def test_write_private_text_preserves_symlink(tmp_path):
    target = tmp_path / "dotfiles" / "config.toml"
    target.parent.mkdir(parents=True)
    target.write_text("initial = true\n")
    target.chmod(0o644)

    symlink_path = tmp_path / "agent" / "config.toml"
    symlink_path.parent.mkdir(parents=True)
    symlink_path.symlink_to(target)

    config.write_private_text(symlink_path, "updated = true\n")

    assert symlink_path.is_symlink()
    assert symlink_path.resolve() == target.resolve()
    assert target.read_text() == "updated = true\n"
    assert _mode(target) == 0o600


@posix_only
def test_credential_files_are_0600_even_when_a_readable_one_existed(tmp_path, monkeypatch):
    cloud_path, memory_path = tmp_path / "cloud.toml", tmp_path / "memory.toml"
    for path in (cloud_path, memory_path):
        path.write_text("stale\n")
        path.chmod(0o644)
    cloud.save_cloud_config(cloud.CloudConfig(api_key="sfc_ingest_" + "a" * 40), cloud_path)
    memory.save_memory_config(memory.MemoryConfig(api_key="mem-key"), memory_path)
    assert _mode(cloud_path) == 0o600 and _mode(memory_path) == 0o600
    assert "stale" not in cloud_path.read_text() + memory_path.read_text()

    monkeypatch.setattr(mcp, "STORE_DIR", tmp_path)
    monkeypatch.setattr(mcp, "CLAUDE_MCP_CONFIG_PATH", tmp_path / "claude-mcp-config.json")
    written = mcp.write_claude_mcp_config(
        [MCPServerConfig(name="x", url="https://mcp.example.com", transport="http", headers={"Authorization": "Bearer s"})])
    assert _mode(written) == 0o600


def test_default_config_template_enables_no_mcp_server():
    """`secfoo config init` used to write an active Atlassian entry, so every
    claude run started `npx -y mcp-remote@latest` (an unpinned download) and
    an OAuth flow, whether or not the user uses Atlassian."""
    template = Path(config.__file__).with_name("config.example.toml").read_text(encoding="utf-8")
    assert "mcp_servers" not in tomllib.loads(template)
    assert "# [[mcp_servers]]\n# name = \"Atlassian-Rovo-MCP\"" in template  # still documented
