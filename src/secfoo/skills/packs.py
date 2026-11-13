"""Shared skill packs (#93): a git repo of `*.md` skills, optionally under
a `skills/` subfolder, installed under `~/.secfoo/skills/packs/<name>/` and
pinned in `packs.lock` (url, ref, resolved commit) so `secfoo skills install
--from-lock` reproduces the same set in CI.

`packs.lock` is secfoo's own small TOML file, like `cloud.toml`: only ever
holds plain strings this module writes itself, so a hand-rolled writer is
safe and avoids adding a TOML-writer dependency (same reasoning as
`secfoo.cloud`).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
DEFAULT_TIMEOUT = 600


def packs_dir() -> Path:
    # Imported lazily -- not at module level -- so a test's
    # monkeypatch.setattr("secfoo.config.STORE_DIR", ...) (see
    # tests/conftest.py's _isolated_custom_skills) takes effect on the next
    # call instead of being baked in at first import, same as
    # skills.loader.user_skill_dirs().
    from secfoo.config import STORE_DIR

    return STORE_DIR / "skills" / "packs"


def lock_path() -> Path:
    from secfoo.config import STORE_DIR

    return STORE_DIR / "skills" / "packs.lock"


class PackError(RuntimeError):
    pass


@dataclass(frozen=True)
class Pack:
    name: str
    url: str
    ref: str
    commit: str

    @property
    def path(self) -> Path:
        return packs_dir() / self.name


def default_pack_name(url: str) -> str:
    """`https://github.com/acme/appsec-skills(.git)` -> `acme-appsec-skills`,
    the example name from the issue. Falls back to asking for `--name`
    rather than guessing at something unreadable."""
    trimmed = url.rstrip("/").removesuffix(".git")
    parts = [part for part in re.split(r"[/:]", trimmed) if part]
    tail = parts[-2:] if len(parts) >= 2 else parts
    name = re.sub(r"[^a-z0-9-]+", "-", "-".join(tail).lower()).strip("-")
    name = re.sub(r"-+", "-", name)
    if not name:
        raise PackError(f"{url}: could not derive a pack name from this URL; pass --name")
    return name


def _toml_escape(value: str) -> str:
    if "\n" in value or "\r" in value:
        raise PackError("a pack's url/ref/commit must not contain newlines")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def load_lock(path: Path | None = None) -> dict[str, Pack]:
    path = path or lock_path()
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise PackError(f"{path}: invalid TOML: {exc}") from exc
    packs: dict[str, Pack] = {}
    for entry in data.get("pack", []):
        try:
            pack = Pack(name=entry["name"], url=entry["url"], ref=entry.get("ref") or "HEAD", commit=entry["commit"])
        except KeyError as exc:
            raise PackError(f"{path}: a [[pack]] entry is missing {exc}") from exc
        packs[pack.name] = pack
    return packs


def save_lock(packs: dict[str, Pack], path: Path | None = None) -> None:
    path = path or lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for pack in sorted(packs.values(), key=lambda p: p.name):
        lines.append("[[pack]]")
        lines.append(f'name = "{_toml_escape(pack.name)}"')
        lines.append(f'url = "{_toml_escape(pack.url)}"')
        lines.append(f'ref = "{_toml_escape(pack.ref)}"')
        lines.append(f'commit = "{_toml_escape(pack.commit)}"')
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def installed_packs(path: Path | None = None) -> list[Pack]:
    return sorted(load_lock(path).values(), key=lambda p: p.name)


def _run_git(args: list[str], *, cwd: Path | None = None, timeout: int = DEFAULT_TIMEOUT) -> str:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        raise PackError(f"git {' '.join(args)} timed out after {timeout}s") from None
    except subprocess.CalledProcessError as exc:
        # Do not forward raw git stderr: a remote server or helper can echo
        # back secrets (same precedent as targets/forge.py).
        detail = (exc.stderr or "").strip().splitlines()[-1:] or [""]
        raise PackError(f"git {' '.join(args)} failed: {detail[0][:300]}") from None
    except OSError:
        raise PackError("unable to run git; check that it is installed and on PATH") from None
    return result.stdout.strip()


def install_pack(
    url: str, *, ref: str | None = None, name: str | None = None, timeout: int = DEFAULT_TIMEOUT
) -> Pack:
    """Clone `url` into `~/.secfoo/skills/packs/<name>`, optionally at
    `ref` (a tag, branch or commit), and record it in packs.lock."""
    resolved_name = name or default_pack_name(url)
    if not NAME_RE.match(resolved_name):
        raise PackError(f"{resolved_name!r} must be lowercase kebab-case (e.g. acme-appsec-skills); pass --name")
    packs = load_lock()
    existing = packs.get(resolved_name)
    target = packs_dir() / resolved_name
    if existing is not None or target.exists():
        raise PackError(
            f"a pack named {resolved_name!r} is already installed at {target} "
            f"(run `secfoo skills remove {resolved_name}` first, or pass --name)"
        )
    packs_dir().mkdir(parents=True, exist_ok=True)
    _run_git(["clone", "--quiet", "--", url, str(target)], timeout=timeout)
    try:
        if ref:
            _run_git(["checkout", "--quiet", "--detach", ref], cwd=target, timeout=timeout)
        commit = _run_git(["rev-parse", "HEAD"], cwd=target, timeout=timeout)
    except PackError:
        shutil.rmtree(target, ignore_errors=True)
        raise
    pack = Pack(name=resolved_name, url=url, ref=ref or "HEAD", commit=commit)
    packs[resolved_name] = pack
    save_lock(packs)
    return pack


def update_pack(name: str, *, timeout: int = DEFAULT_TIMEOUT) -> Pack:
    """Fetch and move `name` to the newest commit on its pinned ref."""
    packs = load_lock()
    pack = packs.get(name)
    if pack is None:
        raise PackError(f"no installed pack named {name!r} (see `secfoo skills list`)")
    target = pack.path
    if not target.is_dir():
        raise PackError(f"{target}: missing on disk; reinstall with `secfoo skills install {pack.url} --name {name}`")
    _run_git(["fetch", "--quiet", "--tags", "origin"], cwd=target, timeout=timeout)
    try:
        resolved = _run_git(["rev-parse", f"origin/{pack.ref}"], cwd=target, timeout=timeout)
    except PackError:
        resolved = _run_git(["rev-parse", pack.ref], cwd=target, timeout=timeout)
    _run_git(["checkout", "--quiet", "--detach", resolved], cwd=target, timeout=timeout)
    updated = Pack(name=pack.name, url=pack.url, ref=pack.ref, commit=resolved)
    packs[name] = updated
    save_lock(packs)
    return updated


def update_all_packs(*, timeout: int = DEFAULT_TIMEOUT) -> list[Pack]:
    return [update_pack(name, timeout=timeout) for name in sorted(load_lock())]


def remove_pack(name: str) -> None:
    packs = load_lock()
    pack = packs.pop(name, None)
    if pack is None:
        raise PackError(f"no installed pack named {name!r} (see `secfoo skills list`)")
    shutil.rmtree(pack.path, ignore_errors=True)
    save_lock(packs)


def install_from_lock(*, timeout: int = DEFAULT_TIMEOUT) -> list[Pack]:
    """Reproduce every pack recorded in packs.lock at its pinned commit --
    for CI (`secfoo skills install --from-lock`). A pack whose folder
    already exists is left alone (already reproduced)."""
    packs = load_lock()
    results = []
    for pack in sorted(packs.values(), key=lambda p: p.name):
        target = pack.path
        if not target.exists():
            packs_dir().mkdir(parents=True, exist_ok=True)
            _run_git(["clone", "--quiet", "--", pack.url, str(target)], timeout=timeout)
            _run_git(["checkout", "--quiet", "--detach", pack.commit], cwd=target, timeout=timeout)
        results.append(pack)
    return results


__all__ = [
    "DEFAULT_TIMEOUT", "Pack", "PackError", "default_pack_name", "install_from_lock",
    "install_pack", "installed_packs", "load_lock", "lock_path", "packs_dir", "remove_pack", "save_lock",
    "update_all_packs", "update_pack",
]
