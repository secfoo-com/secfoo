from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

_GITHUB_URL_RE = re.compile(r"^(https?://github\.com/|git@github\.com:)", re.IGNORECASE)


class TargetResolutionError(RuntimeError):
    pass


class TargetKind(str, Enum):
    LOCAL = "local"
    GITHUB = "github"


@dataclass
class ResolvedTarget:
    kind: TargetKind
    path: Path | None  # None for GITHUB until clone_shallow() fills it in
    display_name: str  # cwd path OR the github URL -- used as the storage project identifier
    is_temporary: bool


def is_github_url(value: str) -> bool:
    return bool(_GITHUB_URL_RE.match(value.strip()))


def resolve_target(target: str | None, *, cwd: Path | None = None) -> ResolvedTarget:
    cwd = cwd or Path.cwd()

    if target is None:
        resolved = cwd.resolve()
        return ResolvedTarget(TargetKind.LOCAL, resolved, str(resolved), False)

    target = target.strip()
    if is_github_url(target):
        return ResolvedTarget(TargetKind.GITHUB, None, target, True)

    path = Path(target).expanduser().resolve()
    if not path.is_dir():
        raise TargetResolutionError(f"Not a directory: {path}")
    return ResolvedTarget(TargetKind.LOCAL, path, str(path), False)


def looks_like_url(value: str) -> bool:
    return bool(re.match(r"^https?://", value.strip(), re.IGNORECASE))
