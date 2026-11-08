from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit

_GITHUB_URL_RE = re.compile(r"^(https?://github\.com/|git@github\.com:)", re.IGNORECASE)


class TargetResolutionError(RuntimeError):
    pass


class TargetKind(str, Enum):
    LOCAL = "local"
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"


@dataclass
class ResolvedTarget:
    kind: TargetKind
    path: Path | None  # None for remote repositories until cloning
    display_name: str  # cwd path OR the github URL -- used as the storage project identifier
    is_temporary: bool


def is_github_url(value: str) -> bool:
    return bool(_GITHUB_URL_RE.match(value.strip()))


def forge_kind(value: str) -> TargetKind | None:
    """Recognize supported GitLab/Bitbucket URLs without accepting credentials."""
    if not (looks_like_url(value) or value.startswith("git@")):
        return None
    try:
        initial = urlsplit(value)
        if initial.username is not None or initial.password is not None:
            raise TargetResolutionError("Repository URLs must not contain credentials; use environment tokens")
    except ValueError:
        raise TargetResolutionError("Invalid repository URL") from None
    if is_github_url(value):
        return None
    hosts = {"gitlab.com": TargetKind.GITLAB, "bitbucket.org": TargetKind.BITBUCKET}
    configured = os.environ.get("SECFOO_GITLAB_HOST", "").strip().lower()
    if configured:
        try:
            parsed_host = urlsplit("https://" + configured)
        except ValueError:
            raise TargetResolutionError("Invalid SECFOO_GITLAB_HOST") from None
        if (parsed_host.netloc != configured or parsed_host.username or parsed_host.password
                or parsed_host.path or parsed_host.query or parsed_host.fragment
                or not parsed_host.hostname):
            raise TargetResolutionError("SECFOO_GITLAB_HOST must be a hostname with an optional port")
        try:
            _ = parsed_host.port
        except ValueError:
            raise TargetResolutionError("Invalid SECFOO_GITLAB_HOST port") from None
        if parsed_host.hostname in {"github.com", "bitbucket.org"}:
            raise TargetResolutionError("SECFOO_GITLAB_HOST conflicts with another forge")
        hosts[configured] = TargetKind.GITLAB
    if value.startswith("git@"):
        match = re.fullmatch(r"git@([^/:]+):(.+)", value)
        if not match:
            return None
        authority, path = match.groups()
        kind = hosts.get(authority.lower())
    else:
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"https", "http"}:
                return None
            if parsed.username is not None or parsed.password is not None:
                raise TargetResolutionError("Repository URLs must not contain credentials; use environment tokens")
            authority, path = parsed.netloc.lower(), parsed.path.lstrip("/")
            kind = hosts.get(authority)
            if not kind:
                return None
            if parsed.scheme.lower() != "https" or parsed.query or parsed.fragment:
                raise TargetResolutionError("GitLab and Bitbucket targets require HTTPS without query or fragment")
        except ValueError:
            raise TargetResolutionError("Invalid repository URL") from None
    if kind:
        parts = path.removesuffix(".git").split("/")
        if (len(parts) < 2 or (kind is TargetKind.BITBUCKET and len(parts) != 2)
                or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or part in {".", ".."}
                       for part in parts)):
            raise TargetResolutionError("Repository URL must identify a namespace and repository")
    return kind


def resolve_target(target: str | None, *, cwd: Path | None = None) -> ResolvedTarget:
    cwd = cwd or Path.cwd()

    if target is None:
        resolved = cwd.resolve()
        return ResolvedTarget(TargetKind.LOCAL, resolved, str(resolved), False)

    target = target.strip()
    kind = forge_kind(target)
    if kind:
        return ResolvedTarget(kind, None, target, True)
    if is_github_url(target):
        return ResolvedTarget(TargetKind.GITHUB, None, target, True)

    if looks_like_url(target) or target.startswith(("git@", "ssh://")):
        raise TargetResolutionError("Unsupported repository URL")

    path = Path(target).expanduser().resolve()
    if not path.is_dir():
        raise TargetResolutionError(f"Not a directory: {path}")
    return ResolvedTarget(TargetKind.LOCAL, path, str(path), False)


def looks_like_url(value: str) -> bool:
    return bool(re.match(r"^https?://", value.strip(), re.IGNORECASE))
