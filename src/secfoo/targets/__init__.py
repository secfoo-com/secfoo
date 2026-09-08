from secfoo.targets.github import clone_shallow
from secfoo.targets.resolver import (
    ResolvedTarget,
    TargetKind,
    TargetResolutionError,
    is_github_url,
    looks_like_url,
    resolve_target,
)

__all__ = [
    "ResolvedTarget",
    "TargetKind",
    "TargetResolutionError",
    "is_github_url",
    "looks_like_url",
    "resolve_target",
    "clone_shallow",
]
