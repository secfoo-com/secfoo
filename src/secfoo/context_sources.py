"""Documentation sources for `secfoo run --context` (#125).

A source is either an https:// URL the agent reads with whatever MCP tooling
it has, or a local Markdown/text/PDF/DOCX/PPTX file or folder that secfoo
extracts itself. This module only decides what a raw string means and
whether it is allowed; reading and rendering live elsewhere.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from secfoo.docext import SUPPORTED_EXTENSIONS as DOCUMENT_EXTENSIONS

TEXT_EXTENSIONS = frozenset({".md", ".markdown", ".txt"})
SUPPORTED_LOCAL_EXTENSIONS = TEXT_EXTENSIONS | DOCUMENT_EXTENSIONS

SourceKind = Literal["url", "file", "directory"]

# "C:\docs\a.md" has no "//", so a Windows drive path is never mistaken
# for a URL with the scheme "c".
_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


class ContextSourceError(ValueError):
    """A context value that cannot be used; the message says why."""


@dataclass(frozen=True)
class ContextSource:
    raw: str  # as the user wrote it, for display
    kind: SourceKind
    location: str  # the cleaned URL, or the resolved absolute path
    # The absolute path as written, before symlinks are followed. A symlink
    # planted inside the scanned target resolves outside it, so the target
    # check must look at this as well as at `location`.
    written: str | None = None


def looks_like_url(value: str) -> bool:
    return bool(_URL_SCHEME.match(value))


def https_url_problem(value: str) -> str | None:
    """Return None if value is a safe https URL, or a human-readable reason string."""
    cleaned = value.strip()
    if not cleaned:
        return "the URL is empty"
    try:
        parts = urlsplit(cleaned)
    except ValueError as exc:
        return f"not a valid URL: {exc}"
    if parts.scheme == "http":
        return "plain http:// is not allowed, use https://"
    if parts.scheme != "https":
        return f"unsupported URL scheme {parts.scheme!r}, use https://"
    if not parts.hostname:
        return "the URL has no host"
    if parts.username or parts.password:
        return "the URL must not contain credentials"
    if any(char in cleaned for char in "\r\n\t \\"):
        return "the URL must not contain whitespace or backslashes"
    return None


def _parse_url(value: str) -> ContextSource:
    problem = https_url_problem(value)
    if problem is not None:
        raise ContextSourceError(problem)
    return ContextSource(raw=value, kind="url", location=value)


def _parse_path(value: str) -> ContextSource:
    try:
        written = os.path.abspath(Path(value).expanduser())
        path = Path(value).expanduser().resolve()
        is_directory = path.is_dir()
        is_file = path.is_file()
    except (OSError, ValueError) as exc:
        raise ContextSourceError(f"not a usable path: {exc}") from exc
    if is_directory:
        return ContextSource(raw=value, kind="directory", location=str(path), written=written)
    if not is_file:
        raise ContextSourceError("no such file or folder (a URL needs the https:// prefix)")
    if path.suffix.lower() not in SUPPORTED_LOCAL_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_LOCAL_EXTENSIONS))
        raise ContextSourceError(
            f"unsupported file type {path.suffix or '(none)'!r}, supported: {supported}"
        )
    return ContextSource(raw=value, kind="file", location=str(path), written=written)


def parse_context_source(value: str) -> ContextSource:
    cleaned = value.strip()
    if not cleaned:
        raise ContextSourceError("empty value")
    return _parse_url(cleaned) if looks_like_url(cleaned) else _parse_path(cleaned)


def _is_same_or_inside(path: Path, anchor: Path) -> bool:
    candidates = [path, *path.parents]
    existing_anchor = False
    try:
        existing_anchor = anchor.exists()
    except OSError:
        pass

    had_permission_error = False
    all_permission_errors = True

    for cand in candidates:
        try:
            if os.path.samefile(cand, anchor):
                return True
            all_permission_errors = False
        except PermissionError:
            had_permission_error = True
        except OSError:
            all_permission_errors = False

    if existing_anchor and had_permission_error and all_permission_errors:
        raise ContextSourceError("could not verify that it is outside the scanned target")

    return False


def _reject_overlap_with_target(source: ContextSource, target_dir: Path | None) -> None:
    """The scanned target is untrusted, so context must be the reviewer's
    own documents: nothing inside the target, and no folder that contains it."""
    if source.kind == "url" or target_dir is None:
        return
    source_path = Path(source.location)
    paths = [source_path] + ([Path(source.written)] if source.written else [])
    if any(_is_same_or_inside(path, target_dir) for path in paths):
        raise ContextSourceError(
            "it is inside the scanned target, which is untrusted; "
            "context must be your own documents"
        )
    if source.kind == "directory" and _is_same_or_inside(target_dir, source_path):
        raise ContextSourceError("it contains the scanned target, so it would pull in untrusted files")


def _dedupe_key(source: ContextSource) -> str:
    # URL paths are case-sensitive; Windows file paths are not.
    return source.location if source.kind == "url" else os.path.normcase(source.location)


def resolve_context_sources(
    *,
    from_config: list[str],
    from_confluence_flag: list[str],
    from_context_flag: list[str],
    target_dir: Path | None,
) -> list[ContextSource]:
    """Merge, validate and de-duplicate every source for one run.

    Order is config defaults, then --confluence (the alias), then --context,
    so a project's standing sources come first. The first bad value raises
    ContextSourceError naming where it came from.
    """
    ordered = (
        [("defaults.context", value) for value in from_config]
        + [("--confluence", value) for value in from_confluence_flag]
        + [("--context", value) for value in from_context_flag]
    )
    sources: list[ContextSource] = []
    seen: set[str] = set()
    for origin, value in ordered:
        try:
            source = parse_context_source(value)
            _reject_overlap_with_target(source, target_dir)
        except ContextSourceError as exc:
            raise ContextSourceError(f"{origin} {value!r}: {exc}") from None
        key = _dedupe_key(source)
        if key in seen:
            continue
        seen.add(key)
        sources.append(source)
    return sources
