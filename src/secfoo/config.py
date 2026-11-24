"""Filesystem layout for the global secfoo store (~/.secfoo by default)."""

from __future__ import annotations

import os
import time
from pathlib import Path

STORE_DIR = Path(os.environ.get("SECFOO_HOME", Path.home() / ".secfoo"))
DB_PATH = STORE_DIR / "secfoo.db"
REPORTS_DIR = STORE_DIR / "reports"
TMP_DIR = STORE_DIR / "tmp"
ATTACHMENTS_DIR = STORE_DIR / "attachments"
# Enterprise portal credentials (secfoo cloud login/logout) -- a dedicated
# file rather than a section in config.toml: config.toml has no writer
# anywhere in the codebase (only read via tomllib) and `secfoo config
# init` works by wholesale-overwriting it from config.example.toml, so
# safely patching one section into a possibly hand-edited config.toml
# would need a TOML writer. cloud.toml is fully owned by `secfoo cloud`,
# safe to overwrite wholesale, and gets chmod 0600 since it holds a secret.
CLOUD_CONFIG_PATH = STORE_DIR / "cloud.toml"


def ensure_store_dirs() -> None:
    # Reports hold the scanned source, prompts and a map of its weaknesses,
    # and the DB holds findings and key hashes: owner-only, like ~/.ssh.
    # 0700 on the root is enough to keep other local users out of all of it.
    STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    _make_private(STORE_DIR)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    ATTACHMENTS_DIR.mkdir(parents=True, exist_ok=True)


def _make_private(directory: Path) -> None:
    try:
        if directory.stat().st_mode & 0o077:
            directory.chmod(0o700)
    except OSError:  # not ours (a shared SECFOO_HOME) or a read-only mount: leave it
        pass


def write_private_text(path: Path, text: str) -> None:
    """Write a secret-bearing file atomically and symlink-safely so it is never
    readable by others, not even between creation and replacement.

    Resolves symlinks first so that dotfile managers (e.g. stow, chezmoi)
    do not have their symlink replaced with a regular file, and writes via a
    temporary file in the target directory before atomically replacing it.
    """
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_name(f".{target.name}.tmp.{os.getpid()}.{time.time_ns()}")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        # POSIX: O_CREAT's mode does not apply to an existing file
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
        os.replace(tmp_path, target)
    finally:
        if fd != -1:
            os.close(fd)
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def run_dir(run_uuid: str) -> Path:
    return REPORTS_DIR / run_uuid


def attachment_dir(assessment_id: int) -> Path:
    return ATTACHMENTS_DIR / str(assessment_id)
