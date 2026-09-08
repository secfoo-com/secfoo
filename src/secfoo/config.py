"""Filesystem layout for the global secfoo store (~/.secfoo by default)."""

from __future__ import annotations

import os
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
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    ATTACHMENTS_DIR.mkdir(parents=True, exist_ok=True)


def run_dir(run_uuid: str) -> Path:
    return REPORTS_DIR / run_uuid


def attachment_dir(assessment_id: int) -> Path:
    return ATTACHMENTS_DIR / str(assessment_id)
