#!/usr/bin/env python3
"""Copies the hand-authored design-system/ folder into the package's static
assets so the wheel is self-contained. Run this after editing anything under
design-system/, before testing or building the web dashboard.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "design-system"
DEST = ROOT / "src" / "secfoo" / "web" / "static" / "design-system"


def main() -> None:
    if not SOURCE.is_dir():
        raise SystemExit(f"source directory not found: {SOURCE}")
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.copytree(SOURCE, DEST)
    print(f"Synced {SOURCE} -> {DEST}")


if __name__ == "__main__":
    main()
