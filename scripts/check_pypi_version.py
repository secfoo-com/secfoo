#!/usr/bin/env python3
"""Fail if src/secfoo/__about__.py is behind the latest release on PyPI."""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def parse(version: str) -> tuple[int, ...]:
    match = re.match(r"^(\d+(?:\.\d+)*)", version)
    if not match:
        raise ValueError(f"unparseable version: {version!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def local_version() -> str:
    text = (ROOT / "src" / "secfoo" / "__about__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError("no __version__ in __about__.py")
    return match.group(1)


def pypi_version(package: str = "secfoo") -> str:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{package}/json", timeout=20) as resp:
        return json.load(resp)["info"]["version"]


def main() -> int:
    local, remote = local_version(), pypi_version()
    print(f"__about__.py: {local}  PyPI: {remote}")
    if parse(local) < parse(remote):
        print(f"::error::__about__.py ({local}) is behind the latest PyPI release ({remote}).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
