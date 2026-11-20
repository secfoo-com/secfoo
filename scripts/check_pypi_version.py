#!/usr/bin/env python3
"""Fail if src/secfoo/__about__.py is behind the latest release on PyPI."""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# Pre-releases sort below the final release, post-releases above it:
# 0.3.2.dev0 < 0.3.2a1 < 0.3.2rc1 < 0.3.2 < 0.3.2.post1 (PEP 440).
_VERSION = re.compile(r"^(\d+(?:\.\d+)*)(?:\.?(dev|a|b|rc|post)\.?(\d*))?$")
_RANK = {"dev": 0, "a": 1, "b": 2, "rc": 3, None: 4, "post": 5}


def parse(version: str) -> tuple:
    match = _VERSION.match(version.strip().lower())
    if not match:
        raise ValueError(f"unparseable version: {version!r}")
    release = [int(part) for part in match.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:  # 0.3 == 0.3.0
        release.pop()
    return (tuple(release), _RANK[match.group(2)], int(match.group(3) or 0))


def local_version() -> str:
    text = (ROOT / "src" / "secfoo" / "__about__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError("no __version__ in __about__.py")
    return match.group(1)


def pypi_version(package: str = "secfoo") -> str:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{package}/json", timeout=20) as resp:  # fixed https URL
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
