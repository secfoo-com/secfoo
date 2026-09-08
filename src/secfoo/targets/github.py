from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from secfoo.targets.resolver import TargetResolutionError


@contextmanager
def clone_shallow(url: str, *, timeout: int = 600) -> Iterator[Path]:
    """Shallow-clone `url` into a temp dir for the duration of the `with`
    block, then remove it unconditionally -- including when the caller's
    block raises.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="secfoo-clone-"))
    try:
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(tmp_dir)],
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.CalledProcessError as exc:
            raise TargetResolutionError(f"git clone failed for {url}: {exc.stderr}") from exc
        except subprocess.TimeoutExpired as exc:
            raise TargetResolutionError(f"git clone timed out after {timeout}s for {url}") from exc
        yield tmp_dir
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
