from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from secfoo.targets.resolver import TargetResolutionError, is_github_url


@contextmanager
def clone_shallow(url: str, *, timeout: int = 600) -> Iterator[Path]:
    """Shallow-clone `url` into a temp dir for the duration of the `with`
    block, then remove it unconditionally -- including when the caller's
    block raises.
    """
    url = url.strip()
    if not is_github_url(url):
        raise TargetResolutionError(
            f"refusing to clone {url!r}: only https://github.com/owner/repo "
            "or git@github.com:owner/repo is allowed"
        )
    tmp_dir = Path(tempfile.mkdtemp(prefix="secfoo-clone-"))
    try:
        try:
            # Command-line -c overrides repo-controlled config. Hooks,
            # fsmonitor, ext::, and file:// cannot run during this clone,
            # and `--` keeps a URL from being parsed as a git option.
            subprocess.run(
                [
                    "git",
                    "-c", "protocol.file.allow=never",
                    "-c", "protocol.ext.allow=never",
                    "-c", "core.hooksPath=/dev/null",
                    "-c", "core.fsmonitor=",
                    "clone",
                    "--depth", "1",
                    "--no-recurse-submodules",
                    "--",
                    url,
                    str(tmp_dir),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr or ""
            if "No space left on device" in stderr:
                raise TargetResolutionError(
                    f"git clone failed for {url}: disk full — free space on your "
                    f"system drive (or clone the repo locally and pass the directory "
                    f"as --target instead of a GitHub URL). Original error: {stderr}"
                ) from exc
            raise TargetResolutionError(f"git clone failed for {url}: {stderr}") from exc
        except subprocess.TimeoutExpired as exc:
            raise TargetResolutionError(f"git clone timed out after {timeout}s for {url}") from exc
        yield tmp_dir
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
