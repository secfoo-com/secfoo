"""Ephemeral clones for GitLab and Bitbucket, with environment-only credentials."""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from secfoo.targets.resolver import TargetKind, TargetResolutionError, forge_kind


@contextmanager
def clone_forge(url: str, *, kind: TargetKind, timeout: int = 600) -> Iterator[Path]:
    if kind not in {TargetKind.GITLAB, TargetKind.BITBUCKET} or forge_kind(url) is not kind:
        raise TargetResolutionError("Invalid forge target")
    token_var = "SECFOO_GITLAB_TOKEN" if kind is TargetKind.GITLAB else "SECFOO_BITBUCKET_TOKEN"
    username = "oauth2" if kind is TargetKind.GITLAB else "x-token-auth"
    with tempfile.TemporaryDirectory(prefix="secfoo-clone-") as directory:
        root = Path(directory)
        checkout = root / "repo"
        env = os.environ.copy()
        # Limit token environment variables passed to the clone subprocess.
        token = env.pop(token_var, "")
        env.pop("SECFOO_GITLAB_TOKEN", None)
        env.pop("SECFOO_BITBUCKET_TOKEN", None)
        env["GIT_TERMINAL_PROMPT"] = "0"
        cmd = ["git"]
        if token and url.lower().startswith("https://"):
            # The helper contains no credentials; Git sees only its temporary path.
            # -c applies to this process, so credentials are not saved in .git/config.
            helper = root / "askpass.py"
            helper.write_text(
                "import os, sys\n"
                "print(os.environ['SECFOO_CLONE_USER'] if 'username' in sys.argv[1].lower() "
                "else os.environ['SECFOO_CLONE_TOKEN'])\n", encoding="utf-8",
            )
            # Git runs askpass commands through its own shell (also bundled
            # with Git for Windows); Python paths containing spaces are quoted.
            askpass = shlex.quote(sys.executable) + " " + shlex.quote(str(helper))
            env.update(GIT_ASKPASS=askpass, SECFOO_CLONE_TOKEN=token, SECFOO_CLONE_USER=username)
            # Disable configured credential helpers so a successful clone cannot
            # store the token through a user's credential manager.
            cmd += ["-c", "credential.helper="]
        if token and url.lower().startswith("https://"):
            cmd += ["-c", "http.followRedirects=false"]
        cmd += ["clone", "--depth", "1", "--", url, str(checkout)]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            raise TargetResolutionError(f"git clone timed out after {timeout}s") from None
        except subprocess.CalledProcessError as exc:
            # Do not forward git stderr: remote servers and helpers can echo secrets.
            detail = " (disk full)" if "No space left on device" in (exc.stderr or "") else ""
            raise TargetResolutionError(f"git clone failed{detail}; check repository access") from None
        except OSError:
            raise TargetResolutionError("Unable to run git clone; check that git is installed") from None
        # Remove askpass material before any agent can inspect the checkout.
        for helper_path in (root / "askpass.py",):
            helper_path.unlink(missing_ok=True)
        yield checkout
