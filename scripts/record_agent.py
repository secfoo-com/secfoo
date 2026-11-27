"""Record a real agent-CLI transcript as a replayable test fixture (#116).

The recordings live under ``tests/fixtures/agents/<id>/<cli-version>/`` and
hold raw stdout, stderr, exit code and the prompt that produced them. Secrets
are redacted before the file is written; if any key-shaped value survives
redaction the script refuses to save the recording at all.

Example (run from the repository root)::

    python scripts/record_agent.py --agent opencode --version 2.3.0 \
        --scenario success --verified-by "Your Name" \
        --workdir examples --prompt-file prompt.md --timeout 120 -- \
        opencode run --format json

Use ``--model``-style flags in the command itself; the adapter's argv is what
gets verified, so the recording must invoke the real CLI exactly as secfoo
does. A timeout is recorded with exit_code ``null`` and status ``timeout``.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "agents"

# Anything matching one of these must never reach a committed fixture. The
# generic credential rule covers ``KEY=value`` / ``key: value`` spellings that
# vendor-specific patterns miss.
SECRET_PATTERNS = [
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9_.\-+/=]{16,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|credential)\b"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+=]{12,}"
    ),
]

REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Replace every key-shaped value in ``text`` with ``[REDACTED]``."""
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def ensure_no_secrets(text: str) -> None:
    """Raise ``ValueError`` if a key-shaped value is still present."""
    for pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            raise ValueError(f"refusing to save recording: secret pattern {pattern.pattern!r} still matches")


def _kill(proc: subprocess.Popen[str]) -> None:
    """Stop a timed-out CLI and its children before reading its output."""
    if os.name == "nt":  # no process groups on Windows; taskkill /T gets descendants
        subprocess.run(  # nosec B603 B607 -- fixed argv, numeric PID from Popen
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except (ProcessLookupError, OSError):
            proc.kill()
    try:
        proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _relative(path: Path) -> str:
    """Store paths relative to the repo so fixtures are machine-independent."""
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--agent", required=True, help="adapter id, e.g. opencode")
    parser.add_argument("--version", required=True, help="exact CLI version string reported by the binary")
    parser.add_argument("--scenario", required=True, help="e.g. success, auth_failure, timeout")
    parser.add_argument("--verified-by", required=True, help="who ran the real CLI")
    parser.add_argument("--workdir", default=".", help="directory the CLI runs in (default: repo root)")
    parser.add_argument("--prompt-file", help="file whose contents are sent to the CLI on stdin")
    parser.add_argument("--prompt", help="prompt text (alternative to --prompt-file)")
    parser.add_argument("--timeout", type=float, default=60.0, help="recording timeout in seconds")
    parser.add_argument(
        "--env", action="append", default=[], metavar="KEY=VALUE", help="extra environment variable (repeatable)"
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="real CLI argv, after --")
    args = parser.parse_args(argv)

    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command:
        parser.error("a CLI command is required after --")
    # Same resolution secfoo.agents.base does: on Windows CreateProcess ignores
    # PATHEXT, so a bare npm shim name must be replaced by which()'s result.
    command[0] = shutil.which(command[0]) or command[0]

    if args.prompt_file and args.prompt is not None:
        parser.error("use either --prompt-file or --prompt, not both")
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text(encoding="utf-8")
    else:
        prompt = args.prompt

    workdir = Path(args.workdir).resolve()
    if not workdir.is_dir():
        parser.error(f"workdir is not a directory: {workdir}")

    env = os.environ.copy()
    for item in args.env:
        key, sep, value = item.partition("=")
        if not sep or not key:
            parser.error(f"invalid --env value: {item!r}")
        env[key] = value

    started = datetime.now(timezone.utc)
    proc = subprocess.Popen(  # nosec B603 -- command is supplied by the verifier on purpose
        command,
        cwd=workdir,
        stdin=subprocess.PIPE if prompt is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(input=prompt, timeout=args.timeout)
        run_status, exit_code = "completed", proc.returncode
    except subprocess.TimeoutExpired:
        _kill(proc)
        stdout, stderr = proc.communicate()
        run_status, exit_code = "timeout", None

    record = {
        "schema": 1,
        "agent": args.agent,
        "cli_version": args.version,
        "scenario": args.scenario,
        "verified_at": started.isoformat(timespec="seconds"),
        "verified_by": args.verified_by,
        "platform": platform.platform(),
        "command": command,
        "workdir": _relative(workdir),
        "prompt": prompt,
        "status": run_status,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    }

    serialized = redact(json.dumps(record, indent=2, ensure_ascii=False))
    try:
        ensure_no_secrets(serialized)
        json.loads(serialized)  # redaction must not corrupt the JSON
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    destination = FIXTURE_ROOT / args.agent / args.version / f"{args.scenario}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(serialized + "\n", encoding="utf-8")
    print(f"recorded {run_status} (exit={exit_code}) -> {destination.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
