"""Optional read-only Claude CLI wrapper with complete stream capture.

Put a launcher named ``claude`` on PATH that executes this file. Set
CLAUDE_EVAL_BINARY to the real official CLI and CLAUDE_EVAL_CAPTURE_DIR to a
private directory. This uses the CLI's normal authentication; it never reads
or exports its credentials. Apply the same wrapper to both source revisions.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path


def parse_stream(stdout: str) -> tuple[dict, list[dict]]:
    events = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    results = [event for event in events if event.get("type") == "result"]
    if (not events or len(results) != 1 or events[-1].get("type") != "result"
            or events[0].get("type") != "system" or events[0].get("subtype") != "init"
            or not any(event.get("type") == "assistant" for event in events)):
        raise ValueError("incomplete Claude stream: expected one final result")
    calls = []
    for event in events:
        if event.get("type") != "assistant":
            continue
        for block in event.get("message", {}).get("content", []):
            if block.get("type") == "tool_use":
                calls.append({"name": block["name"], "input": block.get("input", {})})
    return results[0], calls


def main() -> int:
    binary = Path(os.environ["CLAUDE_EVAL_BINARY"]).resolve(strict=True)
    capture_dir = Path(os.environ["CLAUDE_EVAL_CAPTURE_DIR"])
    capture_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    args = sys.argv[1:]
    args[args.index("--output-format") + 1] = "stream-json"
    args[args.index("--setting-sources") + 1] = ""
    allowed = args[args.index("--allowedTools") + 1].split(",")
    args += ["--verbose", "--settings",
             '{"disableAllHooks":true}', "--disable-slash-commands", "--no-chrome"]
    proc = subprocess.run([str(binary), *args], input=sys.stdin.read(), text=True,
                          capture_output=True, check=False)
    capture = {"argv": args, "stdout": proc.stdout, "stderr": proc.stderr,
               "returncode": proc.returncode}
    try:
        result, calls = parse_stream(proc.stdout)
        capture.update(result=result, tool_calls=calls, tool_observation="complete", tool_allowlist=allowed)
        stdout = json.dumps(result)
    except (ValueError, KeyError, TypeError):
        capture["tool_observation"] = "unavailable"
        stdout = proc.stdout
    path = capture_dir / f"{uuid.uuid4().hex}.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(capture, output)
    path.chmod(0o600)
    sys.stdout.write(stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
