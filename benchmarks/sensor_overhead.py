"""Overhead of the Python runtime probe (#55): requests/sec with and without it.

    python benchmarks/sensor_overhead.py            # all modes, ~10 s
    python benchmarks/sensor_overhead.py --requests 200000

Each mode runs in a fresh interpreter. A "request" is a small handler that
parses a query string, builds a response dict through a few app functions,
and serializes it -- the shape of a typical web handler, without network
noise. "watched" calls the watched vulnerable function on every request
(the worst case); "unwatched" never calls it.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

APP = textwrap.dedent("""\
    import json, sys, time, urllib.parse
    import vulnlib

    def parse(qs):
        return dict(urllib.parse.parse_qsl(qs))

    def build(params, call_vuln):
        body = {"user": params.get("user"), "items": [i * 2 for i in range(10)]}
        if call_vuln:
            body["parsed"] = vulnlib.load(params.get("doc", ""))
        return body

    def handle(qs, call_vuln):
        return json.dumps(build(parse(qs), call_vuln))

    n, call_vuln = int(sys.argv[1]), sys.argv[2] == "watched"
    for _ in range(2000):
        handle("user=a&doc=x", call_vuln)
    start = time.perf_counter()
    for _ in range(n):
        handle("user=alice&doc=hello", call_vuln)
    print(n / (time.perf_counter() - start))
    """)
VULNLIB = "def load(text):\n    return text[::-1]\n"


def run(workdir: Path, requests: int, traffic: str, env_extra: dict[str, str] | None) -> float:
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    for key in ("SECFOO_SENSOR", "SECFOO_SENSOR_ADDR", "SECFOO_EVENTS_OUT"):
        env.pop(key, None)
    env.update(env_extra or {})
    cmd = [sys.executable, "-m", "secfoo.sensor", "app.py", str(requests), traffic]
    out = subprocess.run(cmd, cwd=workdir, env=env, capture_output=True, text=True, check=True)  # nosec B603
    return float(out.stdout.strip().splitlines()[-1])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=100_000)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        (workdir / "app.py").write_text(APP, encoding="utf-8")
        (workdir / "vulnlib.py").write_text(VULNLIB, encoding="utf-8")
        (workdir / "watchlist.json").write_text(json.dumps({"version": 1, "generated_at": "x", "entries": [{
            "finding_fingerprint": "fp", "advisory": None, "ecosystem": "PyPI", "package": "vulnlib",
            "version": "1", "granularity": "symbol", "symbols": ["vulnlib.load"], "source": "osv"}]}), encoding="utf-8")
        probe_env = {"SECFOO_SENSOR": "1", "SECFOO_WATCHLIST": "watchlist.json",
                     "SECFOO_EVENTS_OUT": str(workdir / "events.ndjson"), "SECFOO_FLUSH_INTERVAL": "5"}
        backends = ["profile"] + (["monitoring"] if hasattr(sys, "monitoring") else [])
        print(f"Python {sys.version.split()[0]}, {args.requests:,} requests per mode\n")
        print(f"{'mode':<34}{'req/s':>12}{'overhead':>10}")
        for traffic in ("unwatched", "watched"):
            base = run(workdir, args.requests, traffic, None)
            print(f"{'no probe, ' + traffic:<34}{base:>12,.0f}{'':>10}")
            for backend in backends:
                rate = run(workdir, args.requests, traffic, {**probe_env, "SECFOO_SENSOR_BACKEND": backend})
                label = f"probe ({backend}), {traffic}"
                print(f"{label:<34}{rate:>12,.0f}{(base / rate - 1) * 100:>9.1f}%")


if __name__ == "__main__":
    main()
