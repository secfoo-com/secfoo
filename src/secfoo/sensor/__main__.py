"""`python -m secfoo.sensor app.py [args]` or `python -m secfoo.sensor -m module [args]`.

Starts the probe (only if SECFOO_SENSOR=1), then runs the app exactly as
`python app.py` would.
"""

from __future__ import annotations

import runpy
import sys

from secfoo.sensor import start_from_env


def main(argv: list[str]) -> None:
    if not argv:
        print("usage: python -m secfoo.sensor app.py [args] | -m module [args]", file=sys.stderr)
        raise SystemExit(2)
    start_from_env()
    if argv[0] == "-m" and len(argv) > 1:
        sys.argv = [argv[1], *argv[2:]]
        runpy.run_module(argv[1], run_name="__main__", alter_sys=True)
    else:
        sys.argv = list(argv)
        runpy.run_path(argv[0], run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])
