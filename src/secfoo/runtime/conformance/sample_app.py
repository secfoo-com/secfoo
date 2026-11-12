"""Reference sample app for the #73 conformance kit (Python).

A probe for another runtime ships its own sample app that follows the same
contract: read SECFOO_CONFORMANCE_STEP and do exactly this, then exit 0.

    call     call the watched function 3 times
    nocall   call only the safe function
    request  handle one request to the concrete URL
             /users/8675309?token=<SENTINEL> (route template "GET /users/{id}")
             with an "Authorization: Bearer <SENTINEL>" header, passing both
             to the watched function as arguments; none of it may leave the app
    slow     call the watched function, then keep working for ~1.5 s (the
             kit kills its fake sensor meanwhile; the app must not notice)
    loop     call the watched function SECFOO_CONFORMANCE_N times (overhead)

Run it through the probe, e.g.:
    secfoo sensor conformance -- python -m secfoo.sensor -m secfoo.runtime.conformance.sample_app
"""

from __future__ import annotations

import os
import sys
import time

from secfoo.runtime.conformance import vulnerable

SENTINEL = os.environ.get("SECFOO_CONFORMANCE_SENTINEL", "")


def handle_request(path: str, headers: dict[str, str]) -> str:
    # A real app would route "GET /users/{id}" here.
    return vulnerable.parse(path + headers.get("Authorization", ""))


def main() -> int:
    step = os.environ.get("SECFOO_CONFORMANCE_STEP", "call")
    if step == "call":
        for _ in range(3):
            vulnerable.parse("payload")
    elif step == "nocall":
        for _ in range(3):
            vulnerable.safe("payload")
    elif step == "request":
        handle_request(f"/users/8675309?token={SENTINEL}", {"Authorization": f"Bearer {SENTINEL}"})
    elif step == "slow":
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            vulnerable.parse("payload")
            time.sleep(0.05)
    elif step == "loop":
        for _ in range(int(os.environ.get("SECFOO_CONFORMANCE_N", "100000"))):
            vulnerable.parse("payload")
    else:
        print(f"unknown step {step!r}", file=sys.stderr)
        return 2
    print(f"conformance step {step} ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
