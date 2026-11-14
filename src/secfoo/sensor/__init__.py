"""secfoo runtime sensor: the in-process Python probe (#55).

Opt-in only (#51 rule 0). `start_from_env()` does nothing unless
`SECFOO_SENSOR=1` is set, so importing this package -- or having it on
PYTHONPATH -- never changes an app's behavior.

    SECFOO_SENSOR=1 SECFOO_WATCHLIST=watchlist.json SECFOO_EVENTS_OUT=events.ndjson python -m secfoo.sensor app.py
    secfoo instrument --watchlist watchlist.json -o events.ndjson -- python app.py
"""

from __future__ import annotations

import os
import sys

_probe = None


def enabled(environ=None) -> bool:
    return (os.environ if environ is None else environ).get("SECFOO_SENSOR", "").strip() == "1"


def start_from_env():
    """Start the probe from SECFOO_* variables. Returns it, or None when the
    sensor isn't enabled. Never raises into the app."""
    global _probe
    if _probe is not None or not enabled():
        return _probe
    try:
        from secfoo.sensor.probe import DEFAULT_FLUSH_SECONDS, Probe
        from secfoo.sensor.transport import from_env

        flush = float(os.environ.get("SECFOO_FLUSH_INTERVAL", DEFAULT_FLUSH_SECONDS))
        _probe = Probe(
            watchlist_path=os.environ.get("SECFOO_WATCHLIST") or None,
            transport=from_env(),
            app_root=os.environ.get("SECFOO_APP_ROOT") or None,
            flush_seconds=max(flush, 0.05),
            backend=os.environ.get("SECFOO_SENSOR_BACKEND") or None,
        )
        _probe.start()
    except Exception as exc:  # noqa: BLE001 -- fail-open: a bad config never stops the app
        print(f"secfoo sensor: not started ({exc})", file=sys.stderr)
        _probe = None
    return _probe


def current_probe():
    return _probe
