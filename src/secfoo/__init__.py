from secfoo.__about__ import __version__

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SENSOR_ENV = 'SECFOO_SENSOR'
EVIDENCE_LADDER = (
    'present', 'loaded', 'executed', 'reached_from_traffic',
    'reached_via_exposed_entry_point',
)


def sensor_enabled() -> bool:
    return os.environ.get(SENSOR_ENV) == '1'


@dataclass(frozen=True)
class WatchlistEntry:
    package: str
    version: str
    symbols: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeEvent:
    package: str
    version: str
    state: str
    symbol: str | None = None
    route: str | None = None
    authenticated: bool | None = None
    timestamp: float = field(default_factory=time.time)


def load_watchlist(path: str | Path) -> tuple[WatchlistEntry, ...]:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    return tuple(
        WatchlistEntry(
            package=item['package'],
            version=item['version'],
            symbols=tuple(item.get('symbols', ())),
        )
        for item in data.get('entries', ())
    )


def append_event(path: str | Path, event: RuntimeEvent) -> None:
    if not sensor_enabled():
        return
    with Path(path).open('a', encoding='utf-8') as handle:
        print(json.dumps(asdict(event), sort_keys=True), file=handle)


__all__ = [
    '__version__', 'SENSOR_ENV', 'EVIDENCE_LADDER', 'WatchlistEntry',
    'RuntimeEvent', 'sensor_enabled', 'load_watchlist', 'append_event',
]
