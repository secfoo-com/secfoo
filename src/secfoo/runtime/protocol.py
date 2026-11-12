"""Probe <-> sensor protocol (#73): one contract for every runtime.

Spec: docs/RUNTIME_PROTOCOL.md. Schema: protocol.schema.json (next to this
module). A stream is newline-framed JSON: the probe sends `hello` (and, for
TCP with SECFOO_SENSOR_KEY set, `auth`) followed by #53 event lines; the
sensor may answer `welcome` and later `slow`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from secfoo.runtime.evidence import LANGUAGES, EvidenceError, validate_event

PROTOCOL_VERSION = 1
CONTROL_TYPES = frozenset({"hello", "welcome", "slow", "auth"})

# Values a probe must never send (#51 rule 3): argument values, concrete URL
# paths, query strings, header values, user ids. The conformance kit plants
# this sentinel in all of them and then looks for it, plus these patterns.
SENTINEL = "s3cr3t-SENTINEL-73"
FORBIDDEN_PATTERNS = (
    re.compile(re.escape(SENTINEL)),
    re.compile(r"\?[\w.~-]+="),              # a query string
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/-]{6,}"),  # an Authorization header value
    re.compile(r"/users/8675309"),           # the kit's concrete URL path
)


class ProtocolError(ValueError):
    pass


def _text(message: dict, key: str) -> str:
    value = message.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ProtocolError(f"{message.get('type')}: {key!r} must be a non-empty string")
    return value


def validate_control(message: dict) -> dict:
    kind = message.get("type")
    if kind == "hello":
        if message.get("protocol") != PROTOCOL_VERSION:
            raise ProtocolError(f"hello: protocol must be {PROTOCOL_VERSION}")
        runtime = _text(message, "runtime")
        if runtime not in LANGUAGES:
            raise ProtocolError(f"hello: runtime must be one of {', '.join(sorted(LANGUAGES))}")
        _text(message, "runtime_version")
        _text(message, "probe_version")
        pid = message.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ProtocolError("hello: pid must be a positive integer")
        _text(message, "host")
    elif kind == "welcome":
        if message.get("protocol") != PROTOCOL_VERSION:
            raise ProtocolError(f"welcome: protocol must be {PROTOCOL_VERSION}")
        interval = message.get("flush_interval")
        if not isinstance(interval, (int, float)) or isinstance(interval, bool) or interval <= 0:
            raise ProtocolError("welcome: flush_interval must be a positive number of seconds")
    elif kind == "slow":
        factor = message.get("sample_every")
        if isinstance(factor, bool) or not isinstance(factor, int) or factor < 1:
            raise ProtocolError("slow: sample_every must be an integer >= 1")
    elif kind == "auth":
        _text(message, "key")
    else:
        raise ProtocolError(f"unknown control message type {kind!r}")
    return message


def validate_message(message: object) -> dict:
    """A control message or a #53 event line; raises ProtocolError otherwise."""
    if not isinstance(message, dict):
        raise ProtocolError("each line must be a JSON object")
    if message.get("type") in CONTROL_TYPES:
        return validate_control(message)
    try:
        return validate_event(message)
    except EvidenceError as exc:
        raise ProtocolError(str(exc)) from None


def forbidden_data(lines: Iterable[str]) -> list[str]:
    """Lines that carry data a probe must never send, with the reason."""
    problems = []
    for number, line in enumerate(lines, start=1):
        if '"type":"auth"' in line.replace(" ", ""):
            continue  # the shared key is the one secret that belongs on the wire
        for pattern in FORBIDDEN_PATTERNS:
            if pattern.search(line):
                problems.append(f"line {number}: matches forbidden pattern {pattern.pattern!r}")
                break
    return problems
