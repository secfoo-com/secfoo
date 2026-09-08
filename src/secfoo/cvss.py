"""Real CVSS v3.1 Base Score computation (FIRST.org's public, deterministic
spec: https://www.first.org/cvss/v3.1/specification-document).

The SAST skill's prompt contract requires the LLM to state a full CVSS v3.1
base vector for each finding -- the eight metrics describing attack
surface, privileges, and blast radius, which the model can reason about
directly from the code it just read. It never asserts a bare numeric
score; that number is always computed here, from the vector, via the exact
published formula. This mirrors how a human pentester self-scores their
own discovery -- categorically different from trusting an LLM to invent an
external identifier (e.g. a CVE ID) it has no way to verify.
"""

from __future__ import annotations

import math

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_S_VALUES = {"U", "C"}
_CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

_RATING_BANDS = (
    (0.0, "none"),
    (3.9, "low"),
    (6.9, "medium"),
    (8.9, "high"),
    (10.0, "critical"),
)


class CvssError(ValueError):
    """Raised for a missing, incomplete, or unrecognized CVSS v3.1 vector.
    Never silently defaults a missing metric -- a defaulted metric would
    produce a wrong, confidently-displayed score, which is worse than
    surfacing "no CVSS vector" the way an unrecognized CWE surfaces
    "unverified" elsewhere in this app.
    """


def parse_vector(vector: str) -> dict[str, str]:
    """Parses a CVSS v3.1 base vector string into {"AV": "N", ...}.

    Accepts both the bare metric string the SAST contract asks for
    ("AV:N/AC:L/...") and one prefixed with the official "CVSS:3.1/" label
    (stripped if present, since a real model may add it despite the
    contract's example not showing one). Raises CvssError if any of the
    eight required metrics is missing, duplicated with conflicting values,
    or has a value outside its recognized set.
    """
    if not vector or not vector.strip():
        raise CvssError("Empty CVSS vector")

    text = vector.strip()
    if text.upper().startswith("CVSS:3.1/"):
        text = text[len("CVSS:3.1/") :]
    elif text.upper().startswith("CVSS:3.0/"):
        text = text[len("CVSS:3.0/") :]

    metrics: dict[str, str] = {}
    for segment in text.split("/"):
        segment = segment.strip()
        if not segment:
            continue
        if ":" not in segment:
            raise CvssError(f"Malformed CVSS metric segment: {segment!r}")
        key, _, value = segment.partition(":")
        key, value = key.strip().upper(), value.strip().upper()
        if key not in _METRIC_ORDER:
            continue  # ignore unrecognized/optional metrics (e.g. temporal/environmental)
        metrics[key] = value

    missing = [m for m in _METRIC_ORDER if m not in metrics]
    if missing:
        raise CvssError(f"CVSS vector missing required metric(s): {', '.join(missing)}")

    _validate_value("AV", metrics["AV"], _AV_WEIGHTS)
    _validate_value("AC", metrics["AC"], _AC_WEIGHTS)
    _validate_value("PR", metrics["PR"], _PR_WEIGHTS_UNCHANGED)
    _validate_value("UI", metrics["UI"], _UI_WEIGHTS)
    if metrics["S"] not in _S_VALUES:
        raise CvssError(f"Invalid CVSS Scope (S) value: {metrics['S']!r}")
    _validate_value("C", metrics["C"], _CIA_WEIGHTS)
    _validate_value("I", metrics["I"], _CIA_WEIGHTS)
    _validate_value("A", metrics["A"], _CIA_WEIGHTS)

    return metrics


def _validate_value(metric: str, value: str, weights: dict[str, float]) -> None:
    if value not in weights:
        raise CvssError(f"Invalid CVSS {metric} value: {value!r}")


def _roundup(value: float) -> float:
    """CVSS's own defined rounding: up to the nearest 0.1, not Python's
    round-half-to-even. The int-of-value*100000 trick (from FIRST.org's
    own reference implementation) avoids float representation noise, e.g.
    a naive ceil(4.02 * 10) / 10 landing on 4.099999999999999.
    """
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (math.floor(int_value / 10000) + 1) / 10


def base_score(vector: str) -> float:
    """The real CVSS v3.1 Base Score for `vector`, via the published
    Impact/Exploitability formula. Raises CvssError on a malformed or
    incomplete vector rather than guessing.
    """
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"

    c = _CIA_WEIGHTS[metrics["C"]]
    i = _CIA_WEIGHTS[metrics["I"]]
    a = _CIA_WEIGHTS[metrics["A"]]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    pr_weights = _PR_WEIGHTS_CHANGED if scope_changed else _PR_WEIGHTS_UNCHANGED
    exploitability = (
        8.22
        * _AV_WEIGHTS[metrics["AV"]]
        * _AC_WEIGHTS[metrics["AC"]]
        * pr_weights[metrics["PR"]]
        * _UI_WEIGHTS[metrics["UI"]]
    )

    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def rating(score: float) -> str:
    """0-10 CVSS base score -> none/low/medium/high/critical, the official
    FIRST.org qualitative severity rating bands.
    """
    if score <= 0.0:
        return "none"
    for upper, band in _RATING_BANDS:
        if score <= upper:
            return band
    return "critical"
