"""Coverage-guided fuzzing of secfoo's text parsers with Atheris.

The parsers here consume text written by an LLM (reports) or by hand (skill
definitions), so they see every shape of input. The properties checked are
the same ones tests/test_property_parsers.py asserts with Hypothesis; this
harness drives them with libFuzzer's coverage feedback instead of random
generation, which finds deeper paths.

Run locally (Linux or macOS with clang):

    pip install atheris
    python fuzz/fuzz_parsers.py -max_total_time=60

Any crash is written to the current directory as crash-<sha1>; reproduce
with `python fuzz/fuzz_parsers.py crash-<sha1>`.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from secfoo.report.severity import count_severities, extract_overall_risk_rating
    from secfoo.skills.loader import SkillLoadError, _parse_frontmatter
    from secfoo.web.finding_filters import normalize_severity


def test_one_input(data: bytes) -> None:
    provider = atheris.FuzzedDataProvider(data)
    text = provider.ConsumeUnicodeNoSurrogates(4096)

    # Report parsers must accept any text and never raise.
    counts = count_severities(text)
    assert counts.total == counts.critical + counts.high + counts.medium + counts.low + counts.info
    rating = extract_overall_risk_rating(text)
    assert rating is None or rating == rating.lower()

    # Frontmatter parsing may reject input, but only with SkillLoadError.
    try:
        fields, body = _parse_frontmatter(text, source="<fuzz>")
    except SkillLoadError:
        pass
    else:
        assert isinstance(fields, dict)
        assert isinstance(body, str)

    # Severity normalisation is total and idempotent.
    normalised = normalize_severity(text[:64])
    assert normalize_severity(normalised) == normalised


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
