"""Coverage-guided fuzzing of secfoo's text parsers with Atheris.

The parsers here consume text written by an LLM (reports) or by hand (skill
definitions), so they see every shape of input. The properties checked are
the same ones tests/test_property_parsers.py asserts with Hypothesis; this
harness drives them with libFuzzer's coverage feedback instead of random
generation, which finds deeper paths.

Run locally (Linux or macOS with clang):

    pip install atheris
    python fuzz/fuzz_parsers.py WORK fuzz/corpus/parsers -max_total_time=60

Any crash is written to the current directory as crash-<sha1>; reproduce it
on any platform, with or without Atheris, with
`python fuzz/fuzz_parsers.py crash-<sha1>`. See fuzz/_common.py.
"""

from __future__ import annotations

from _common import main

from secfoo.report.severity import count_severities, extract_overall_risk_rating
from secfoo.skills.loader import SkillLoadError, _parse_frontmatter
from secfoo.web.finding_filters import normalize_severity


def check(data: bytes) -> None:
    # The first 4096 characters, as atheris' ConsumeUnicodeNoSurrogates(4096)
    # gave before; the corpus is real reports, so decode them as text.
    text = data.decode("utf-8", errors="replace")[:4096]

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


if __name__ == "__main__":
    main(check)
