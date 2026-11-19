"""Property-based tests for the report and skill-definition parsers.

These parsers consume text produced by an LLM (reports) or written by hand
(skill files), so they get fed every shape of input. Hypothesis generates
the inputs; the properties below are what must hold for all of them:
round-tripping, never raising on garbage, and counting exactly what was
put in.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from secfoo.report.markdown import MalformedReportError
from secfoo.report.severity import (
    SeverityCounts,
    count_severities,
    extract_overall_risk_rating,
)
from secfoo.skills.loader import SkillLoadError, _parse_frontmatter
from secfoo.web.finding_filters import _VALID_SEVERITIES, normalize_severity

# --------------------------------------------------------------------------- #
# report/severity.py
# --------------------------------------------------------------------------- #

TIERS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}

# Any casing of a recognised tier word, e.g. "HIGH", "High", "hIgH".
tier_word = st.sampled_from(sorted(TIERS)).flatmap(
    lambda word: st.lists(st.booleans(), min_size=len(word), max_size=len(word)).map(
        lambda caps: "".join(c.upper() if up else c for c, up in zip(word, caps))
    )
)
# Letters only, so it can never collide with a tier alias by accident.
unknown_word = st.from_regex(r"[A-Za-z]{1,12}", fullmatch=True).filter(lambda w: w.lower() not in TIERS)
# A heading title or a line of filler: anything printable on one line that
# doesn't start a new heading.
one_line = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\n\r"),
    max_size=40,
).filter(lambda s: not s.lstrip().startswith("###"))


# Example findings a report may legitimately show: inside a closed code
# fence or a blockquote they are illustrations, never counted.
example_title = one_line.filter(lambda s: "~" not in s and "`" not in s)
example_block = st.tuples(st.sampled_from(["fence", "quote"]), tier_word, example_title).map(
    lambda t: (f"~~~~\n### [{t[1]}] F9: {t[2]}\n~~~~" if t[0] == "fence" else f"> ### [{t[1]}] F9: {t[2]}")
)


@given(
    headings=st.lists(st.tuples(st.one_of(tier_word, unknown_word), one_line), max_size=25),
    filler=st.lists(one_line, max_size=25),
    examples=st.lists(example_block, max_size=5),
)
def test_count_severities_counts_exactly_the_recognised_headings(headings, filler, examples):
    lines = ["prose: " + text for text in filler]
    expected = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for word, title in headings:
        lines.insert(len(lines) // 2, f"### [{word}] F: {title}")
        tier = TIERS.get(word.lower())
        if tier:
            expected[tier] += 1
    for block in examples:  # separated by blank lines so each stays its own block
        lines.insert(len(lines) // 3, "\n" + block + "\n")
    counts = count_severities("\n".join(lines))
    assert counts == SeverityCounts(**expected)
    assert counts.total == sum(expected.values())


@given(st.text())
@settings(max_examples=300)
def test_arbitrary_source_in_closed_fence_keeps_real_finding(text):
    import re
    fence = '`' * (max((len(m[0]) for m in re.finditer(r'`+', text)), default=0) + 3)
    report = f"{fence}\n{text}\n{fence}\n\n### [High] F1: real\n"
    assert count_severities(report).high == 1


@given(text=st.text(), separator=st.sampled_from(['\u2028', '\u2029', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x85']))
@settings(max_examples=300)
def test_unicode_separators_cannot_close_a_fence(text, separator):
    import re

    import pytest
    fence = '`' * (max((len(m[0]) for m in re.finditer(r'`+', text)), default=0) + 3)
    report = f"{fence}\n### [High] F1: real\n{text}x{separator}{fence}\nend\n"
    with pytest.raises(MalformedReportError):
        count_severities(report)


@given(
    word=st.one_of(tier_word, unknown_word),
    before=one_line,
    after=one_line,
    shape=st.sampled_from(["{}", "- {}", "> {}"]),
)
def test_overall_risk_rating_round_trips(word, before, after, shape):
    # The marker is matched case-insensitively and the rating is lowercased,
    # whether it is a plain line, a list item or a blockquote callout.
    line = shape.format(f"**Overall risk rating:** {word}")
    report = f"# Report\n\nprose: {before}\n\n{line}\n\nprose: {after}"
    assert extract_overall_risk_rating(report) == word.lower()


@given(st.text())
def test_overall_risk_rating_only_rejects_malformed_reports(text):
    """Arbitrary text never crashes the extractor with anything but
    MalformedReportError, and only when the severity counter (which gates
    CI) rejects the same text: the two never disagree about a report."""
    try:
        rating = extract_overall_risk_rating(text)
    except MalformedReportError:
        try:
            count_severities(text)
        except MalformedReportError:
            return
        raise AssertionError("rating extractor rejected a report the severity counter accepts")
    assert rating is None or rating == rating.lower()


# --------------------------------------------------------------------------- #
# skills/loader.py frontmatter
# --------------------------------------------------------------------------- #

frontmatter_key = st.from_regex(r"[a-z][a-z0-9_]{0,15}", fullmatch=True)
# Values may contain ':' (the parser splits on the first one only) but not
# newlines or '---', which would end the block.
frontmatter_value = (
    st.text(
        alphabet=st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="\n\r"),
        min_size=1,
        max_size=40,
    )
    .map(str.strip)
    .filter(lambda v: v and "---" not in v)
)
body_text = st.text(max_size=200).filter(lambda b: "---" not in b)


@given(fields=st.dictionaries(frontmatter_key, frontmatter_value, min_size=1, max_size=8), body=body_text)
def test_frontmatter_round_trips(fields, body):
    rendered = "---\n" + "".join(f"{k}: {v}\n" for k, v in fields.items()) + "---\n" + body
    parsed_fields, parsed_body = _parse_frontmatter(rendered, source="<test>")
    assert parsed_fields == fields
    assert parsed_body == body.strip()


@given(st.text())
@settings(max_examples=300)
def test_frontmatter_rejects_garbage_with_skill_load_error_only(text):
    try:
        fields, body = _parse_frontmatter(text, source="<test>")
    except SkillLoadError:
        return
    assert isinstance(fields, dict)
    assert isinstance(body, str)


# --------------------------------------------------------------------------- #
# web/finding_filters.py
# --------------------------------------------------------------------------- #

@given(st.one_of(st.none(), st.text(max_size=30)))
def test_normalize_severity_is_total_and_idempotent(value):
    out = normalize_severity(value)
    assert out == "" or out in _VALID_SEVERITIES
    assert normalize_severity(out) == out


@given(st.sampled_from(sorted(_VALID_SEVERITIES) + ["informational"]), st.text(alphabet=" \t", max_size=4))
def test_normalize_severity_ignores_case_and_padding(word, pad):
    assert normalize_severity(pad + word.upper() + pad) == normalize_severity(word)
