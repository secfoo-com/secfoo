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
    alphabet=st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="\n\r"),
    max_size=40,
).filter(lambda s: not s.lstrip().startswith("###"))


@given(
    headings=st.lists(st.tuples(st.one_of(tier_word, unknown_word), one_line), max_size=25),
    filler=st.lists(one_line, max_size=25),
)
def test_count_severities_counts_exactly_the_recognised_headings(headings, filler):
    lines = list(filler)
    expected = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for word, title in headings:
        lines.insert(len(lines) // 2, f"### [{word}] F: {title}")
        tier = TIERS.get(word.lower())
        if tier:
            expected[tier] += 1
    counts = count_severities("\n".join(lines))
    assert counts == SeverityCounts(**expected)
    assert counts.total == sum(expected.values())


@given(st.text())
@settings(max_examples=300)
def test_count_severities_never_raises(text):
    counts = count_severities(text)
    assert counts.total >= 0


@given(word=st.one_of(tier_word, unknown_word), before=st.text(max_size=80), after=st.text(max_size=80))
def test_overall_risk_rating_round_trips(word, before, after):
    # The marker is matched case-insensitively and the rating is lowercased.
    report = f"{before}\n**Overall risk rating:** {word}\n{after}"
    assert extract_overall_risk_rating(report) == word.lower()


@given(st.text())
def test_overall_risk_rating_never_raises(text):
    rating = extract_overall_risk_rating(text)
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
