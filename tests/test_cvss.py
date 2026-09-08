from __future__ import annotations

import pytest

from secfoo.cvss import CvssError, base_score, parse_vector, rating

# Real published CVSS v3.1 base vectors, hand-verified against the
# FIRST.org spec's own Impact/Exploitability formula (not trusted from any
# secondary source) -- see cvss.py's module docstring for why these numbers
# matter: the LLM never asserts a score directly, only these vectors.
_VECTORS = [
    # The canonical "worst case with Scope Unchanged" vector widely cited
    # as the maximum achievable base score of 9.8 when S:U -- 10.0 is only
    # reachable with Scope Changed (see below).
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "critical"),
    # Scope-changed branch: 1.08x multiplier pushes this to the true 10.0 cap.
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
    # Exercises the PR weight and an unauthenticated-availability-only impact.
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5, "medium"),
]


@pytest.mark.parametrize("vector,expected_score,expected_rating", _VECTORS)
def test_base_score_matches_published_vectors(vector, expected_score, expected_rating):
    score = base_score(vector)
    assert score == expected_score
    assert rating(score) == expected_rating


def test_base_score_zero_impact_is_none_rated():
    score = base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0
    assert rating(score) == "none"


def test_parse_vector_strips_official_cvss_prefix():
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N") == {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N",
    }


def test_parse_vector_works_without_any_prefix():
    metrics = parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
    assert metrics["AV"] == "N"


def test_parse_vector_rejects_missing_metric():
    with pytest.raises(CvssError, match="A"):
        parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")


def test_parse_vector_rejects_empty_string():
    with pytest.raises(CvssError):
        parse_vector("")


def test_parse_vector_rejects_unrecognized_metric_value():
    with pytest.raises(CvssError, match="AV"):
        parse_vector("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")


def test_parse_vector_rejects_unrecognized_scope_value():
    with pytest.raises(CvssError):
        parse_vector("AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:N")


def test_base_score_raises_on_malformed_vector_rather_than_guessing():
    with pytest.raises(CvssError):
        base_score("not a vector")


def test_rating_bands_match_first_org_thresholds():
    assert rating(0.0) == "none"
    assert rating(0.1) == "low"
    assert rating(3.9) == "low"
    assert rating(4.0) == "medium"
    assert rating(6.9) == "medium"
    assert rating(7.0) == "high"
    assert rating(8.9) == "high"
    assert rating(9.0) == "critical"
    assert rating(10.0) == "critical"
