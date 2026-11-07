from datetime import date

from secfoo.web import finding_filters as ff


def test_normalize_severity():
    assert ff.normalize_severity("High") == "high"
    assert ff.normalize_severity(" CRITICAL ") == "critical"
    assert ff.normalize_severity("Informational") == "info"
    assert ff.normalize_severity("bogus") == ""
    assert ff.normalize_severity(None) == ""


def test_in_day_range_is_inclusive_and_open_ended():
    ts = "2026-10-09T22:24:40+00:00"
    assert ff.in_day_range(ts, None, None)
    assert ff.in_day_range(ts, date(2026, 10, 9), date(2026, 10, 9))
    assert ff.in_day_range(ts, date(2026, 10, 1), None)
    assert not ff.in_day_range(ts, date(2026, 10, 10), None)
    assert not ff.in_day_range(ts, None, date(2026, 10, 8))
    assert not ff.in_day_range(None, date(2026, 10, 1), None)


def test_query_string_drops_empty_values_and_encodes():
    assert ff.query_string(status="open", q="a&b", severity="", project_id=None) == "status=open&q=a%26b"
