from __future__ import annotations

import json
import urllib.error

import pytest

from secfoo import osv
from secfoo.storage.repository import RunRepository


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def fake_urlopen(monkeypatch):
    """Configures `urllib.request.urlopen` inside secfoo.osv to either
    return one fixed outcome for every call, or consume a queue of
    per-call outcomes (dict payload or an Exception instance) in order --
    needed for enrich_lookups tests where different keys get different
    results. Records every Request object seen.
    """
    calls = []

    def _install(*, response: dict | None = None, raises: Exception | None = None, sequence: list | None = None):
        queue = list(sequence) if sequence is not None else None

        def _fake_urlopen(request, timeout=None):
            calls.append(request)
            if queue is not None:
                outcome = queue.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                return _FakeResponse(outcome)
            if raises is not None:
                raise raises
            return _FakeResponse(response if response is not None else {})

        monkeypatch.setattr("secfoo.osv.urllib.request.urlopen", _fake_urlopen)
        return calls

    return _install


def _repo(tmp_path):
    return RunRepository(db_path=tmp_path / "db.sqlite")


# ---------------------------------------------------------------------------
# normalize_ecosystem
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Python", "PyPI"),
        ("python", "PyPI"),
        ("PyPI", "PyPI"),
        ("Node.js", "npm"),
        ("npm", "npm"),
        ("JavaScript", "npm"),
        ("Java", "Maven"),
        (".NET", "NuGet"),
        ("Go", "Go"),
        ("Rust", "crates.io"),
        ("Ruby", "RubyGems"),
        ("PHP", "Packagist"),
    ],
)
def test_normalize_ecosystem_recognizes_common_values(raw, expected):
    assert osv.normalize_ecosystem(raw) == expected


@pytest.mark.parametrize("raw", ["Alpine", "Debian", "Homebrew", "some made up thing", "", None])
def test_normalize_ecosystem_never_guesses_unrecognized_values(raw):
    assert osv.normalize_ecosystem(raw) is None


# ---------------------------------------------------------------------------
# query_osv
# ---------------------------------------------------------------------------


def test_query_osv_returns_vulns_on_match(fake_urlopen):
    fake_urlopen(response={"vulns": [{"id": "CVE-2022-33124", "summary": "Invalid IPv6 URL"}]})
    result = osv.query_osv("PyPI", "aiohttp", "3.8.0")
    assert result == [{"id": "CVE-2022-33124", "summary": "Invalid IPv6 URL"}]


def test_query_osv_returns_empty_list_when_no_vulns_field(fake_urlopen):
    fake_urlopen(response={})  # OSV omits "vulns" entirely for a clean package
    assert osv.query_osv("PyPI", "some-safe-package", "1.0.0") == []


def test_query_osv_sends_expected_request_body(fake_urlopen):
    calls = fake_urlopen(response={"vulns": []})
    osv.query_osv("npm", "left-pad", "1.3.0")
    assert len(calls) == 1
    request = calls[0]
    assert request.full_url == osv.OSV_API_URL
    body = json.loads(request.data.decode("utf-8"))
    assert body == {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.3.0"}


def test_query_osv_wraps_http_error(fake_urlopen):
    fake_urlopen(raises=urllib.error.HTTPError("url", 500, "Server Error", {}, None))
    with pytest.raises(osv.OsvError):
        osv.query_osv("PyPI", "aiohttp", "3.8.0")


def test_query_osv_wraps_url_error(fake_urlopen):
    fake_urlopen(raises=urllib.error.URLError("Connection refused"))
    with pytest.raises(osv.OsvError):
        osv.query_osv("PyPI", "aiohttp", "3.8.0")


# ---------------------------------------------------------------------------
# enrich_lookups
# ---------------------------------------------------------------------------


def test_enrich_lookups_empty_keys_is_a_noop(tmp_path, fake_urlopen):
    calls = fake_urlopen(response={"vulns": []})
    repo = _repo(tmp_path)
    hit_failure = osv.enrich_lookups(repo, [])
    assert hit_failure is False
    assert calls == []
    repo.close()


def test_enrich_lookups_queries_and_caches_uncached_keys(tmp_path, fake_urlopen):
    fake_urlopen(sequence=[
        {"vulns": [{"id": "CVE-2022-33124"}]},
        {"vulns": []},
    ])
    repo = _repo(tmp_path)
    hit_failure = osv.enrich_lookups(repo, [("PyPI", "aiohttp", "3.8.0"), ("npm", "left-pad", "1.3.0")])
    assert hit_failure is False

    lookup_map = repo.osv_lookup_map()
    assert lookup_map[("PyPI", "aiohttp", "3.8.0")].vulns == [{"id": "CVE-2022-33124"}]
    assert lookup_map[("npm", "left-pad", "1.3.0")].vulns == []
    repo.close()


def test_enrich_lookups_skips_already_fresh_entries(tmp_path, fake_urlopen):
    calls = fake_urlopen(response={"vulns": []})
    repo = _repo(tmp_path)
    repo.upsert_osv_lookup(ecosystem="PyPI", package="aiohttp", version="3.8.0", vulns=[{"id": "CVE-2022-33124"}])

    hit_failure = osv.enrich_lookups(repo, [("PyPI", "aiohttp", "3.8.0")])
    assert hit_failure is False
    assert calls == []  # never queried -- already fresh in the cache
    # Original cached value untouched.
    assert repo.osv_lookup_map()[("PyPI", "aiohttp", "3.8.0")].vulns == [{"id": "CVE-2022-33124"}]
    repo.close()


def test_enrich_lookups_requeries_stale_entries(tmp_path, fake_urlopen):
    import datetime as dt

    calls = fake_urlopen(response={"vulns": [{"id": "NEW-CVE"}]})
    repo = _repo(tmp_path)
    repo.upsert_osv_lookup(ecosystem="PyPI", package="aiohttp", version="3.8.0", vulns=[])
    stale_time = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).isoformat()
    repo._conn.execute(
        "UPDATE osv_lookups SET queried_at = ? WHERE ecosystem='PyPI' AND package='aiohttp' AND version='3.8.0'",
        (stale_time,),
    )
    repo._conn.commit()

    hit_failure = osv.enrich_lookups(repo, [("PyPI", "aiohttp", "3.8.0")])
    assert hit_failure is False
    assert len(calls) == 1
    assert repo.osv_lookup_map()[("PyPI", "aiohttp", "3.8.0")].vulns == [{"id": "NEW-CVE"}]
    repo.close()


def test_enrich_lookups_deduplicates_repeated_keys(tmp_path, fake_urlopen):
    calls = fake_urlopen(response={"vulns": []})
    repo = _repo(tmp_path)
    osv.enrich_lookups(repo, [("PyPI", "aiohttp", "3.8.0"), ("PyPI", "aiohttp", "3.8.0")])
    assert len(calls) == 1
    repo.close()


def test_enrich_lookups_respects_budget(tmp_path, fake_urlopen):
    calls = fake_urlopen(response={"vulns": []})
    repo = _repo(tmp_path)
    keys = [("PyPI", f"pkg{i}", "1.0.0") for i in range(10)]
    osv.enrich_lookups(repo, keys, budget=3)
    assert len(calls) == 3
    repo.close()


def test_enrich_lookups_aborts_pass_on_first_connection_failure(tmp_path, fake_urlopen):
    """A timeout/URLError almost always means OSV is unreachable for the
    whole pass, not that one row is special -- must stop immediately
    rather than burning the rest of the budget re-discovering the same
    outage one request at a time.
    """
    calls = fake_urlopen(sequence=[urllib.error.URLError("Connection refused")])
    repo = _repo(tmp_path)
    keys = [("PyPI", f"pkg{i}", "1.0.0") for i in range(5)]
    hit_failure = osv.enrich_lookups(repo, keys)
    assert hit_failure is True
    assert len(calls) == 1  # exactly 1 of 5 attempted, not all 5
    assert repo.osv_lookup_map() == {}
    repo.close()


def test_enrich_lookups_http_error_also_aborts_pass(tmp_path, fake_urlopen):
    calls = fake_urlopen(sequence=[urllib.error.HTTPError("url", 503, "Unavailable", {}, None)])
    repo = _repo(tmp_path)
    keys = [("PyPI", f"pkg{i}", "1.0.0") for i in range(5)]
    hit_failure = osv.enrich_lookups(repo, keys)
    assert hit_failure is True
    assert len(calls) == 1
    repo.close()
