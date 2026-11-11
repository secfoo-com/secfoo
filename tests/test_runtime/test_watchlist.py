"""#52: vulnerable-function watchlist built from cached OSV records (no network)."""
from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secfoo.cli import app
from secfoo.runtime import watchlist
from secfoo.runtime.watchlist import build_watchlist, normalize_symbol
from secfoo.storage.repository import RunRepository

# Fixture OSV records, trimmed to the fields the builder reads.
GO_VULN = {
    "id": "GO-2023-1571", "aliases": ["CVE-2022-41723", "GHSA-vvpx-j8f3-3w6h"],
    "affected": [{
        "package": {"ecosystem": "Go", "name": "golang.org/x/net"},
        "ecosystem_specific": {"imports": [
            {"path": "golang.org/x/net/http2/hpack", "symbols": ["Decoder.DecodeFull", "Decoder.Write"]},
            {"path": "golang.org/x/net/http2", "symbols": ["Server.ServeConn"]},
        ]},
    }],
}
RUST_VULN = {
    "id": "RUSTSEC-2021-0078", "aliases": ["CVE-2021-32715", "GHSA-f3pg-qwvg-p99c"],
    "affected": [{
        "package": {"ecosystem": "crates.io", "name": "hyper"},
        "ecosystem_specific": {"affects": {"functions": ["hyper::proto::h1::role::parse_headers"]}},
    }],
}
PYYAML_VULN = {  # PyPI advisories rarely carry symbols in OSV
    "id": "GHSA-8q59-q68h-6hv4", "aliases": ["CVE-2020-14343"],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "pyyaml"}}],
}
PYYAML_OTHER = {"id": "PYSEC-2021-142", "aliases": ["CVE-2020-1747"], "affected": [{"package": {"ecosystem": "PyPI", "name": "pyyaml"}}]}
BAD_SYMBOL_VULN = {
    "id": "GO-2099-0001",
    "affected": [{"package": {"ecosystem": "Go", "name": "example.com/lib"},
                  "ecosystem_specific": {"imports": [{"path": "example.com/lib", "symbols": ["not a symbol!"]}]}}],
}


@pytest.fixture
def repo(tmp_path):
    with RunRepository(db_path=tmp_path / "db.sqlite") as repo:
        yield repo


def _finding(repo, pid, run_id, fp, package, ecosystem, version, cve="unverified", status="open"):
    repo.upsert_sca_finding(project_id=pid, fingerprint=fp, run_id=run_id, current_ref="D1", package=package,
                            severity="high", ecosystem=ecosystem, version=version, cve=cve)
    if status == "closed":
        repo.connection.execute("UPDATE sca_findings SET status='closed' WHERE fingerprint=?", (fp,))
        repo.connection.commit()


@pytest.fixture
def project(repo):
    pid = repo.upsert_project("https://github.com/acme/app", "app", "github")
    run_id = repo.get_run(repo.create_run(project_id=pid, skill_id="sca-reachability", skill_name="SCA",
                                          agent_id="claude", confluence_urls=[])).id
    repo.upsert_osv_lookup(ecosystem="Go", package="golang.org/x/net", version="0.6.0", vulns=[GO_VULN])
    repo.upsert_osv_lookup(ecosystem="crates.io", package="hyper", version="0.14.9", vulns=[RUST_VULN])
    repo.upsert_osv_lookup(ecosystem="PyPI", package="pyyaml", version="5.3", vulns=[PYYAML_VULN, PYYAML_OTHER])
    _finding(repo, pid, run_id, "fp-go", "golang.org/x/net", "Go", "0.6.0")
    _finding(repo, pid, run_id, "fp-rust", "hyper", "Rust", "0.14.9", cve="CVE-2021-32715")
    _finding(repo, pid, run_id, "fp-yaml", "pyyaml", "Python", "5.3", cve="CVE-2020-14343")
    _finding(repo, pid, run_id, "fp-nocache", "left-pad", "npm", "1.0.0")
    _finding(repo, pid, run_id, "fp-closed", "requests", "Python", "2.0.0", status="closed")
    return pid


def _by_fp(document):
    out = {}
    for entry in document["entries"]:
        out.setdefault(entry["finding_fingerprint"], []).append(entry)
    return out


def test_osv_go_import_symbols_become_importpath_qualified_symbols(repo, project):
    [entry] = _by_fp(build_watchlist(repo, project)[0])["fp-go"]
    assert entry["granularity"] == "symbol" and entry["source"] == "osv"
    assert entry["symbols"] == [
        "golang.org/x/net/http2.Server.ServeConn",
        "golang.org/x/net/http2/hpack.Decoder.DecodeFull",
        "golang.org/x/net/http2/hpack.Decoder.Write",
    ]
    assert entry["advisory"] == "GHSA-vvpx-j8f3-3w6h"  # GHSA id preferred over the OSV id
    assert (entry["ecosystem"], entry["package"], entry["version"]) == ("Go", "golang.org/x/net", "0.6.0")


def test_rustsec_affected_functions_are_used(repo, project):
    [entry] = _by_fp(build_watchlist(repo, project)[0])["fp-rust"]
    assert entry["symbols"] == ["hyper::proto::h1::role::parse_headers"]
    assert entry["ecosystem"] == "crates.io"  # report's "Rust" normalised to OSV's vocabulary


def test_no_symbols_falls_back_to_package_granularity_for_the_named_advisory(repo, project):
    [entry] = _by_fp(build_watchlist(repo, project)[0])["fp-yaml"]
    assert entry["granularity"] == "package" and entry["symbols"] == [] and entry["source"] == "package"
    assert entry["advisory"] == "GHSA-8q59-q68h-6hv4"  # only the CVE the finding named, not PYSEC-2021-142


def test_finding_without_cached_osv_data_is_kept_at_package_granularity(repo, project):
    [entry] = _by_fp(build_watchlist(repo, project)[0])["fp-nocache"]
    assert entry["granularity"] == "package" and entry["advisory"] is None


def test_only_open_findings_are_listed(repo, project):
    assert "fp-closed" not in _by_fp(build_watchlist(repo, project)[0])


def test_unverified_finding_gets_every_advisory_for_its_version(repo, project):
    repo.connection.execute("UPDATE sca_findings SET cve='unverified' WHERE fingerprint='fp-yaml'")
    repo.connection.commit()
    advisories = {e["advisory"] for e in _by_fp(build_watchlist(repo, project)[0])["fp-yaml"]}
    assert advisories == {"GHSA-8q59-q68h-6hv4", "PYSEC-2021-142"}


def test_symbols_that_dont_fit_the_notation_are_dropped_but_the_entry_is_kept(repo, project):
    pid = project
    run_id = repo.list_sca_findings(project_id=pid)[0].first_seen_run_id
    repo.upsert_osv_lookup(ecosystem="Go", package="example.com/lib", version="1.0.0", vulns=[BAD_SYMBOL_VULN])
    _finding(repo, pid, run_id, "fp-bad", "example.com/lib", "Go", "1.0.0")
    document, notes = build_watchlist(repo, pid)
    [entry] = _by_fp(document)["fp-bad"]
    assert entry["granularity"] == "package" and entry["symbols"] == []
    assert any("didn't fit" in n for n in notes)


def test_unrecognised_ecosystem_is_kept_and_noted(repo, project):
    run_id = repo.list_sca_findings(project_id=project)[0].first_seen_run_id
    _finding(repo, project, run_id, "fp-alpine", "musl", "Alpine", "1.2.3")
    document, notes = build_watchlist(repo, project)
    [entry] = _by_fp(document)["fp-alpine"]
    assert entry["granularity"] == "package" and entry["ecosystem"] == "Alpine"
    assert any("isn't recognised" in n for n in notes)


# ---------- optional GitHub advisory source ----------


def test_ghsa_source_fills_symbols_when_osv_has_none(repo, project):
    calls = []

    def fake_fetch(url):
        calls.append(url)
        return {"vulnerabilities": [{"package": {"ecosystem": "pip", "name": "PyYAML"},
                                     "vulnerable_functions": ["yaml.load", "yaml.full_load"]}]}

    [entry] = _by_fp(build_watchlist(repo, project, github_fetch=fake_fetch)[0])["fp-yaml"]
    assert entry["source"] == "ghsa" and entry["symbols"] == ["yaml.full_load", "yaml.load"]
    assert calls == ["https://api.github.com/advisories/GHSA-8q59-q68h-6hv4"]  # OSV symbols already covered Go/Rust


def test_ghsa_rate_limit_stops_further_calls_and_is_noted(repo, project):
    repo.connection.execute("UPDATE sca_findings SET cve='unverified' WHERE fingerprint='fp-yaml'")
    repo.connection.commit()
    calls = []

    def limited(url):
        calls.append(url)
        raise urllib.error.HTTPError(url, 403, "rate limited", {}, io.BytesIO())

    document, notes = build_watchlist(repo, project, github_fetch=limited)
    assert len(calls) == 1  # stopped after the first limit
    assert all(e["granularity"] == "package" for e in _by_fp(document)["fp-yaml"])
    assert any("rate limit" in n for n in notes)


def test_no_network_by_default(repo, project, monkeypatch):
    monkeypatch.setattr(watchlist.urllib.request, "urlopen", lambda *a, **k: pytest.fail("no network by default"))
    build_watchlist(repo, project)


# ---------- notation ----------


@pytest.mark.parametrize("ecosystem, symbol", [
    ("PyPI", "yaml.load"), ("npm", "lodash#template"), ("npm", "@babel/core#transform"),
    ("Maven", "org.apache.logging.log4j.core.lookup.JndiLookup#lookup"),
    ("NuGet", "System.Text.Json.JsonSerializer#Deserialize"), ("Go", "golang.org/x/net/html.Parse"),
    ("Go", "golang.org/x/net/http2.Server.ServeConn"), ("crates.io", "hyper::proto::h1::role::parse_headers"),
    ("RubyGems", "Nokogiri::XML::Document.parse"), ("RubyGems", "Rack::Request#params"),
    ("Packagist", "Symfony\\Component\\Yaml\\Yaml::parse"), ("Packagist", "unserialize"),
])
def test_issue_examples_fit_their_notation(ecosystem, symbol):
    assert normalize_symbol(ecosystem, symbol) == symbol


@pytest.mark.parametrize("ecosystem, symbol", [
    ("PyPI", "load"), ("PyPI", "yaml load"), ("npm", "lodash.template"), ("Maven", "JndiLookup.lookup"),
    ("crates.io", "parse_headers"), ("Go", "Parse"), ("Unknown", "a.b"),
])
def test_symbols_outside_the_notation_are_rejected(ecosystem, symbol):
    assert normalize_symbol(ecosystem, symbol) is None


# ---------- schema + CLI ----------


def test_output_matches_the_json_schema(repo, project):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((Path(watchlist.__file__).parent / "watchlist.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    document = build_watchlist(repo, project)[0]
    jsonschema.Draft202012Validator(schema).validate(document)
    bad = {**document, "entries": [{**document["entries"][0], "granularity": "package", "symbols": ["x.y"]}]}
    assert not jsonschema.Draft202012Validator(schema).is_valid(bad)


def test_cli_writes_the_watchlist(tmp_path, monkeypatch, project, repo):
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda: RunRepository(db_path=repo.db_path))
    out = tmp_path / "watchlist.json"
    result = CliRunner().invoke(app, ["runtime", "watchlist", "--project", "app", "-o", str(out)])
    assert result.exit_code == 0, result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["version"] == 1 and len(document["entries"]) == 4
    assert "4 watchlist entries: 2 with symbols, 2 at package granularity" in result.output


def test_cli_unknown_project(tmp_path, monkeypatch, repo):
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda: RunRepository(db_path=repo.db_path))
    result = CliRunner().invoke(app, ["runtime", "watchlist", "--project", "nope"])
    assert result.exit_code == 1 and "no single project matches" in result.output
