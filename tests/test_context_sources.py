from __future__ import annotations

import pytest

from secfoo.context_sources import (
    ContextSourceError,
    looks_like_url,
    parse_context_source,
    resolve_context_sources,
)


def _resolve(*, config=(), confluence=(), context=(), target=None):
    return resolve_context_sources(
        from_config=list(config),
        from_confluence_flag=list(confluence),
        from_context_flag=list(context),
        target_dir=target,
    )


def test_https_url_is_accepted():
    source = parse_context_source("  https://acme.atlassian.net/wiki/spaces/SEC/pages/1  ")
    assert source.kind == "url"
    assert source.location == "https://acme.atlassian.net/wiki/spaces/SEC/pages/1"


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("http://wiki.example.com/page", "plain http://"),
        ("ftp://wiki.example.com/page", "unsupported URL scheme"),
        ("file:///etc/passwd", "unsupported URL scheme"),
        ("https://user:secret@wiki.example.com/page", "credentials"),
        ("https:///no-host", "no host"),
        ("https://wiki.example.com/a b", "whitespace"),
    ],
)
def test_unsafe_urls_are_rejected(value, message):
    with pytest.raises(ContextSourceError, match=message):
        parse_context_source(value)


def test_windows_drive_paths_are_not_urls():
    assert not looks_like_url("C:\\docs\\design.md")
    assert looks_like_url("https://example.com")


def test_empty_value_is_rejected():
    with pytest.raises(ContextSourceError, match="empty"):
        parse_context_source("   ")


def test_local_markdown_file_is_accepted(tmp_path):
    doc = tmp_path / "architecture.md"
    doc.write_text("# Design", encoding="utf-8")
    source = parse_context_source(str(doc))
    assert source.kind == "file"
    assert source.location == str(doc.resolve())


def test_local_directory_is_accepted(tmp_path):
    assert parse_context_source(str(tmp_path)).kind == "directory"


def test_unsupported_file_type_is_rejected(tmp_path):
    image = tmp_path / "diagram.png"
    image.write_bytes(b"\x89PNG")
    with pytest.raises(ContextSourceError, match="unsupported file type"):
        parse_context_source(str(image))


def test_missing_path_is_rejected(tmp_path):
    with pytest.raises(ContextSourceError, match="no such file"):
        parse_context_source(str(tmp_path / "missing.md"))


def test_file_inside_the_scanned_target_is_rejected(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    doc = target / "design.md"
    doc.write_text("x", encoding="utf-8")
    with pytest.raises(ContextSourceError, match="inside the scanned target"):
        _resolve(context=[str(doc)], target=target)


def test_folder_containing_the_scanned_target_is_rejected(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    with pytest.raises(ContextSourceError, match="contains the scanned target"):
        _resolve(context=[str(tmp_path)], target=target)


def test_document_next_to_the_target_is_accepted(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    doc = tmp_path / "design.md"
    doc.write_text("x", encoding="utf-8")
    assert [s.kind for s in _resolve(context=[str(doc)], target=target)] == ["file"]


def test_sources_merge_in_order_and_drop_duplicates():
    a = "https://wiki.example.com/a"
    b = "https://wiki.example.com/b"
    c = "https://wiki.example.com/c"
    merged = _resolve(config=[a], confluence=[b], context=[a, c])
    assert [s.location for s in merged] == [a, b, c]


def test_same_local_file_written_two_ways_is_one_source(tmp_path):
    (tmp_path / "sub").mkdir()
    doc = tmp_path / "design.md"
    doc.write_text("x", encoding="utf-8")
    roundabout = tmp_path / "sub" / ".." / "design.md"
    assert len(_resolve(context=[str(doc), str(roundabout)])) == 1


def test_error_names_where_the_bad_value_came_from():
    with pytest.raises(ContextSourceError, match=r"--context 'http://x\.example/a': plain http://"):
        _resolve(context=["http://x.example/a"])
    with pytest.raises(ContextSourceError, match="defaults.context"):
        _resolve(config=["http://x.example/a"])
    with pytest.raises(ContextSourceError, match="--confluence"):
        _resolve(confluence=["http://x.example/a"])


def test_scheme_less_url_gets_a_hint():
    with pytest.raises(ContextSourceError, match="needs the https:// prefix"):
        parse_context_source("wiki.example.com/some/page")

