from __future__ import annotations

import pytest

from secfoo.context_sources import (
    ContextSourceError,
    https_url_problem,
    looks_like_url,
    parse_context_source,
    resolve_context_sources,
)
from secfoo.skills.renderer import _https_page_urls
from secfoo.web.templating import https_url


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


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://example.com/valid/path",
        "  https://sub.domain.org/page?query=1#frag  ",
        "http://insecure.example.com/page",
        "https://user:pass@example.com/page",
        "https://example.com/with space",
        "https://example.com/with\\backslash",
        "https:///no-host",
        "ftp://example.com/resource",
        "",
        "   ",
        "not a url",
    ],
)
def test_https_url_problem_consistency(raw_url):
    problem = https_url_problem(raw_url)
    filtered_renderer = _https_page_urls([raw_url])
    filtered_templating = https_url(raw_url)

    if problem is None:
        assert len(filtered_renderer) == 1
        assert filtered_renderer[0] == raw_url.strip()
        assert filtered_templating == raw_url.strip()
    else:
        assert len(filtered_renderer) == 0
        assert filtered_templating == ""


def test_symlink_inside_target_is_rejected(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    outside_doc = tmp_path / "doc.md"
    outside_doc.write_text("content", encoding="utf-8")
    link_inside = target / "link_to_doc.md"
    try:
        link_inside.symlink_to(outside_doc)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")

    with pytest.raises(ContextSourceError, match="inside the scanned target"):
        _resolve(context=[str(link_inside)], target=target)


def test_symlinked_target_alias_is_rejected(tmp_path):
    target = tmp_path / "real_repo"
    target.mkdir()
    target_alias = tmp_path / "repo_alias"
    try:
        target_alias.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")

    doc = target / "design.md"
    doc.write_text("content", encoding="utf-8")

    with pytest.raises(ContextSourceError, match="inside the scanned target"):
        _resolve(context=[str(doc)], target=target_alias)


def test_sibling_directory_sharing_prefix_is_accepted(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    sibling = tmp_path / "project-docs"
    sibling.mkdir()
    doc = sibling / "arch.md"
    doc.write_text("design", encoding="utf-8")

    sources = _resolve(context=[str(doc), str(sibling)], target=target)
    assert len(sources) == 2


def test_case_insensitive_target_overlap_is_rejected(tmp_path):
    target = tmp_path / "MyProject"
    target.mkdir()
    test_file = target / "test.txt"
    test_file.write_text("x", encoding="utf-8")
    case_variant = tmp_path / "myproject" / "test.txt"
    if not case_variant.exists():
        pytest.skip("Filesystem is case-sensitive")

    doc = tmp_path / "myproject" / "design.md"
    doc.write_text("design", encoding="utf-8")
    with pytest.raises(ContextSourceError, match="inside the scanned target"):
        _resolve(context=[str(doc)], target=target)



def test_symlinked_folder_inside_target_is_rejected(tmp_path):
    """A folder symlink planted in the untrusted target (docs -> ~/Documents)
    must not let the scanned repo choose which local files are inlined."""
    target = tmp_path / "repo"
    target.mkdir()
    private = tmp_path / "Documents"
    private.mkdir()
    (private / "secret.md").write_text("LEAKED", encoding="utf-8")
    link = target / "docs"
    try:
        link.symlink_to(private, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")
    with pytest.raises(ContextSourceError, match="inside the scanned target"):
        _resolve(context=[str(link)], target=target)
    with pytest.raises(ContextSourceError, match="inside the scanned target"):
        _resolve(context=[str(link / "secret.md")], target=target)


def test_a_symlink_outside_the_target_is_still_allowed(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.md").write_text("ok", encoding="utf-8")
    link = tmp_path / "docs-link"
    try:
        link.symlink_to(docs, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")
    [source] = _resolve(context=[str(link)], target=target)
    assert source.kind == "directory"
