from __future__ import annotations

import pytest

from secfoo.targets.resolver import (
    TargetKind,
    TargetResolutionError,
    is_github_url,
    resolve_target,
)


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/org/repo", True),
        ("http://github.com/org/repo", True),
        ("git@github.com:org/repo.git", True),
        ("https://gitlab.com/org/repo", False),
        ("/some/local/path", False),
    ],
)
def test_is_github_url(url, expected):
    assert is_github_url(url) is expected


def test_resolve_target_defaults_to_cwd(tmp_path):
    resolved = resolve_target(None, cwd=tmp_path)
    assert resolved.kind == TargetKind.LOCAL
    assert resolved.path == tmp_path.resolve()
    assert resolved.is_temporary is False


def test_resolve_target_github_url_has_no_path_yet():
    resolved = resolve_target("https://github.com/org/repo")
    assert resolved.kind == TargetKind.GITHUB
    assert resolved.path is None
    assert resolved.is_temporary is True
    assert resolved.display_name == "https://github.com/org/repo"


def test_resolve_target_local_dir(tmp_path):
    resolved = resolve_target(str(tmp_path))
    assert resolved.kind == TargetKind.LOCAL
    assert resolved.path == tmp_path.resolve()


def test_resolve_target_missing_dir_raises(tmp_path):
    with pytest.raises(TargetResolutionError):
        resolve_target(str(tmp_path / "does-not-exist"))
