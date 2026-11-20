"""Guards against documentation drifting away from the code it describes."""

from __future__ import annotations

import inspect
import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# "tag push", "tag-push", "Tag push", "on every vX.Y.Z tag" ... unless negated.
_TAG_PUSH_CLAIM = re.compile(r"tag[- ]push|on every `?v?X\.Y\.Z`? tag", re.IGNORECASE)
_NEGATED = re.compile(r"\bnot\b[^.]{0,40}$", re.IGNORECASE)


def _has_push_trigger(on_block: str) -> bool:
    """`push` as a trigger: the inline value (`on: push`, `on: [push, ...]`)
    or a block-form key (`  push:`). Comments and descriptions don't count."""
    inline, _, body = on_block.partition("\n")
    if re.search(r"\bpush\b", inline.split("#", 1)[0]):
        return True
    return bool(re.search(r"^[ \t]+push[ \t]*:", body, re.MULTILINE))


def _top_level_on_block(workflow: str) -> str:
    """The workflow's `on:` block: from `on:` to the next top-level key,
    blank lines and comments included (a blank line must not end it)."""
    match = re.search(r'^["\']?on["\']?:[ \t]*(.*)\n((?:(?:[ \t]+.*|[ \t]*|#.*)\n)*)', workflow, re.MULTILINE)
    assert match, "release.yml has no top-level `on:` key"
    return match.group(1) + "\n" + match.group(2)


def test_release_workflow_is_manual_only() -> None:
    """The release workflow is workflow_dispatch only; any push trigger
    (block form, flow form, or after a blank line) fails this test."""
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    triggers = _top_level_on_block(workflow)
    assert "workflow_dispatch" in triggers
    assert not _has_push_trigger(triggers), triggers


def test_docs_do_not_claim_the_release_runs_on_tag_push() -> None:
    files = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").rglob("*.md"))]
    offenders = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for match in _TAG_PUSH_CLAIM.finditer(line):
                if not _NEGATED.search(line[: match.start()]):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert offenders == []


def test_the_on_block_parser_sees_triggers_after_a_blank_line() -> None:
    workflow = "name: R\non:\n  workflow_dispatch:\n    inputs: {}\n\n  push:\n    tags: ['v*']\njobs: {}\n"
    assert _has_push_trigger(_top_level_on_block(workflow))
    assert _has_push_trigger(_top_level_on_block('"on": [push, workflow_dispatch]\njobs: {}\n'))
    commented = "on:\n  workflow_dispatch:\n\n# the GHCR push needs packages: write\njobs: {}\n"
    assert not _has_push_trigger(_top_level_on_block(commented))


def _project() -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib

    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def test_no_obsolete_api_extra() -> None:
    """litellm and langgraph are base dependencies, so `secfoo[api]` must not come back."""
    project = _project()
    assert "api" not in project.get("optional-dependencies", {})
    base = {re.split(r"[\s<>=!~;\[]", dep, maxsplit=1)[0].lower() for dep in project["dependencies"]}
    assert {"litellm", "langgraph"} <= base

    files = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "action.yml", ROOT / "Dockerfile",
             *sorted((ROOT / "docs").rglob("*.md")), *sorted((ROOT / "src").rglob("*.py")),
             *sorted((ROOT / "npm").rglob("*.md")), *sorted((ROOT / "examples").rglob("*.yml"))]
    files = [path for path in files if path.is_file()]
    offenders = [str(path.relative_to(ROOT)) for path in files if "secfoo[api]" in path.read_text(encoding="utf-8")]
    assert offenders == []


def test_product_description_is_the_same_everywhere() -> None:
    """The Typer help, CITATION.cff abstract and PyPI description tell one story."""
    from secfoo.cli import app

    description = _project()["description"]
    abstract = re.search(r'^abstract:\s*"(.*)"\s*$', (ROOT / "CITATION.cff").read_text(encoding="utf-8"), re.MULTILINE)
    assert abstract, "CITATION.cff has no abstract"
    assert abstract.group(1) == description
    assert app.info.help
    assert description.startswith(app.info.help.rstrip("."))
    # `secfoo --help` can show the root callback's docstring instead of Typer(help=...).
    assert inspect.getdoc(app.registered_callback.callback) == app.info.help
    # The npm package page is the third public listing.
    npm = json.loads((ROOT / "npm/secfoo/package.json").read_text(encoding="utf-8"))
    assert npm["description"] == description
    for path in (ROOT / "src/secfoo/cli.py", ROOT / "CITATION.cff", ROOT / "npm/secfoo/package.json",
                 ROOT / "npm/secfoo/README.md"):
        assert "Context-based security architectural assessment" not in path.read_text(encoding="utf-8"), path


# --- packaging drift (#120) -------------------------------------------------

_OBSOLETE_ORG_REFS = re.compile(r"github\.com/rakfortltd|raw\.githubusercontent\.com/rakfortltd|ghcr\.io/rakfortltd|REPO=\"rakfortltd|Repo = \"rakfortltd")


def _tracked_text_files() -> list[Path]:
    """Text files git tracks, so a local .venv, build/ or dist/ can't produce
    false hits; fuzz reproducers and test fixtures are deliberately odd bytes."""
    suffixes = {".md", ".sh", ".ps1", ".yml", ".yaml", ".json", ".cff", ".toml"}
    names = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    paths = [ROOT / name for name in names.decode().split("\0") if name]
    return [p for p in paths
            if (p.suffix in suffixes or p.name == "Dockerfile") and p.is_file()
            and not p.relative_to(ROOT).as_posix().startswith(("fuzz/corpus/", "tests/fixtures/"))
            and p.resolve() != Path(__file__).resolve()]


def test_no_references_to_the_old_github_org_or_image() -> None:
    """Repo URLs, the installers and the image live under secfoo-com; the npm
    scope `@rakfortltd/` is a published package name and is allowed."""
    files = _tracked_text_files()
    assert any(p.name == "install.sh" for p in files) and any(p.name == "Dockerfile" for p in files)
    offenders = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if _OBSOLETE_ORG_REFS.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert offenders == []


def _check_pypi_version():
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_pypi_version", ROOT / "scripts/check_pypi_version.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_about_version_is_pep440_and_not_behind_the_last_tagged_release() -> None:
    check = _check_pypi_version()
    local = check.local_version()
    check.parse(local)  # raises on anything the release check can't compare
    tags = subprocess.run(["git", "tag", "--list", "v*"], cwd=ROOT, capture_output=True, text=True, check=False).stdout.split()
    for tag in tags:
        assert check.parse(local) >= check.parse(tag[1:]), f"__about__.py {local} is behind tag {tag}"


@pytest.mark.parametrize(("lower", "higher"), [
    ("0.3.0", "0.3.1"), ("0.3.1", "0.3.2.dev0"), ("0.3.2.dev0", "0.3.2a1"), ("0.3.2a1", "0.3.2rc1"),
    ("0.3.2rc1", "0.3.2"), ("0.3.2", "0.3.2.post1"), ("0.3.9", "0.3.10"), ("0.9", "0.10.0"),
])
def test_version_check_orders_like_pep440(lower, higher) -> None:
    parse = _check_pypi_version().parse
    assert parse(lower) < parse(higher)


def test_version_check_treats_trailing_zeros_as_equal() -> None:
    parse = _check_pypi_version().parse
    assert parse("0.3") == parse("0.3.0")
