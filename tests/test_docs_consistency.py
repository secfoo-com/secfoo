"""Guard against documentation, CLI metadata, and packaging drift (#120)."""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from typer.testing import CliRunner

from secfoo import __version__
from secfoo.cli import app

REPO_ROOT = Path(__file__).resolve().parent.parent


def _doc_files() -> list[Path]:
    return [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.md"))]


def test_no_obsolete_secfoo_api_extra():
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = pyproject["project"].get("optional-dependencies", {})
    assert "api" not in extras, "litellm/langgraph are base dependencies; remove empty [api] extra"

    deps = pyproject["project"]["dependencies"]
    assert any(d.startswith("litellm") for d in deps)
    assert any(d.startswith("langgraph") for d in deps)

    paths = [*_doc_files(), REPO_ROOT / "pyproject.toml", *sorted((REPO_ROOT / "src" / "secfoo").rglob("*.py"))]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "secfoo[api]" not in text, f"obsolete secfoo[api] reference in {path.relative_to(REPO_ROOT)}"


def test_no_obsolete_rakfortltd_repo_or_ghcr_urls():
    """Repo, raw, release, and GHCR URLs must point to secfoo-com/secfoo (npm scope @rakfortltd stays)."""
    bad_patterns = (
        "github.com/rakfortltd/secfoo",
        "raw.githubusercontent.com/rakfortltd/secfoo",
        "ghcr.io/rakfortltd/secfoo",
        'REPO="rakfortltd/secfoo"',
        '$Repo = "rakfortltd/secfoo"',
    )
    paths = [
        *_doc_files(),
        REPO_ROOT / "install.sh",
        REPO_ROOT / "install.ps1",
        REPO_ROOT / "Dockerfile",
        REPO_ROOT / ".github" / "workflows" / "release.yml",
        REPO_ROOT / "examples" / "ci" / "gitlab-ci.yml",
        *sorted((REPO_ROOT / "npm").rglob("package.json")),
        REPO_ROOT / "npm" / "secfoo" / "README.md",
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for pat in bad_patterns:
            assert pat not in text, f"obsolete '{pat}' in {path.relative_to(REPO_ROOT)}"


def test_descriptions_aligned_across_pyproject_citation_and_cli_help():
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0

    for label, text in (
        ("pyproject.toml", pyproject["project"]["description"]),
        ("CITATION.cff", citation),
        ("secfoo --help", result.output),
    ):
        assert "AI security review CLI" in text, f"{label} missing 'AI security review CLI'"
        assert "Context-based security architectural assessment" not in text, (
            f"obsolete description still present in {label}"
        )


def test_reference_release_trigger_matches_workflow_dispatch():
    ref = (REPO_ROOT / "docs" / "REFERENCE.md").read_text(encoding="utf-8")
    rel = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in rel
    assert "on every `vX.Y.Z` tag push" not in ref
    assert "workflow_dispatch" in ref


def test_version_is_at_least_0_3_1():
    parts = tuple(int(p) for p in __version__.split(".")[:3])
    assert parts >= (0, 3, 1), f"__version__ ({__version__}) behind published PyPI release 0.3.1"


def test_relative_markdown_links_resolve():
    link_re = re.compile(r"\[[^\]]+\]\(([^)#\s]+)(?:#[^)]*)?\)")
    for md in _doc_files():
        text = md.read_text(encoding="utf-8")
        for target in link_re.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (md.parent / target).resolve()
            assert resolved.exists(), f"broken relative link '{target}' in {md.relative_to(REPO_ROOT)}"
