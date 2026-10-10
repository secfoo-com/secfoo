"""Deterministic language/framework detection for a scan target.

Two consumers need the same answer to "what stack is this":

- structured findings (sast/sca/secret-scanning rows get `language` and
  `framework` columns, so findings from different repos can be grouped by
  stack without re-reading report prose), and
- the memory guidance section of the prompt, which tells the agent which
  exact language/framework values to send to the `secfoo-memory` tools.

Both are derived from files on disk (extensions, dependency manifests),
never from the model's own "Languages and frameworks detected" prose,
which varies run to run ("Python 3", "python", "CPython").
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

# Directories never worth walking -- dependencies, caches, build output.
_SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage", ".turbo",
    "target", "vendor", ".terraform", ".idea", ".vscode",
}

# Bounds the walk on a huge monorepo: detection only needs a representative
# sample, not every file.
_MAX_FILES = 20_000

EXTENSION_LANGUAGES = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "shell", ".bash": "shell",
    ".tf": "terraform",
    ".sql": "sql",
}

# Files that aren't source by extension but are where secrets and
# misconfigurations live -- classified so a secret-scanning finding in
# `deploy/ci.yml` still gets a meaningful language value.
_CONFIG_EXTENSIONS = {".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml", ".env": "dotenv"}

ECOSYSTEM_LANGUAGES = {
    "npm": "javascript",
    "pypi": "python",
    "maven": "java",
    "gradle": "java",
    "go": "go",
    "crates.io": "rust",
    "cargo": "rust",
    "rubygems": "ruby",
    "nuget": "csharp",
    "packagist": "php",
    "composer": "php",
    "pub": "dart",
    "hex": "elixir",
}

# Dependency name -> framework slug, per language. Only frameworks that
# change what a vulnerability looks like (routing, templating, ORM
# defaults) -- not every library.
_JS_FRAMEWORKS = {
    "express": "express", "koa": "koa", "fastify": "fastify", "@hapi/hapi": "hapi",
    "@nestjs/core": "nestjs", "next": "nextjs", "nuxt": "nuxt", "react": "react",
    "vue": "vue", "@angular/core": "angular", "svelte": "svelte", "electron": "electron",
}
_PY_FRAMEWORKS = {
    "django": "django", "flask": "flask", "fastapi": "fastapi", "starlette": "starlette",
    "tornado": "tornado", "pyramid": "pyramid", "aiohttp": "aiohttp", "sanic": "sanic",
}
_JAVA_FRAMEWORKS = {
    "spring-boot": "spring", "spring-webmvc": "spring", "spring-web": "spring",
    "struts2-core": "struts", "quarkus": "quarkus", "micronaut": "micronaut",
}
_GO_FRAMEWORKS = {
    "github.com/gin-gonic/gin": "gin", "github.com/labstack/echo": "echo",
    "github.com/gofiber/fiber": "fiber", "github.com/gorilla/mux": "gorilla",
}
_RUBY_FRAMEWORKS = {"rails": "rails", "sinatra": "sinatra"}
_PHP_FRAMEWORKS = {"laravel/framework": "laravel", "symfony/symfony": "symfony", "symfony/http-kernel": "symfony"}
_RUST_FRAMEWORKS = {"actix-web": "actix", "axum": "axum", "rocket": "rocket"}

_PY_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")
_QUOTED_NAME_RE = re.compile(r"""["']([A-Za-z0-9_.\-]+)\s*(?:[<>=!~;\[ ]|["'])""")


@dataclass(frozen=True)
class Stack:
    """Languages ordered most-files-first; frameworks keyed by language."""

    languages: list[str] = field(default_factory=list)
    frameworks: dict[str, list[str]] = field(default_factory=dict)

    @property
    def primary_language(self) -> str | None:
        return self.languages[0] if self.languages else None

    def frameworks_for(self, language: str | None) -> list[str]:
        if not language:
            return []
        # typescript projects declare their frameworks in package.json,
        # same as javascript ones.
        if language == "typescript":
            return self.frameworks.get("typescript") or self.frameworks.get("javascript", [])
        return self.frameworks.get(language, [])

    def all_frameworks(self) -> list[str]:
        seen: list[str] = []
        for language in self.languages + sorted(self.frameworks):
            for framework in self.frameworks.get(language, []):
                if framework not in seen:
                    seen.append(framework)
        return seen


def language_for_path(path: str | None) -> str | None:
    """`app/db.py` -> "python"; unknown or missing -> None. Config files
    (`.yml`, `.env`, ...) map to their format name, since that's the most
    useful stack value for a secret or misconfiguration finding in one."""
    if not path:
        return None
    pure = PurePosixPath(path.strip().replace("\\", "/"))
    name = pure.name.lower()
    if name == ".env" or name.startswith(".env."):
        return "dotenv"
    if name == "dockerfile" or name.endswith(".dockerfile"):
        return "dockerfile"
    suffix = pure.suffix.lower()
    return EXTENSION_LANGUAGES.get(suffix) or _CONFIG_EXTENSIONS.get(suffix)


def language_for_ecosystem(ecosystem: str | None) -> str | None:
    if not ecosystem:
        return None
    return ECOSYSTEM_LANGUAGES.get(ecosystem.strip().lower())


def _read(path: Path, limit: int = 512_000) -> str:
    try:
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _match_names(names: set[str], table: dict[str, str]) -> set[str]:
    return {table[name] for name in names if name in table}


def _package_json_frameworks(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, dict):
        return set()
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            names.update(name.lower() for name in section)
    return _match_names(names, _JS_FRAMEWORKS)


def _python_frameworks(path: Path, text: str) -> set[str]:
    names: set[str] = set()
    if path.name.endswith(".txt"):
        for line in text.splitlines():
            match = _PY_REQUIREMENT_NAME_RE.match(line)
            if match and not line.lstrip().startswith(("#", "-")):
                names.add(match.group(1).lower())
    else:
        # pyproject.toml / Pipfile / setup.py / setup.cfg: quoted names
        # are good enough -- a false positive needs a framework name in
        # quotes, which in a manifest means it is a dependency.
        names.update(match.group(1).lower() for match in _QUOTED_NAME_RE.finditer(text))
        if path.name == "Pipfile":
            names.update(
                line.split("=")[0].strip().strip('"').lower() for line in text.splitlines() if "=" in line
            )
    return _match_names(names, _PY_FRAMEWORKS)


def _substring_frameworks(text: str, table: dict[str, str]) -> set[str]:
    lowered = text.lower()
    return {framework for name, framework in table.items() if name in lowered}


def _manifest_frameworks(path: Path) -> tuple[str, set[str]] | None:
    name = path.name
    lowered = name.lower()
    if name == "package.json":
        return "javascript", _package_json_frameworks(_read(path))
    if (lowered.startswith("requirements") and lowered.endswith(".txt")) or name in (
        "pyproject.toml", "Pipfile", "setup.py", "setup.cfg",
    ):
        return "python", _python_frameworks(path, _read(path))
    if name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return "java", _substring_frameworks(_read(path), _JAVA_FRAMEWORKS)
    if name == "go.mod":
        return "go", _substring_frameworks(_read(path), _GO_FRAMEWORKS)
    if name == "Gemfile":
        text = _read(path)
        gems = {m.group(1).lower() for m in re.finditer(r"""gem\s+["']([^"']+)["']""", text)}
        return "ruby", _match_names(gems, _RUBY_FRAMEWORKS)
    if name == "composer.json":
        return "php", _substring_frameworks(_read(path), _PHP_FRAMEWORKS)
    if name == "Cargo.toml":
        return "rust", _substring_frameworks(_read(path), _RUST_FRAMEWORKS)
    if lowered.endswith(".csproj"):
        return "csharp", {"aspnetcore"} if "microsoft.aspnetcore" in _read(path).lower() else set()
    return None


def detect_stack(workdir: Path | None) -> Stack:
    """Walks `workdir` once (bounded) and returns its stack. Never raises:
    a missing or unreadable directory just yields an empty Stack."""
    if workdir is None or not Path(workdir).is_dir():
        return Stack()
    counts: Counter[str] = Counter()
    frameworks: dict[str, set[str]] = {}
    seen_files = 0
    for root, dirs, files in os.walk(workdir):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            seen_files += 1
            if seen_files > _MAX_FILES:
                break
            path = Path(root) / name
            language = EXTENSION_LANGUAGES.get(path.suffix.lower())
            if language:
                counts[language] += 1
            manifest = _manifest_frameworks(path)
            if manifest:
                manifest_language, found = manifest
                if found:
                    frameworks.setdefault(manifest_language, set()).update(found)
        if seen_files > _MAX_FILES:
            break

    # A package.json whose sources are .ts files is a typescript project;
    # attribute its frameworks to typescript too so frameworks_for() works
    # for either language.
    if "javascript" in frameworks and counts.get("typescript", 0) > counts.get("javascript", 0):
        frameworks.setdefault("typescript", set()).update(frameworks["javascript"])

    languages = [language for language, _count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
    return Stack(
        languages=languages,
        frameworks={language: sorted(found) for language, found in sorted(frameworks.items())},
    )
