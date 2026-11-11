"""Loads skill definitions from Markdown files with a small hand-parsed
frontmatter block (id/name/description/version). Deliberately avoids a YAML
dependency since the schema is tiny and fixed.

Skills come from these locations, merged (#79):

1. built-ins: `src/secfoo/skills/definitions/*.md`;
2. the user folder: `$SECFOO_HOME/skills/*.md` (default `~/.secfoo/skills/`);
3. `[skills] paths = [...]` in `~/.secfoo/config.toml`;
4. `SECFOO_SKILLS_PATH`, folders separated by `os.pathsep` (for CI);
5. one-off files registered with `register_skill_file()` (`secfoo run --skill-file`).

Skills are **never** loaded from the target being scanned: a cloned repo
could ship a `.secfoo/skills/` folder of prompt instructions. Only the
locations above count, and none of them is derived from the target.

Built-ins fail hard on any problem. A malformed or clashing *user* skill is
skipped with a one-line warning instead, so one bad file can't break every
command. User folders are re-read when a file's mtime changes, so a running
`secfoo serve` picks up new or edited skills without a restart.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFINITIONS_DIR = Path(__file__).parent / "definitions"
SKILLS_PATH_ENV = "SECFOO_SKILLS_PATH"
ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
GENERIC_OUTPUT = "generic"


class SkillLoadError(RuntimeError):
    pass


@dataclass(frozen=True)
class Skill:
    id: str
    name: str
    description: str
    version: int
    body: str
    # Optional compact label for space-constrained UI (sidebar nav, chart
    # axes). Full names like "SCA -- Reachability & Upgrade Triage" don't
    # fit a 16rem sidebar. Falls back to `name` when the frontmatter
    # omits it.
    short_name: str = ""
    # #79: for a custom skill, "generic" or the id of a built-in whose
    # output contract and findings lifecycle it reuses. Built-ins use their
    # own id (see output_type).
    output: str = GENERIC_OUTPUT
    category: str = ""
    source: str = "builtin"   # builtin / user / file
    path: Path | None = None
    sha256: str = ""          # of the definition file, recorded on every run

    @property
    def nav_label(self) -> str:
        return self.short_name or self.name

    @property
    def is_builtin(self) -> bool:
        return self.source == "builtin"

    @property
    def output_type(self) -> str:
        """Which built-in's contract and findings lifecycle a run uses:
        the skill's own id for a built-in, else its `output` field."""
        return self.id if self.is_builtin else self.output


def _parse_frontmatter(text: str, *, source: Path) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        raise SkillLoadError(f"{source}: missing frontmatter block")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise SkillLoadError(f"{source}: malformed frontmatter block")
    _, raw_frontmatter, body = parts
    fields: dict[str, str] = {}
    for line in raw_frontmatter.strip().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise SkillLoadError(f"{source}: bad frontmatter line {line!r}")
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields, body.strip()


def _load_file(path: Path, *, source: str = "builtin") -> Skill:
    raw = path.read_bytes()
    fields, body = _parse_frontmatter(raw.decode("utf-8"), source=path)
    try:
        skill = Skill(
            id=fields["id"],
            name=fields["name"],
            description=fields["description"],
            version=int(fields["version"]),
            body=body,
            short_name=fields.get("short_name", ""),
            output=fields.get("output", GENERIC_OUTPUT) or GENERIC_OUTPUT,
            category=fields.get("category", ""),
            source=source,
            path=path,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    except KeyError as exc:
        raise SkillLoadError(f"{path}: missing required frontmatter field {exc}") from exc
    except ValueError:
        raise SkillLoadError(f"{path}: version must be an integer, got {fields.get('version')!r}") from None
    if source != "builtin":
        _validate_custom(skill)
    return skill


def _validate_custom(skill: Skill) -> None:
    where = skill.path
    if not ID_RE.match(skill.id):
        raise SkillLoadError(f"{where}: id {skill.id!r} must be lowercase kebab-case (e.g. graphql-review)")
    for field_name in ("name", "description"):
        if not getattr(skill, field_name):
            raise SkillLoadError(f"{where}: {field_name} must not be empty")
    if not skill.body:
        raise SkillLoadError(f"{where}: the skill has no instructions after the frontmatter")
    builtins = builtin_skills()
    if skill.output != GENERIC_OUTPUT and skill.output not in builtins:
        raise SkillLoadError(
            f"{where}: output must be 'generic' or a built-in skill id ({', '.join(sorted(builtins))}), "
            f"got {skill.output!r}"
        )


@lru_cache(maxsize=1)
def builtin_skills() -> dict[str, Skill]:
    skills: dict[str, Skill] = {}
    for path in sorted(DEFINITIONS_DIR.glob("*.md")):
        skill = _load_file(path)
        if skill.id in skills:
            raise SkillLoadError(f"duplicate skill id {skill.id!r} in {path}")
        skills[skill.id] = skill
    return skills


# ---------- user locations ----------


def user_skill_dirs() -> list[tuple[Path, str]]:
    """(folder, label) for every user location, in precedence order. Only
    fixed places from the user's own setup -- never the scan target."""
    from secfoo.config import STORE_DIR
    from secfoo.settings import ConfigError, load_config

    dirs: list[tuple[Path, str]] = [(STORE_DIR / "skills", "user")]
    try:
        configured = load_config().skill_paths
    except ConfigError as exc:
        _warn(f"ignoring [skills] paths: {exc}")
        configured = []
    dirs += [(Path(p).expanduser(), "path") for p in configured]
    env = os.environ.get(SKILLS_PATH_ENV, "")
    dirs += [(Path(p).expanduser(), "path") for p in env.split(os.pathsep) if p.strip()]
    seen: set[Path] = set()
    unique = []
    for folder, label in dirs:
        key = folder.resolve() if folder.exists() else folder
        if key not in seen:
            seen.add(key)
            unique.append((folder, label))
    return unique


def _user_files() -> list[tuple[Path, str]]:
    files = []
    for folder, label in user_skill_dirs():
        if folder.is_dir():
            files.extend((path, label) for path in sorted(folder.glob("*.md")) if path.is_file())
    return files


_warned: set[str] = set()


def _warn(message: str) -> None:
    if message not in _warned:
        _warned.add(message)
        print(f"secfoo: warning: {message}", file=sys.stderr)


_registered: dict[str, Skill] = {}
_cache: dict[str, object] = {"signature": None, "skills": None, "problems": []}


def _signature() -> tuple:
    entries = []
    for path, label in _user_files():
        try:
            entries.append((str(path), label, path.stat().st_mtime_ns))
        except OSError:
            continue
    return tuple(entries), tuple(sorted(_registered))


def _load_user_skills(builtins: dict[str, Skill]) -> tuple[dict[str, Skill], list[str]]:
    skills: dict[str, Skill] = {}
    problems: list[str] = []
    for path, label in _user_files():
        try:
            skill = _load_file(path, source="user" if label == "user" else "path")
        except (SkillLoadError, OSError, UnicodeDecodeError) as exc:
            problems.append(f"skipped custom skill: {exc}")
            continue
        clash = builtins.get(skill.id) or skills.get(skill.id)
        if clash is not None:
            problems.append(
                f"skipped custom skill {path}: id {skill.id!r} is already used by {clash.path} "
                "(custom skills can't override another skill; rename one)"
            )
            continue
        skills[skill.id] = skill
    return skills, problems


def load_all_skills() -> dict[str, Skill]:
    """Built-ins plus every valid user skill. Cheap to call often: user
    folders are only re-read when a file is added, removed or edited."""
    builtins = builtin_skills()
    signature = _signature()
    if _cache["signature"] != signature:
        user, problems = _load_user_skills(builtins)
        merged = {**builtins, **user}
        for skill in _registered.values():
            merged.setdefault(skill.id, skill)
        _cache.update(signature=signature, skills=merged, problems=problems)
        for problem in problems:
            _warn(problem)
    return _cache["skills"]  # type: ignore[return-value]


def load_problems() -> list[str]:
    """Why custom skills were skipped on the last load (for `secfoo skills`)."""
    load_all_skills()
    return list(_cache["problems"])  # type: ignore[arg-type]


def register_skill_file(path: Path) -> Skill:
    """Load one file for this process only (`secfoo run --skill-file`).
    Raises SkillLoadError -- an explicitly named file should fail loudly."""
    skill = _load_file(path, source="file")
    existing = load_all_skills().get(skill.id)
    if existing is not None and existing.path != skill.path:
        raise SkillLoadError(f"{path}: id {skill.id!r} is already used by {existing.path}")
    _registered[skill.id] = skill
    return skill


def validate_files(paths: list[Path]) -> tuple[list[Skill], list[str]]:
    """Parse and check `paths` (files or folders) as custom skills, as
    `secfoo skills validate` does. Returns (valid skills, problems)."""
    files: list[Path] = []
    problems: list[str] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.md")))
        elif path.is_file():
            files.append(path)
        else:
            problems.append(f"{path}: no such file or folder")
    builtins = builtin_skills()
    valid: dict[str, Skill] = {}
    for path in files:
        try:
            skill = _load_file(path, source="path")
        except (SkillLoadError, OSError, UnicodeDecodeError) as exc:
            problems.append(str(exc))
            continue
        clash = builtins.get(skill.id) or valid.get(skill.id)
        if clash is not None:
            problems.append(f"{path}: id {skill.id!r} is already used by {clash.path}")
            continue
        valid[skill.id] = skill
    return list(valid.values()), problems


def load_skill(skill_id: str) -> Skill:
    skills = load_all_skills()
    try:
        return skills[skill_id]
    except KeyError:
        available = ", ".join(sorted(skills)) or "<none found>"
        raise SkillLoadError(f"unknown skill id {skill_id!r}. Available: {available}") from None


def _reset_for_tests() -> None:
    _registered.clear()
    _warned.clear()
    _cache.update(signature=None, skills=None, problems=[])


__all__ = [
    "Skill", "SkillLoadError", "builtin_skills", "load_all_skills", "load_problems", "load_skill",
    "register_skill_file", "user_skill_dirs", "validate_files",
]
