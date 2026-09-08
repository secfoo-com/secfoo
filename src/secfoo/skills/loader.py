"""Loads skill definitions from Markdown files with a small hand-parsed
frontmatter block (id/name/description/version). Deliberately avoids a YAML
dependency since the schema is tiny and fixed.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFINITIONS_DIR = Path(__file__).parent / "definitions"


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

    @property
    def nav_label(self) -> str:
        return self.short_name or self.name


def _parse_frontmatter(text: str, *, source: Path) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        raise SkillLoadError(f"{source}: missing frontmatter block")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise SkillLoadError(f"{source}: malformed frontmatter block")
    _, raw_frontmatter, body = parts
    fields: dict[str, str] = {}
    for line in raw_frontmatter.strip().splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            raise SkillLoadError(f"{source}: bad frontmatter line {line!r}")
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields, body.strip()


def _load_file(path: Path) -> Skill:
    fields, body = _parse_frontmatter(path.read_text(), source=path)
    try:
        return Skill(
            id=fields["id"],
            name=fields["name"],
            description=fields["description"],
            version=int(fields["version"]),
            body=body,
            short_name=fields.get("short_name", ""),
        )
    except KeyError as exc:
        raise SkillLoadError(f"{path}: missing required frontmatter field {exc}") from exc


@lru_cache(maxsize=1)
def load_all_skills() -> dict[str, Skill]:
    skills: dict[str, Skill] = {}
    for path in sorted(DEFINITIONS_DIR.glob("*.md")):
        skill = _load_file(path)
        if skill.id in skills:
            raise SkillLoadError(f"duplicate skill id {skill.id!r} in {path}")
        skills[skill.id] = skill
    return skills


def load_skill(skill_id: str) -> Skill:
    skills = load_all_skills()
    try:
        return skills[skill_id]
    except KeyError:
        available = ", ".join(sorted(skills)) or "<none found>"
        raise SkillLoadError(f"unknown skill id {skill_id!r}. Available: {available}") from None
