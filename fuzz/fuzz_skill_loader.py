"""Fuzz the custom skill loader (#79, #93): skill file bytes -> Skill.

Input: the raw bytes of a skill file (frontmatter + instructions), exactly
what `--skill-file`, a skills folder or a `--skill-file <url>` download hands
to `_build_skill`.

Contract: a Skill, or SkillLoadError naming the problem -- never another
exception (callers only catch SkillLoadError). A custom skill that loads has
a kebab-case id, a name, a description, instructions and an integer version,
and its sha256 is of the exact bytes given.

    python fuzz/fuzz_skill_loader.py WORK fuzz/corpus/skill_loader -max_total_time=60
"""

from __future__ import annotations

import hashlib

from _common import main

from secfoo.skills.loader import ID_RE, Skill, SkillLoadError, _build_skill


def check(data: bytes) -> None:
    for source in ("user", "url", "builtin"):  # builtin skips the custom-skill checks; all must be total
        try:
            skill = _build_skill(data, source=source, path=None, origin="<fuzz>")
        except SkillLoadError:
            continue
        assert isinstance(skill, Skill)
        assert isinstance(skill.version, int)
        assert skill.sha256 == hashlib.sha256(data).hexdigest()
        if source != "builtin":
            assert ID_RE.match(skill.id)
            assert skill.name and skill.description and skill.body


if __name__ == "__main__":
    main(check)
