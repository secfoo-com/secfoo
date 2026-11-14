"""Loads skill definitions from Markdown files with a small hand-parsed
frontmatter block (id/name/description/version). Deliberately avoids a YAML
dependency since the schema is tiny and fixed.

Skills come from these locations, merged (#79, #93):

1. built-ins: `src/secfoo/skills/definitions/*.md`;
2. the user folder: `$SECFOO_HOME/skills/*.md` (default `~/.secfoo/skills/`);
3. `[skills] paths = [...]` in `~/.secfoo/config.toml`;
4. `SECFOO_SKILLS_PATH`, folders separated by `os.pathsep` (for CI);
5. installed skill packs (`secfoo skills install`), under
   `~/.secfoo/skills/packs/<name>/` or its `skills/` subfolder;
6. one-off files or HTTPS URLs registered with `register_skill_file()`
   (`secfoo run --skill-file`).

Skills are **never** loaded from the target being scanned: a cloned repo
could ship a `.secfoo/skills/` folder of prompt instructions. Only the
locations above count, and none of them is derived from the target.

Built-ins fail hard on any problem. A malformed or clashing *custom* skill is
skipped with a one-line warning instead, so one bad file can't break every
command. User folders and packs are re-read when a file's mtime changes (or a
pack is installed/removed), so a running `secfoo serve` picks up new or
edited skills without a restart.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFINITIONS_DIR = Path(__file__).parent / "definitions"
SKILLS_PATH_ENV = "SECFOO_SKILLS_PATH"
ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
GENERIC_OUTPUT = "generic"
# #93: --skill-file over HTTPS is capped well below secfoo's other size
# limits -- a skill is a short prompt, not a payload.
MAX_URL_SKILL_BYTES = 256 * 1024


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
    source: str = "builtin"   # builtin / user / path / file / url / pack
    path: Path | None = None
    # #93: for source == "url", the fetch URL; for source == "pack", the
    # literal "pack:<name>@<commit>". Carried into `runs.skill_source`
    # instead of the generic "user" label so a run's page can link back to
    # exactly what ran (see source_label).
    origin: str = ""
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

    @property
    def source_label(self) -> str:
        """What `runs.skill_source` records (#93): `builtin` for a
        built-in, the URL or `pack:<name>@<commit>` for those two sources,
        else `user` (the pre-#93 behavior for every other custom source)."""
        if self.is_builtin:
            return "builtin"
        if self.source in ("url", "pack") and self.origin:
            return self.origin
        return "user"

    @property
    def is_trusted_source(self) -> bool:
        """#93: only a built-in or a file under the user's own
        `~/.secfoo/skills/` folder skips the first-run trust prompt --
        everything else (a configured path, a one-off file or URL, a pack)
        is instructions secfoo didn't author, so it's confirmed once."""
        return self.is_builtin or self.source == "user"


def _parse_frontmatter(text: str, *, source: str) -> tuple[dict[str, str], str]:
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


def _build_skill(raw: bytes, *, source: str, path: Path | None, origin: str = "") -> Skill:
    label = str(path) if path is not None else origin
    fields, body = _parse_frontmatter(raw.decode("utf-8"), source=label)
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
            origin=origin,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    except KeyError as exc:
        raise SkillLoadError(f"{label}: missing required frontmatter field {exc}") from exc
    except ValueError:
        raise SkillLoadError(f"{label}: version must be an integer, got {fields.get('version')!r}") from None
    if source != "builtin":
        _validate_custom(skill)
    return skill


def _load_file(path: Path, *, source: str = "builtin", origin: str = "") -> Skill:
    return _build_skill(path.read_bytes(), source=source, path=path, origin=origin)


class _HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses to follow a redirect away from https:// (#93): urllib
    follows redirects by default regardless of scheme, which would let an
    https URL silently hand the "fetched over HTTPS" skill file to a
    plain-http response instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise SkillLoadError(f"refusing to follow a redirect to a non-https URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url_skill(url: str, *, expected_sha256: str | None = None, timeout: int = 20) -> Skill:
    """Fetch and validate a skill from an HTTPS URL (#93's `--skill-file
    <url>`). Never follows a redirect to a non-https URL, and never reads
    more than MAX_URL_SKILL_BYTES. If `expected_sha256` is given, a mismatch
    is raised before the content is parsed, let alone run."""
    if not url.lower().startswith("https://"):
        scheme = url.split("://", 1)[0] if "://" in url else "(none)"
        raise SkillLoadError(f"{url}: --skill-file URLs must use https:// (got {scheme}://)")
    opener = urllib.request.build_opener(_HTTPSOnlyRedirectHandler)
    try:
        with opener.open(url, timeout=timeout) as response:  # nosec B310 -- https-only, no-redirect-to-http opener; size-capped below
            raw = response.read(MAX_URL_SKILL_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise SkillLoadError(f"{url}: HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise SkillLoadError(f"{url}: {exc.reason}") from None
    if len(raw) > MAX_URL_SKILL_BYTES:
        raise SkillLoadError(f"{url}: exceeds the {MAX_URL_SKILL_BYTES // 1024} KB limit for a --skill-file URL")
    if expected_sha256 is not None:
        digest = hashlib.sha256(raw).hexdigest()
        if digest.lower() != expected_sha256.strip().lower():
            raise SkillLoadError(
                f"{url}: sha256 mismatch (expected {expected_sha256}, got {digest}) -- refusing to run it"
            )
    return _build_skill(raw, source="url", path=None, origin=url)


def _validate_custom(skill: Skill) -> None:
    where = skill.path or skill.origin or skill.id
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


def _pack_skill_dirs() -> list[tuple[Path, str]]:
    """(folder, "pack:<name>@<commit>") for every installed skill pack
    (#93). Imported lazily -- same reason `user_skill_dirs()` imports
    secfoo.config/settings lazily: avoids a module-load-time cycle between
    the loader and secfoo.skills.packs (which validates files through this
    module when installing)."""
    try:
        from secfoo.skills.packs import installed_packs
    except ImportError:
        return []
    dirs = []
    for pack in installed_packs():
        skills_subdir = pack.path / "skills"
        folder = skills_subdir if skills_subdir.is_dir() else pack.path
        dirs.append((folder, f"pack:{pack.name}@{pack.commit}"))
    return dirs


def _user_files() -> list[tuple[Path, str, str]]:
    """(path, label, origin) for every custom-skill file on disk: a user
    location's label is "user"/"path" with no origin; a pack's label is
    "pack" with its `pack:<name>@<commit>` origin."""
    files: list[tuple[Path, str, str]] = []
    for folder, label in user_skill_dirs():
        if folder.is_dir():
            files.extend((path, label, "") for path in sorted(folder.glob("*.md")) if path.is_file())
    for folder, origin in _pack_skill_dirs():
        if folder.is_dir():
            files.extend((path, "pack", origin) for path in sorted(folder.glob("*.md")) if path.is_file())
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
    for path, label, origin in _user_files():
        try:
            entries.append((str(path), label, origin, path.stat().st_mtime_ns))
        except OSError:
            continue
    return tuple(entries), tuple(sorted(_registered))


def _skill_source_for_label(label: str) -> str:
    if label == "user":
        return "user"
    if label == "pack":
        return "pack"
    return "path"


def _load_user_skills(builtins: dict[str, Skill]) -> tuple[dict[str, Skill], list[str]]:
    skills: dict[str, Skill] = {}
    problems: list[str] = []
    for path, label, origin in _user_files():
        try:
            skill = _load_file(path, source=_skill_source_for_label(label), origin=origin)
        except (SkillLoadError, OSError, UnicodeDecodeError) as exc:
            problems.append(f"skipped custom skill: {exc}")
            continue
        clash = builtins.get(skill.id) or skills.get(skill.id)
        if clash is not None:
            where = clash.path or clash.origin
            problems.append(
                f"skipped custom skill {path}: id {skill.id!r} is already used by {where} "
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


def _identity(skill: Skill) -> tuple[Path | None, str]:
    return (skill.path, skill.origin)


def register_skill_file(path_or_url: str | Path, *, expected_sha256: str | None = None) -> Skill:
    """Load one file or HTTPS URL for this process only (`secfoo run
    --skill-file`, #93 adds URL support). Raises SkillLoadError -- an
    explicitly named source should fail loudly."""
    text = str(path_or_url)
    if text.lower().startswith(("http://", "https://")):
        skill = fetch_url_skill(text, expected_sha256=expected_sha256)
    else:
        if expected_sha256 is not None:
            raise SkillLoadError(f"{path_or_url}: --skill-sha256 only applies to a --skill-file URL")
        skill = _load_file(Path(path_or_url), source="file")
    existing = load_all_skills().get(skill.id)
    if existing is not None and _identity(existing) != _identity(skill):
        where = existing.path or existing.origin
        raise SkillLoadError(f"{path_or_url}: id {skill.id!r} is already used by {where}")
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
    "MAX_URL_SKILL_BYTES", "Skill", "SkillLoadError", "builtin_skills", "fetch_url_skill", "load_all_skills",
    "load_problems", "load_skill", "register_skill_file", "user_skill_dirs", "validate_files",
]
