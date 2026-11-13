"""#93: shared skill packs -- install/update/remove/list and packs.lock."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secfoo.cli import app
from secfoo.skills.loader import load_all_skills, load_problems, load_skill
from secfoo.skills.packs import (
    PackError,
    default_pack_name,
    install_from_lock,
    install_pack,
    installed_packs,
    remove_pack,
    save_lock,
    update_all_packs,
    update_pack,
)

runner = CliRunner(env={"COLUMNS": "300"})


def _out(result) -> str:
    return " ".join(result.output.split())


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _write_skill(folder: Path, skill_id: str, *, version: int = 1, body: str = "Review it.") -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{skill_id}.md").write_text(
        f"---\nid: {skill_id}\nname: {skill_id.title()}\ndescription: From a pack.\nversion: {version}\n---\n\n"
        f"{body}\n",
        encoding="utf-8",
    )


def _make_repo(tmp_path: Path, name: str = "origin", *, skill_id: str = "pack-skill") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(["init", "--quiet", "-b", "main"], repo)
    _git(["config", "user.email", "test@example.com"], repo)
    _git(["config", "user.name", "Test"], repo)
    _write_skill(repo / "skills", skill_id)
    _git(["add", "-A"], repo)
    _git(["commit", "--quiet", "-m", "initial"], repo)
    _git(["tag", "v1"], repo)
    return repo


@pytest.fixture
def home(_isolated_custom_skills):
    return _isolated_custom_skills


# ---------- default_pack_name ----------


def test_default_pack_name_variants():
    assert default_pack_name("https://github.com/acme/appsec-skills") == "acme-appsec-skills"
    assert default_pack_name("https://github.com/acme/appsec-skills.git") == "acme-appsec-skills"
    assert default_pack_name("git@github.com:acme/appsec-skills.git") == "acme-appsec-skills"


# ---------- install / update / remove / list ----------


def test_install_pack_from_a_local_repo_at_a_tag(home, tmp_path):
    repo = _make_repo(tmp_path)
    pack = install_pack(str(repo), ref="v1", name="acme-pack")
    assert pack.name == "acme-pack" and pack.ref == "v1" and len(pack.commit) == 40
    assert pack.path.is_dir()
    assert installed_packs() == [pack]

    skill = load_skill("pack-skill")
    assert skill.source == "pack"
    assert skill.origin == f"pack:acme-pack@{pack.commit}"


def test_install_pack_without_name_derives_one_from_the_url(home, tmp_path):
    org_dir = tmp_path / "acme"
    org_dir.mkdir()
    repo = _make_repo(org_dir, name="appsec-skills")
    pack = install_pack(str(repo))
    assert pack.name == "acme-appsec-skills"


def test_install_twice_under_the_same_name_errors(home, tmp_path):
    repo = _make_repo(tmp_path)
    install_pack(str(repo), name="acme-pack")
    with pytest.raises(PackError, match="already installed"):
        install_pack(str(repo), name="acme-pack")


def test_update_moves_to_the_newest_commit_on_its_ref(home, tmp_path):
    repo = _make_repo(tmp_path)
    pack = install_pack(str(repo), ref="main", name="acme-pack")
    first_commit = pack.commit

    _write_skill(repo / "skills", "pack-skill", version=2, body="Review it again.")
    _git(["commit", "--quiet", "-am", "bump"], repo)

    updated = update_pack("acme-pack")
    assert updated.commit != first_commit
    assert load_skill("pack-skill").version == 2
    assert load_skill("pack-skill").origin == f"pack:acme-pack@{updated.commit}"


def test_update_unknown_pack_errors(home):
    with pytest.raises(PackError, match="no installed pack"):
        update_pack("nope")


def test_update_all_packs_updates_every_installed_pack(home, tmp_path):
    repo_a = _make_repo(tmp_path, name="repo-a", skill_id="skill-a")
    repo_b = _make_repo(tmp_path, name="repo-b", skill_id="skill-b")
    install_pack(str(repo_a), ref="main", name="pack-a")
    install_pack(str(repo_b), ref="main", name="pack-b")

    _write_skill(repo_a / "skills", "skill-a", version=2)
    _git(["commit", "--quiet", "-am", "bump"], repo_a)

    updated = update_all_packs()
    assert {p.name for p in updated} == {"pack-a", "pack-b"}
    assert load_skill("skill-a").version == 2


def test_remove_pack_deletes_the_checkout_and_the_skill(home, tmp_path):
    repo = _make_repo(tmp_path)
    pack = install_pack(str(repo), name="acme-pack")
    assert pack.path.is_dir()
    remove_pack("acme-pack")
    assert not pack.path.exists()
    assert installed_packs() == []
    assert "pack-skill" not in load_all_skills()


def test_remove_unknown_pack_errors(home):
    with pytest.raises(PackError, match="no installed pack"):
        remove_pack("nope")


def test_install_from_lock_reproduces_the_pinned_commit(home, tmp_path):
    repo = _make_repo(tmp_path)
    pack = install_pack(str(repo), ref="v1", name="acme-pack")

    # A newer commit lands on the repo after the lock was pinned/committed.
    _write_skill(repo / "skills", "pack-skill", version=2)
    _git(["commit", "--quiet", "-am", "bump"], repo)

    remove_pack("acme-pack")  # simulate a fresh CI checkout: packs.lock exists, the pack folder does not
    save_lock({pack.name: pack})

    reproduced = install_from_lock()
    assert reproduced == [pack]
    assert load_skill("pack-skill").version == 1  # the pinned commit, not the newer one


def test_pack_skill_clashing_with_a_builtin_is_skipped(home, tmp_path):
    repo = _make_repo(tmp_path, skill_id="sast")
    install_pack(str(repo), name="acme-pack")
    assert load_all_skills()["sast"].is_builtin  # the pack's own "sast" lost the clash, built-in wins
    problems = load_problems()
    assert any("sast" in problem and "already used by" in problem for problem in problems)


def test_pack_without_a_skills_subfolder_still_loads(home, tmp_path):
    repo = tmp_path / "flat-repo"
    repo.mkdir()
    _git(["init", "--quiet", "-b", "main"], repo)
    _git(["config", "user.email", "test@example.com"], repo)
    _git(["config", "user.name", "Test"], repo)
    _write_skill(repo, "flat-skill")
    _git(["add", "-A"], repo)
    _git(["commit", "--quiet", "-m", "initial"], repo)

    install_pack(str(repo), name="flat-pack")
    assert load_skill("flat-skill").source == "pack"


# ---------- CLI ----------


def test_cli_install_update_remove_and_list(home, tmp_path):
    repo = _make_repo(tmp_path)
    install_result = runner.invoke(app, ["skills", "install", str(repo), "--ref", "v1", "--name", "acme-pack"])
    assert install_result.exit_code == 0, install_result.output
    assert "Installed acme-pack" in install_result.output

    list_result = runner.invoke(app, ["skills", "list"])
    line = next(line for line in list_result.output.splitlines() if "pack-skill" in line)
    assert "pack:acme-pack@" in line

    update_result = runner.invoke(app, ["skills", "update", "acme-pack"])
    assert update_result.exit_code == 0 and "acme-pack" in _out(update_result)

    remove_result = runner.invoke(app, ["skills", "remove", "acme-pack"])
    assert remove_result.exit_code == 0
    assert runner.invoke(app, ["skills", "update", "acme-pack"]).exit_code == 1


def test_cli_install_from_lock(home, tmp_path):
    repo = _make_repo(tmp_path)
    pack = install_pack(str(repo), name="acme-pack")
    remove_pack("acme-pack")
    save_lock({pack.name: pack})

    result = runner.invoke(app, ["skills", "install", "--from-lock"])
    assert result.exit_code == 0, result.output
    assert "acme-pack" in _out(result)
    assert load_skill("pack-skill").source == "pack"


def test_cli_install_with_both_url_and_from_lock_errors(home, tmp_path):
    repo = _make_repo(tmp_path)
    result = runner.invoke(app, ["skills", "install", str(repo), "--from-lock"])
    assert result.exit_code == 1 and "pass no URL" in _out(result)


def test_cli_install_with_neither_url_nor_from_lock_errors(home):
    result = runner.invoke(app, ["skills", "install"])
    assert result.exit_code == 1 and "--from-lock" in _out(result)
