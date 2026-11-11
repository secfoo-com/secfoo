"""Scoring rules for scripts/leaderboard.py (the hackathon leaderboard)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "leaderboard.py"
spec = importlib.util.spec_from_file_location("leaderboard", SCRIPT)
leaderboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(leaderboard)

REPO = "secfoo-com/secfoo"


def pr(number, author, merged_at, issues=(), author_type="User"):
    return {
        "number": number,
        "title": f"PR {number}",
        "url": f"https://github.com/{REPO}/pull/{number}",
        "merged_at": merged_at,
        "author": author,
        "author_type": author_type,
        "issues": list(issues),
    }


def issue(number, *labels):
    return {
        "number": number,
        "title": f"Issue {number}",
        "url": f"https://github.com/{REPO}/issues/{number}",
        "labels": list(labels),
    }


@pytest.mark.parametrize(
    ("labels", "expected"),
    [
        (["difficulty: hard"], "hard"),
        (["Difficulty: Medium", "bug"], "medium"),
        (["difficulty/low"], "low"),
        (["difficulty-hard"], "hard"),
        (["hard", "enhancement"], None),  # bare words don't count
        (["difficulty: low", "difficulty: hard"], "hard"),  # conflict -> highest
        ([], None),
    ],
)
def test_difficulty_label_parsing(labels, expected):
    assert leaderboard.difficulty_of(labels) == expected


def test_points_and_levels():
    assert leaderboard.POINTS == {"hard": 10, "medium": 6, "low": 3}
    assert leaderboard.level_for(0) is None
    assert leaderboard.level_for(24) is None
    assert leaderboard.level_for(25) == "Level 3"
    assert leaderboard.level_for(50) == "Level 2"
    assert leaderboard.level_for(99) == "Level 2"
    assert leaderboard.level_for(100) == "Level 1"
    assert leaderboard.next_level_for(30) == {"name": "Level 2", "min_points": 50}
    assert leaderboard.next_level_for(150) is None


def test_points_are_summed_per_contributor_and_ranked():
    prs = [
        pr(1, "alice", "2026-11-08T10:00:00Z", [issue(10, "difficulty: hard")]),
        pr(2, "bob", "2026-11-08T11:00:00Z", [issue(11, "difficulty: low"), issue(12, "difficulty: medium")]),
        pr(3, "alice", "2026-11-09T09:00:00Z", [issue(13, "difficulty: medium")]),
    ]
    board = leaderboard.score(prs, REPO)
    by_login = {c["login"]: c for c in board["contributors"]}
    assert by_login["alice"]["points"] == 16
    assert by_login["alice"]["counts"] == {"hard": 1, "medium": 1, "low": 0}
    assert by_login["alice"]["merged_prs"] == 2
    assert by_login["bob"]["points"] == 9
    assert [c["login"] for c in board["contributors"]] == ["alice", "bob"]
    assert by_login["alice"]["rank"] == 1 and by_login["bob"]["rank"] == 2
    assert by_login["alice"]["level"] is None  # 16 < 25


def test_each_issue_is_scored_once_for_the_first_merged_pr():
    prs = [
        pr(2, "bob", "2026-11-08T12:00:00Z", [issue(10, "difficulty: hard")]),
        pr(1, "alice", "2026-11-08T10:00:00Z", [issue(10, "difficulty: hard")]),  # merged earlier
    ]
    board = leaderboard.score(prs, REPO)
    by_login = {c["login"]: c for c in board["contributors"]}
    assert by_login["alice"]["points"] == 10
    assert by_login["bob"]["points"] == 0
    assert len(board["awards"]) == 1


def test_unlabelled_issues_are_flagged_not_scored():
    prs = [pr(1, "alice", "2026-11-08T10:00:00Z", [issue(10, "enhancement", "hackathon")])]
    board = leaderboard.score(prs, REPO)
    assert board["contributors"][0]["points"] == 0
    assert board["awards"] == []
    assert [(a["pr"], a["issue"], a["contributor"]) for a in board["needs_difficulty"]] == [(1, 10, "alice")]


def test_bots_excluded_and_since_and_exclude_filters():
    prs = [
        pr(1, "dependabot[bot]", "2026-11-08T10:00:00Z", [issue(10, "difficulty: hard")], author_type="Bot"),
        pr(2, "maintainer", "2026-11-08T10:00:00Z", [issue(11, "difficulty: hard")]),
        pr(3, "alice", "2026-11-01T10:00:00Z", [issue(12, "difficulty: hard")]),  # before --since
        pr(4, "alice", "2026-11-09T10:00:00Z", [issue(13, "difficulty: low")]),
    ]
    board = leaderboard.score(prs, REPO, since="2026-11-08T00:00:00Z", exclude={"Maintainer"})
    assert [(c["login"], c["points"]) for c in board["contributors"]] == [("alice", 3)]


def test_levels_reached():
    issues = [issue(100 + i, "difficulty: hard") for i in range(10)]
    board = leaderboard.score([pr(1, "alice", "2026-11-08T10:00:00Z", issues)], REPO)
    assert board["contributors"][0]["points"] == 100
    assert board["contributors"][0]["level"] == "Level 1"


def test_markdown_badge_and_comment_render():
    prs = [
        pr(1, "alice", "2026-11-08T10:00:00Z", [issue(10, "difficulty: hard")]),
        pr(2, "bob", "2026-11-08T11:00:00Z", [issue(11, "enhancement")]),
    ]
    board = leaderboard.score(prs, REPO)

    md = leaderboard.render_markdown(board)
    assert "| 1 | [@alice](https://github.com/alice) | **10** |" in md
    assert "## Needs a difficulty label" in md
    assert "[#2](https://github.com/secfoo-com/secfoo/pull/2) | [#11]" in md

    badge = leaderboard.render_badge(board)
    assert badge["schemaVersion"] == 1
    assert badge["message"] == "alice leads with 10 pts"

    comment = leaderboard.render_pr_comment(board, 1)
    assert "+10 points" in comment
    assert "alice now has **10 points** (rank #1)." in comment
    assert "15 more to reach Level 3" in comment

    pending = leaderboard.render_pr_comment(board, 2)
    assert "no `difficulty:` label yet" in pending

    assert leaderboard.render_pr_comment(board, 999) is None


def test_cli_offline_writes_outputs(tmp_path):
    fixture = tmp_path / "prs.json"
    fixture.write_text(
        __import__("json").dumps([pr(1, "alice", "2026-11-08T10:00:00Z", [issue(10, "difficulty: medium")])]),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    assert leaderboard.main(["--repo", REPO, "--from-json", str(fixture), "--out", str(out),
                             "--announce-pr", "1", "--dry-run"]) == 0
    assert (out / "LEADERBOARD.md").exists()
    assert (out / "badge.json").exists()
    data = __import__("json").loads((out / "leaderboard.json").read_text(encoding="utf-8"))
    assert data["contributors"][0]["points"] == 6
