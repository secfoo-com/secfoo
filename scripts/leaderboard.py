"""Builds the contributor leaderboard for the secfoo hackathon.

Scoring rules (see CONTRIBUTING.md, "Hackathon points"):

* A merged PR earns points for every issue it closes, based on the issue's
  difficulty label: ``difficulty: hard`` = 10, ``difficulty: medium`` = 6,
  ``difficulty: low`` = 3.
* Each issue is scored once, for the first merged PR that closed it.
* Contributors reach Bronze at 25 points, Silver at 50, Gold at 100.
* Merged PRs that close an issue without a difficulty label earn nothing yet;
  they're listed under "Needs a difficulty label" so a maintainer can add one.
  The board recomputes from scratch on every run, so late labels count.

Run by .github/workflows/leaderboard.yml, which publishes the output to the
``leaderboard`` branch. Local use (needs a token with read access):

    GITHUB_TOKEN=... python scripts/leaderboard.py --repo secfoo-com/secfoo --out build/leaderboard

Offline use with a saved fixture (the same shape ``--dump-prs`` writes):

    python scripts/leaderboard.py --repo secfoo-com/secfoo --from-json prs.json --out build/leaderboard
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Points per difficulty label. Labels are matched case-insensitively as
# "difficulty: hard", "difficulty/hard" or "difficulty-hard".
POINTS = {"hard": 10, "medium": 6, "low": 3}
DIFFICULTY_RE = re.compile(r"^difficulty\s*[:/-]\s*(hard|medium|low)$", re.IGNORECASE)

# Highest level first. A contributor holds the first level whose threshold
# they meet; below the lowest threshold they have no level yet.
LEVELS = [
    {"name": "Gold", "min_points": 100},
    {"name": "Silver", "min_points": 50},
    {"name": "Bronze", "min_points": 25},
]

GRAPHQL_URL = "https://api.github.com/graphql"
PR_QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: MERGED, first: 100, after: $after,
                 orderBy: {field: CREATED_AT, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number title url mergedAt
        author { login __typename }
        closingIssuesReferences(first: 20) {
          nodes {
            number title url state
            labels(first: 30) { nodes { name } }
          }
        }
      }
    }
  }
}
"""


# --------------------------------------------------------------------------- #
# GitHub API
# --------------------------------------------------------------------------- #

def _token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        sys.exit("GITHUB_TOKEN (or GH_TOKEN) is required to query GitHub")
    return token


def _request(url: str, payload: dict | None = None, method: str = "POST") -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {_token()}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "secfoo-leaderboard")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        sys.exit(f"GitHub API {error.code} for {url}: {body[:500]}")


def fetch_merged_prs(repo: str) -> list[dict]:
    """Every merged PR with the issues GitHub records it as closing."""
    owner, name = repo.split("/", 1)
    prs: list[dict] = []
    after = None
    while True:
        result = _request(GRAPHQL_URL, {"query": PR_QUERY, "variables": {"owner": owner, "name": name, "after": after}})
        if "errors" in result:
            sys.exit(f"GraphQL errors: {json.dumps(result['errors'], indent=2)}")
        connection = result["data"]["repository"]["pullRequests"]
        for node in connection["nodes"]:
            author = node.get("author") or {}
            prs.append({
                "number": node["number"],
                "title": node["title"],
                "url": node["url"],
                "merged_at": node["mergedAt"],
                "author": author.get("login") or "ghost",
                "author_type": author.get("__typename") or "User",
                "issues": [
                    {
                        "number": issue["number"],
                        "title": issue["title"],
                        "url": issue["url"],
                        "labels": [label["name"] for label in issue["labels"]["nodes"]],
                    }
                    for issue in node["closingIssuesReferences"]["nodes"]
                ],
            })
        if not connection["pageInfo"]["hasNextPage"]:
            return prs
        after = connection["pageInfo"]["endCursor"]


def post_pr_comment(repo: str, pr_number: int, body: str) -> None:
    _request(f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments", {"body": body})


# --------------------------------------------------------------------------- #
# Scoring (pure; covered by tests/test_leaderboard.py)
# --------------------------------------------------------------------------- #

def difficulty_of(labels: list[str]) -> str | None:
    """The issue's difficulty, or None. If several labels disagree, the
    highest wins (and the board flags the issue for cleanup)."""
    found = {match.group(1).lower() for label in labels if (match := DIFFICULTY_RE.match(label.strip()))}
    for difficulty in ("hard", "medium", "low"):
        if difficulty in found:
            return difficulty
    return None


def level_for(points: int) -> str | None:
    for level in LEVELS:
        if points >= level["min_points"]:
            return level["name"]
    return None


def next_level_for(points: int) -> dict | None:
    """The lowest level the contributor hasn't reached yet, or None at the top."""
    for level in reversed(LEVELS):
        if points < level["min_points"]:
            return level
    return None


def is_bot(pr: dict) -> bool:
    return pr.get("author_type") == "Bot" or pr["author"].endswith("[bot]")


def score(prs: list[dict], repo: str, *, since: str | None = None, exclude: set[str] | None = None) -> dict:
    exclude = {login.lower() for login in (exclude or set())}
    eligible = [
        pr for pr in prs
        if not is_bot(pr)
        and pr["author"].lower() not in exclude
        and (since is None or pr["merged_at"] >= since)
    ]
    eligible.sort(key=lambda pr: (pr["merged_at"], pr["number"]))

    contributors: dict[str, dict] = {}
    awards: list[dict] = []
    needs_difficulty: list[dict] = []
    seen_issues: set[int] = set()

    def contributor(login: str) -> dict:
        return contributors.setdefault(login, {
            "login": login,
            "points": 0,
            "counts": {"hard": 0, "medium": 0, "low": 0},
            "merged_prs": 0,
            "awards": [],
        })

    for pr in eligible:
        entry = contributor(pr["author"])
        entry["merged_prs"] += 1
        for issue in pr["issues"]:
            if issue["number"] in seen_issues:
                continue  # already credited to an earlier PR
            seen_issues.add(issue["number"])
            difficulty = difficulty_of(issue["labels"])
            record = {
                "pr": pr["number"],
                "pr_url": pr["url"],
                "issue": issue["number"],
                "issue_url": issue["url"],
                "issue_title": issue["title"],
                "contributor": pr["author"],
                "merged_at": pr["merged_at"],
            }
            if difficulty is None:
                needs_difficulty.append(record)
                continue
            record.update({"difficulty": difficulty, "points": POINTS[difficulty]})
            entry["points"] += POINTS[difficulty]
            entry["counts"][difficulty] += 1
            entry["awards"].append(record)
            awards.append(record)

    ranked = sorted(
        contributors.values(),
        key=lambda c: (-c["points"], -c["counts"]["hard"], -c["counts"]["medium"], -c["merged_prs"], c["login"].lower()),
    )
    for rank, entry in enumerate(ranked, start=1):
        entry["rank"] = rank
        entry["level"] = level_for(entry["points"])

    return {
        "repo": repo,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "since": since,
        "points": POINTS,
        "levels": LEVELS,
        "contributors": ranked,
        "awards": sorted(awards, key=lambda a: a["merged_at"], reverse=True),
        "needs_difficulty": sorted(needs_difficulty, key=lambda a: a["merged_at"], reverse=True),
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _when(iso: str) -> str:
    return iso[:10]


def render_markdown(board: dict) -> str:
    repo = board["repo"]
    out: list[str] = []
    out.append("# secfoo contributor leaderboard\n")
    out.append(
        f"_Updated {board['generated_at'].replace('T', ' ').rstrip('Z')} UTC by "
        f"[`leaderboard.yml`](https://github.com/{repo}/blob/main/.github/workflows/leaderboard.yml). "
        "Generated file; edits here are overwritten._\n"
    )
    if board["since"]:
        out.append(f"_Counting PRs merged on or after {_when(board['since'])}._\n")

    out.append("## Standings\n")
    scored = [c for c in board["contributors"] if c["points"] > 0]
    if not scored:
        out.append("No points awarded yet. Merge a PR that closes an issue with a `difficulty:` label to get on the board.\n")
    else:
        out.append("| # | Contributor | Points | Level | Hard | Medium | Low | Merged PRs |")
        out.append("|---:|---|---:|---|---:|---:|---:|---:|")
        for c in scored:
            out.append(
                f"| {c['rank']} | [@{c['login']}](https://github.com/{c['login']}) | **{c['points']}** | "
                f"{c['level'] or '—'} | {c['counts']['hard']} | {c['counts']['medium']} | {c['counts']['low']} | {c['merged_prs']} |"
            )
        out.append("")
    unscored = [c for c in board["contributors"] if c["points"] == 0]
    if unscored:
        names = ", ".join(f"[@{c['login']}](https://github.com/{c['login']})" for c in unscored)
        out.append(f"Merged PRs but no scored issues yet: {names}.\n")

    out.append("## How points work\n")
    out.append("Points come from the `difficulty:` label on the issue a merged PR closes "
               "(link it with `Fixes #123` in the PR description or the sidebar).\n")
    out.append("| Issue label | Points |")
    out.append("|---|---:|")
    for difficulty in ("hard", "medium", "low"):
        out.append(f"| `difficulty: {difficulty}` | {POINTS[difficulty]} |")
    out.append("")
    out.append("| Level | Points needed |")
    out.append("|---|---:|")
    for level in LEVELS:
        out.append(f"| {level['name']} | {level['min_points']} |")
    out.append("")
    out.append("Each issue is scored once, for the first PR merged that closes it. "
               "Bots are excluded. Full rules: "
               f"[CONTRIBUTING.md](https://github.com/{repo}/blob/main/CONTRIBUTING.md#hackathon-points).\n")

    out.append("## Recent awards\n")
    if not board["awards"]:
        out.append("None yet.\n")
    else:
        out.append("| Merged | Contributor | PR | Issue | Difficulty | Points |")
        out.append("|---|---|---|---|---|---:|")
        for a in board["awards"][:25]:
            out.append(
                f"| {_when(a['merged_at'])} | [@{a['contributor']}](https://github.com/{a['contributor']}) | "
                f"[#{a['pr']}]({a['pr_url']}) | [#{a['issue']}]({a['issue_url']}) {a['issue_title']} | "
                f"{a['difficulty']} | +{a['points']} |"
            )
        out.append("")

    out.append("## Needs a difficulty label\n")
    if not board["needs_difficulty"]:
        out.append("Every closed issue is labelled. Nothing to do.\n")
    else:
        out.append("These merged PRs closed an issue that has no `difficulty:` label, so they "
                   "haven't been scored. A maintainer adds the label and the next run credits them.\n")
        out.append("| Merged | Contributor | PR | Issue |")
        out.append("|---|---|---|---|")
        for a in board["needs_difficulty"]:
            out.append(
                f"| {_when(a['merged_at'])} | [@{a['contributor']}](https://github.com/{a['contributor']}) | "
                f"[#{a['pr']}]({a['pr_url']}) | [#{a['issue']}]({a['issue_url']}) {a['issue_title']} |"
            )
        out.append("")
    return "\n".join(out)


def render_badge(board: dict) -> dict:
    """shields.io endpoint schema: https://shields.io/badges/endpoint-badge"""
    scored = [c for c in board["contributors"] if c["points"] > 0]
    if not scored:
        message, color = "no points yet", "lightgrey"
    else:
        leader = scored[0]
        message = f"{leader['login']} leads with {leader['points']} pts"
        color = "brightgreen"
    return {"schemaVersion": 1, "label": "hackathon leaderboard", "message": message, "color": color}


def render_pr_comment(board: dict, pr_number: int) -> str | None:
    """Comment for a just-merged PR, or None if it closed no issues."""
    awarded = [a for a in board["awards"] if a["pr"] == pr_number]
    pending = [a for a in board["needs_difficulty"] if a["pr"] == pr_number]
    if not awarded and not pending:
        return None
    repo = board["repo"]
    lines = ["### Leaderboard update", ""]
    for a in awarded:
        lines.append(f"- Closed #{a['issue']} (`difficulty: {a['difficulty']}`): **+{a['points']} points**")
    for a in pending:
        lines.append(f"- Closed #{a['issue']}, which has no `difficulty:` label yet, so it isn't scored. "
                     "A maintainer can add `difficulty: hard`, `medium` or `low` and the board recomputes automatically.")
    login = (awarded or pending)[0]["contributor"]
    entry = next((c for c in board["contributors"] if c["login"] == login), None)
    if entry and entry["points"] > 0:
        standing = f"{login} now has **{entry['points']} points** (rank #{entry['rank']}"
        standing += f", {entry['level']})." if entry["level"] else ")."
        nxt = next_level_for(entry["points"])
        if nxt:
            standing += f" {nxt['min_points'] - entry['points']} more to reach {nxt['name']}."
        lines += ["", standing]
    lines += ["", f"[Full leaderboard](https://github.com/{repo}/blob/leaderboard/LEADERBOARD.md)"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", required=True, help="owner/name, e.g. secfoo-com/secfoo")
    parser.add_argument("--out", type=Path, default=Path("build/leaderboard"), help="output directory")
    parser.add_argument("--since", help="only count PRs merged at/after this ISO-8601 instant")
    parser.add_argument("--exclude", default="", help="comma-separated logins to leave off the board")
    parser.add_argument("--from-json", type=Path, help="read merged PRs from this file instead of GitHub")
    parser.add_argument("--dump-prs", type=Path, help="also save the fetched merged PRs here (fixture for --from-json)")
    parser.add_argument("--announce-pr", type=int, metavar="N", help="comment the award on merged PR #N")
    parser.add_argument("--dry-run", action="store_true", help="print the PR comment instead of posting it")
    args = parser.parse_args(argv)

    if args.from_json:
        prs = json.loads(args.from_json.read_text(encoding="utf-8"))
    else:
        prs = fetch_merged_prs(args.repo)
    if args.dump_prs:
        args.dump_prs.parent.mkdir(parents=True, exist_ok=True)
        args.dump_prs.write_text(json.dumps(prs, indent=2) + "\n", encoding="utf-8")

    exclude = {login.strip() for login in args.exclude.split(",") if login.strip()}
    board = score(prs, args.repo, since=args.since or None, exclude=exclude)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "LEADERBOARD.md").write_text(render_markdown(board), encoding="utf-8")
    (args.out / "leaderboard.json").write_text(json.dumps(board, indent=2) + "\n", encoding="utf-8")
    (args.out / "badge.json").write_text(json.dumps(render_badge(board)) + "\n", encoding="utf-8")
    scored = sum(1 for c in board["contributors"] if c["points"] > 0)
    print(f"{len(prs)} merged PRs, {len(board['awards'])} awards, {scored} contributors on the board, "
          f"{len(board['needs_difficulty'])} issues need a difficulty label -> {args.out}")

    if args.announce_pr:
        comment = render_pr_comment(board, args.announce_pr)
        if comment is None:
            print(f"PR #{args.announce_pr} closed no issues; nothing to announce")
        elif args.dry_run:
            print(comment)
        else:
            post_pr_comment(args.repo, args.announce_pr, comment)
            print(f"commented on PR #{args.announce_pr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
