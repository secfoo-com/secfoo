# Writing your own skills

A **skill** is one kind of security review secfoo can run: SAST, threat
modeling, SCA reachability, and so on. You can add your own, such as a GraphQL
API review, a PCI DSS scoping pass, or a check against your internal coding
standard, by dropping a Markdown file in a folder. It then shows up in
`secfoo run --skill`, `--help`, the dashboard and assessments. You don't change
any code or rebuild anything.

```bash
secfoo skills new graphql-review          # scaffold ~/.secfoo/skills/graphql-review.md
$EDITOR ~/.secfoo/skills/graphql-review.md
secfoo skills validate                     # check every custom skill
secfoo skills show graphql-review --target .   # preview the exact prompt
secfoo run --skill graphql-review --target .
```

Two complete examples are in [`examples/skills/`](../examples/skills/).

## Where skills are loaded from

All of these are merged:

1. **Built-ins** shipped with secfoo.
2. **Your folder:** `$SECFOO_HOME/skills/*.md` (default `~/.secfoo/skills/`).
3. **Extra folders** from `~/.secfoo/config.toml`, for example a team's shared
   skills repo checked out locally:
   ```toml
   [skills]
   paths = ["~/work/appsec-skills", "/opt/company/secfoo-skills"]
   ```
4. **`SECFOO_SKILLS_PATH`:** extra folders separated by `:` (`;` on Windows),
   handy in CI.
5. **Installed packs:** `secfoo skills install <git-url>` (see
   [Sharing skills with your team](#sharing-skills-with-your-team) below).
6. **One-off:** `secfoo run --skill-file ./my-skill.md --target .` runs a file
   or an `https://` URL without installing it:
   ```bash
   secfoo run --skill-file https://raw.githubusercontent.com/acme/appsec-skills/main/graphql-review.md --target .
   # pin it for CI -- a content mismatch fails before the skill runs at all
   secfoo run --skill-file https://.../graphql-review.md --skill-sha256 <hex> --target .
   ```
   A URL is fetched over HTTPS only (no `http://`, and no redirect to one),
   capped at 256 KB.

secfoo **never** loads skills from the target it is scanning. A cloned repo
can't add instructions by shipping a `.secfoo/skills/` folder.

`secfoo skills list` shows every skill with its source and output type.
`secfoo serve` picks up new or edited skill files without a restart.

## File format

```markdown
---
id: graphql-review
name: GraphQL API Security Review
short_name: GraphQL API
description: Reviews a GraphQL API for authorization gaps and query-cost abuse.
version: 1
output: generic
category: API
---

Your instructions to the reviewer go here...
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Lowercase kebab-case. Must not match a built-in or another custom skill. |
| `name` | yes | Shown in reports and the dashboard. |
| `description` | yes | One line, shown in the skill picker. |
| `version` | yes | An integer. Bump it when you change the instructions. |
| `short_name` | no | Compact label for the sidebar. |
| `output` | no | `generic` (default) or the id of a built-in skill whose report format and findings dashboard to reuse. |
| `category` | no | Groups custom skills in the sidebar (e.g. `Compliance`). |

Lines starting with `#` in the frontmatter are comments.

### `output`: where results go

- **`generic`:** the report uses secfoo's generic format, with findings under
  `### [SEVERITY] F1: title` headings. The skill gets its own activity page,
  run list and severity counts.
- **A built-in id, such as `sast`, `sca-reachability` or `secret-scanning`:**
  the report uses that skill's exact format, and its findings land in that
  skill's dashboard and open/closed lifecycle. A custom "SAST for our
  framework" skill (see `examples/skills/django-sast.md`) then shows up next to
  the built-in SAST findings. A custom run only **adds and updates** findings.
  It never closes findings the built-in scan recorded, because it only covered
  what your instructions asked about.

## What secfoo adds around your instructions

The skill body holds only your instructions. secfoo always wraps them with:

- its safety preamble (treat the target as untrusted, never execute it);
- the target and exclusion sections;
- depth guidance (`--depth quick` / `standard`);
- the output contract for the skill's `output` type.

A custom skill can't remove any of these, so its reports always parse and its
severity counts and CI gates (`--fail-on`) work like a built-in's. Run
`secfoo skills show <id>` to see the full prompt.

## Validation

- A malformed custom skill, or one whose `id` clashes with another, is
  **skipped with a one-line warning** naming the files. Every other command keeps
  working. Built-in skills fail loudly instead.
- `secfoo skills validate [PATH...]` checks files or folders and exits `1` on
  any problem. Run it in CI on a shared skills repo:
  ```yaml
  - run: pip install secfoo && secfoo skills validate .
  ```

## Traceability

Custom skills change over time, so every run records which definition produced
it: the skill's `version`, its source, and a SHA-256 of the definition file.
For a built-in or a file under `~/.secfoo/skills/`, the source is `builtin` /
`user`; for a URL or an installed pack, it's the URL itself or
`pack:<name>@<commit>`, so a run's page always says exactly what ran. If a
later run of the same skill id used a different SHA-256, its page is marked
**definition changed**.

## Trust model

A skill's text becomes agent instructions, so the first time a run would use
one secfoo didn't author -- anything other than a built-in or a file under
`~/.secfoo/skills/*.md` (a configured path, a one-off file or URL, a pack) --
`secfoo run` prints its id, name, source and SHA-256 and asks you to confirm.
`--yes` skips the prompt, and it's always skipped on a non-interactive run
(CI, `--json`). The run still records what actually ran either way.

## Sharing skills with your team

Two ways, in increasing order of rigor:

- **A plain checkout:** keep the skills in a git repo, one `.md` file per
  skill, run `secfoo skills validate .` in its CI, and have each person add
  the checkout to `[skills] paths`. Updating the repo updates everyone's
  skills immediately -- good for a small team that trusts its own `main`.
- **A pinned pack:** `secfoo skills install` clones the repo once into
  `~/.secfoo/skills/packs/<name>/` (skills optionally under a `skills/`
  subfolder) and pins it in `~/.secfoo/skills/packs.lock`:
  ```bash
  secfoo skills install https://github.com/acme/appsec-skills            # -> packs/acme-appsec-skills
  secfoo skills install https://github.com/acme/appsec-skills --ref v3   # a tag, branch or commit
  secfoo skills update [NAME]      # move an installed pack (or every one) to its ref's newest commit
  secfoo skills remove NAME
  secfoo skills list               # shows each skill's pack and commit
  ```
  Check `packs.lock` into your own repo and run `secfoo skills install
  --from-lock` in CI to reproduce the exact same commit every time, instead of
  whatever the pack's branch happens to point to that day.

Either way, bump a skill's `version` when you change its instructions, so
runs show which wording they used.
