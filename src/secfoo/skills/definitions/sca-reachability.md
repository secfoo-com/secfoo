---
id: sca-reachability
name: SCA — Reachability & Upgrade Triage
description: Dependency risk review focused on whether vulnerable code is actually reachable, plus a concrete upgrade plan.
short_name: SCA
version: 1
---

Review third-party dependency risk. The deliverable is a *triaged,
actionable* upgrade plan — not a raw CVE dump.

1. **Inventory.** Read the manifests and lockfiles that actually exist
   here (`requirements*.txt`, `pyproject.toml`, `poetry.lock`,
   `package.json`, `package-lock.json`, `yarn.lock`, `go.mod`, `go.sum`,
   `pom.xml`, `build.gradle`, `Gemfile.lock`, `Cargo.lock`). Record direct
   vs. transitive, and the exact resolved version wherever a lockfile
   gives you one.

2. **Version hygiene.** Flag unbounded ranges (`>=` with no upper bound),
   missing lockfiles, wildcard pins, and packages pinned to versions that
   are years behind or unmaintained.

3. **Known-vulnerability assessment.** Where you recognize a dependency as
   having significant known issues at the pinned version, say so — but
   **never invent a CVE ID**. If you aren't confident of the identifier,
   write "unverified — confirm with an SCA scanner" and describe the
   vulnerability *class* instead. Recommend `pip-audit`, `npm audit`, or
   `osv-scanner` for authoritative confirmation.

4. **Reachability triage.** This is the part that matters most. For each
   notable dependency risk, determine from the code whether the affected
   functionality is actually used:
   - **Reachable** — the affected API is called on a path exposed to
     untrusted input. Cite `file:line`.
   - **Conditionally reachable** — used, but only behind a flag, config,
     or code path that isn't currently active. Name the condition.
   - **Not reachable** — the package is installed but the affected
     functionality is never invoked. Say what you checked.
   Reachability should drive priority far more than raw CVSS does.

5. **Upgrade triage.** For each item worth fixing: the target version,
   whether it's a patch/minor/major bump, breaking changes to expect, and
   any transitive constraint that blocks it. Group upgrades that must
   ship together.

6. **Supply-chain hygiene.** Note install-time scripts, dependencies
   fetched from non-registry sources (git URLs, direct tarballs), packages
   recently transferred or typosquat-prone, and any dependency pulled over
   plain HTTP.

Severity: **High** = reachable and exploitable from untrusted input.
**Medium** = conditionally reachable, or unbounded-range exposure on a
security-relevant package. **Low** = not reachable, or hygiene only.
