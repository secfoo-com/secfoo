---
name: Bug report
about: Something isn't working as expected
title: ''
labels: bug
assignees: ''
---

**Command run**

```
secfoo run --skill ... --target ... --agent ...
```

**Expected behavior**

**Actual behavior**

**Version**

- `secfoo --version` (or `pip show secfoo`):
- Agent CLI + version (`claude --version` / `cursor-agent --version` / etc.):
- OS:

**Logs**

If this is a run failure, attach the relevant files from
`~/.secfoo/reports/<run-uuid>/` — `stderr.log` especially, it's almost
always the fastest way to diagnose an agent-adapter problem.
