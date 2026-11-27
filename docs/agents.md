# Agent setup and troubleshooting

Select an adapter with `--agent`. CLI adapters must be installed on `PATH`
and authenticated before the run; secfoo cannot answer interactive prompts.
Install commands and authentication steps not specified by the adapters are
unverified here: consult the relevant agent's installation and login instructions.
The table describes the argv secfoo builds, not a command to paste verbatim.
`PROMPT` is the rendered review prompt, `WORKDIR` the target directory, and
brackets indicate optional arguments. All CLI processes run in `WORKDIR`.

| `--agent` | Setup and command |
| --- | --- |
| `claude` | Install via `npm install -g @anthropic-ai/claude-code` or `curl -fsSL https://claude.ai/install.sh \| bash` ([docs](https://docs.anthropic.com/en/docs/claude-code/setup)). Authenticate with `claude auth login`. For non-interactive use, set `ANTHROPIC_API_KEY`, or with a Claude subscription run `claude setup-token` once and set the token it prints as `CLAUDE_CODE_OAUTH_TOKEN` (verified `2.1.329 (Claude Code)` on 2026-11-21, macOS Darwin arm64). `claude [--model MODEL] -p --output-format json --allowedTools TOOLS --permission-mode default --setting-sources user --strict-mcp-config --no-session-persistence [--mcp-config PATH]` (prompt on stdin). `TOOLS` starts with `Read,Grep,Glob,Bash(git log:*),Bash(git diff:*)` and includes configured MCP servers when present. The tool grant is read-only, not an OS sandbox. |
| `agent` (Cursor) | Install via `curl https://cursor.com/install -fsS \| bash` ([docs](https://cursor.com/docs/cli/overview)). Authenticate with `agent login` or set `CURSOR_API_KEY` for non-interactive use (login and `CURSOR_API_KEY` confirmed in `agent --help` for `2026.08.11-e8db854` on 2026-11-21, macOS arm64; install command from the official docs). `agent [--model MODEL] -p PROMPT` |
| `agy` (Antigravity) | Install the `agy` CLI from the Antigravity distribution ([docs](https://antigravity.google)), then run `agy install` to add it to `PATH`. The CLI has no login subcommand: sign in through Antigravity before headless runs (checked against `agy --help` for `1.5.3` on 2026-11-21, macOS arm64). `agy --print PROMPT --print-timeout Ns` (`N` is the effective timeout in seconds). Headless mode denies tool calls requiring approval. |
| `gemini` | Install via `npm install -g @google/gemini-cli` ([docs](https://github.com/google-gemini/gemini-cli)). Authenticate interactively with `gemini` or set `GEMINI_API_KEY` for non-interactive use (verified `0.38.1` on 2026-11-21, macOS Darwin arm64). `gemini [--model MODEL] -p PROMPT --output-format json --skip-trust`. No `--yolo` write auto-approval is passed. |
| `codex` | Install via `npm install -g @openai/codex` ([docs](https://github.com/openai/codex)). Authenticate with `codex login` or set `OPENAI_API_KEY` for non-interactive use (verified `codex-cli 0.159.0` on 2026-11-21, macOS Darwin arm64). `codex exec [--model MODEL] --sandbox read-only [-c windows.sandbox="unelevated"] --skip-git-repo-check --ephemeral --color never --cd WORKDIR -` (prompt on stdin; `-c` is Windows-only). |
| `copilot` | Install via `npm install -g @github/copilot` ([docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli)). Authenticate by running `copilot` and using its `/login` command, or set `GH_TOKEN` / `GITHUB_TOKEN` (a fine-grained token with the Copilot Requests permission) for non-interactive use (checked against official docs on 2026-11-21). `copilot [--model MODEL] --output-format json --allow-all-tools` (prompt on stdin). Tools, including writes, are auto-approved: read-only behavior relies on review instructions, not a sandbox. |
| `droid` | Install via `curl -fsSL https://app.factory.ai/cli \| sh` ([docs](https://docs.factory.ai/cli/getting-started/overview)). Set `FACTORY_API_KEY` for non-interactive use or run `droid` to sign in interactively (checked against official docs on 2026-11-21, not on an installed CLI). `droid exec [-m MODEL] --output-format json --cwd WORKDIR -- PROMPT`. Droid defaults to read-only; a full authenticated secfoo run was not verified in the adapter. |
| `devin` | Install via `brew install --cask devin-cli` ([docs](https://docs.devin.ai)). Authenticate beforehand with `devin auth login`; credential reuse for headless runs is unverified (install and login checked against official docs on 2026-11-21, not on an installed CLI). `devin -p PROMPT --respect-workspace-trust false --permission-mode auto`. The combined command and an authenticated end-to-end run are unverified; `auto` is documented by the CLI as approving read-only tools. |
| `opencode` | Install via `npm install -g @opencode/cli` ([docs](https://opencode.ai/docs/)); the installed package was `@opencode/cli@2.3.0` on 2026-11-28, Windows x64. Authenticate for paid providers with `opencode auth login` (or `/connect` in the TUI); the free `opencode/*` models used for verification needed no login (`opencode auth list` reported no integrations). `opencode run --standalone --format json [-m MODEL]` (prompt on stdin). v2 removed the v1 `--pure` and `--dir` flags, and the v1 permission env vars are ignored: the read-only `permissions` array is shipped in `src/secfoo/agents/opencode-readonly.json`, loaded via `OPENCODE_CONFIG`, and requires `--standalone` to take effect. |
| `api` | No agent binary is invoked. `litellm` and `langgraph` are installed with secfoo; if importing them fails, reinstall secfoo the way you installed it (`pipx reinstall secfoo` or `pip install --force-reinstall secfoo`). Set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`. Source files are included in the API prompt. Model selection uses the configured model, then `SECFOO_API_MODEL`, then `openai/gpt-4.1-mini`. |

## Verification matrix

Recordings are made with `scripts/record_agent.py` (raw stdout/stderr/exit code,
prompt and CLI version; credentials are redacted and the script refuses to save
a transcript containing a key-shaped value). They live under
`tests/fixtures/agents/<id>/<cli-version>/` and are replayed by tests. A blank
cell means "not checked yet", not "verified working".

| `--agent` | CLI version | Date | Verified by | Install | Auth | Run | Timeout | Cost | Recordings |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `opencode` | `opencode v2.3.0` (`@opencode/cli@2.3.0`, Windows x64) | 2026-11-28 | Shruti Singh | Command from official docs; installed package observed | Free `opencode/*` models needed no login; paid model returned `provider.no-route` | ✅ `secret-scanning --depth quick` on `examples/`, report parsed by `extract_report()` | ✅ 8 s run killed, `status=timeout` | ✅ `step_finish` cost 0; input 46675 / output 3382 tokens | `success`, `auth_failure`, `timeout`, `permission_denied`, `flag_drift` |

The other adapters' version/date/check notes are in the table above; this
matrix is filled in as real recordings land. Issue #116 stays open until every
CLI adapter has a success and a failure recording.

To repeat the opencode run:

```bash
python scripts/record_agent.py --agent opencode --version 2.3.0 \
  --scenario success --verified-by "Your Name" --workdir examples \
  --prompt-file prompt.md --timeout 180 \
  --env OPENCODE_CONFIG=src/secfoo/agents/opencode-readonly.json -- \
  opencode run --standalone --format json -m opencode/big-pickle
```

`agy` and `devin` do not support adapter model selection; secfoo warns and
ignores a requested model. Other CLI model flags are shown above.

## Troubleshooting

- `binary_not_found`: `binary '<name>' not found on PATH` means the CLI
  was not found. Install it and make its binary available on `PATH`.
  Detection checks the binary, not authentication.
- OpenCode v2.3.0 ignores the v1 `OPENCODE_CONFIG_CONTENT`/`OPENCODE_PERMISSION`
  env vars and the v1 `--pure`/`--dir` flags (`flag_drift.json` records the
  CLI's `Unrecognized flag` errors). With those env vars alone a write tool
  was observed actually creating `proof.txt`; the shipped v2 `permissions`
  array plus `--standalone` denied the same write (`permission_denied.json`).
  Keep secfoo updated when upgrading OpenCode majors.
- Authentication or trust prompts cannot be answered during a run: stdin
  is closed or used for the prompt. Authenticate beforehand. Droid reports
  `Authentication failed` without its key; Devin was observed reporting
  `Error: Login canceled` without login. Gemini uses `--skip-trust`;
  Devin uses `--respect-workspace-trust false` because its headless mode
  cannot show the trust prompt. Check the CLI's error if trust still fails.
- `timeout`: secfoo kills the process tree. Cursor's headless mode has a
  documented hang; its default timeout is 900 seconds (other CLI adapters
  default to 1800). Antigravity also receives its effective print timeout.
  OpenCode's 8-second recording produced `status=timeout` with no report.
- `failed`: inspect the error. OpenCode v2 reports an unconfigured provider as
  a stdout JSON event (`provider.no-route`, `Model unavailable: ...`) with an
  empty stderr; secfoo extracts that message so the reason is not lost. Gemini
  can report `IneligibleTierError`;
  the adapter suggests Antigravity (`--agent agy`) if it persists. Codex
  reports a failed run if its sandbox rejects commands. Antigravity may
  return empty output or `Error: Agent execution terminated due to error.`;
  try another agent if it remains unreliable. Claude can put an error
  reason in stdout JSON even when stderr is empty; secfoo extracts it.
- API `not_configured`: `No API key set. Set one of: OPENAI_API_KEY,
  ANTHROPIC_API_KEY, GEMINI_API_KEY`. If LiteLLM or LangGraph cannot be imported,
  the run is `failed` and the error says to reinstall secfoo.

For a run failure, see `~/.secfoo/reports/<run-uuid>/stderr.log`; see
[Reporting bugs](../CONTRIBUTING.md#reporting-bugs) for what to include
when reporting it.
