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
| `claude` | Install command unverified; subscription login is supported. `claude [--model MODEL] -p --output-format json --allowedTools TOOLS --permission-mode default --setting-sources user --strict-mcp-config --no-session-persistence [--mcp-config PATH]` (prompt on stdin). `TOOLS` starts with `Read,Grep,Glob,Bash(git log:*),Bash(git diff:*)` and includes configured MCP servers when present. The tool grant is read-only, not an OS sandbox. |
| `agent` (Cursor) | Install and authentication commands unverified. `agent [--model MODEL] -p PROMPT` |
| `agy` (Antigravity) | Install and authentication commands unverified. `agy --print PROMPT --print-timeout Ns` (`N` is the effective timeout in seconds). Headless mode denies tool calls requiring approval. |
| `gemini` | Install and authentication commands unverified. `gemini [--model MODEL] -p PROMPT --output-format json --skip-trust`. No `--yolo` write auto-approval is passed. |
| `codex` | Install and authentication commands unverified. `codex exec [--model MODEL] --sandbox read-only [-c windows.sandbox="unelevated"] --skip-git-repo-check --ephemeral --color never --cd WORKDIR -` (prompt on stdin; `-c` is Windows-only). |
| `copilot` | The adapter identifies the npm package as `@github/copilot`; install and authentication commands are unverified. `copilot [--model MODEL] --output-format json --allow-all-tools` (prompt on stdin). Tools, including writes, are auto-approved: read-only behavior relies on review instructions, not a sandbox. |
| `droid` | Install command unverified. Set `FACTORY_API_KEY` for noninteractive use. `droid exec [-m MODEL] --output-format json --cwd WORKDIR -- PROMPT`. Droid defaults to read-only; a full authenticated secfoo run was not verified in the adapter. |
| `devin` | The adapter identifies the official Homebrew cask as `devin-cli`; install command unverified. Authenticate beforehand with `devin auth login`; credential reuse for headless runs is unverified. `devin -p PROMPT --respect-workspace-trust false --permission-mode auto`. The combined command and an authenticated end-to-end run are unverified; `auto` is documented by the CLI as approving read-only tools. |
| `api` | No agent binary is invoked. If dependencies are missing, run `pip install "secfoo[api]"`. Set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`. Source files are included in the API prompt. Model selection uses the configured model, then `SECFOO_API_MODEL`, then `openai/gpt-4.1-mini`. |

`agy` and `devin` do not support adapter model selection; secfoo warns and
ignores a requested model. Other CLI model flags are shown above.

## Troubleshooting

- `binary_not_found`: `binary '<name>' not found on PATH` means the CLI
  was not found. Install it and make its binary available on `PATH`.
  Detection checks the binary, not authentication.
- Authentication or trust prompts cannot be answered during a run: stdin
  is closed or used for the prompt. Authenticate beforehand. Droid reports
  `Authentication failed` without its key; Devin was observed reporting
  `Error: Login canceled` without login. Gemini uses `--skip-trust`;
  Devin uses `--respect-workspace-trust false` because its headless mode
  cannot show the trust prompt. Check the CLI's error if trust still fails.
- `timeout`: secfoo kills the process tree. Cursor's headless mode has a
  documented hang; its default timeout is 900 seconds (other CLI adapters
  default to 1800). Antigravity also receives its effective print timeout.
- `failed`: inspect the error. Gemini can report `IneligibleTierError`;
  the adapter suggests Antigravity (`--agent agy`) if it persists. Codex
  reports a failed run if its sandbox rejects commands. Antigravity may
  return empty output or `Error: Agent execution terminated due to error.`;
  try another agent if it remains unreliable. Claude can put an error
  reason in stdout JSON even when stderr is empty; secfoo extracts it.
- API `not_configured`: `No API key set. Set one of: OPENAI_API_KEY,
  ANTHROPIC_API_KEY, GEMINI_API_KEY`. Missing LiteLLM/LangGraph dependencies
  produce `failed` with the install command above.

For a run failure, see `~/.secfoo/reports/<run-uuid>/stderr.log`; see
[Reporting bugs](../CONTRIBUTING.md#reporting-bugs) for what to include
when reporting it.
