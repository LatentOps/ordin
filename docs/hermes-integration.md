# Hermes Agent hooks

Available in the 0.4 development checkout. Ordin reviews actions; Hermes owns
tool execution, credentials, approvals and sandboxing. This adapter does not
invoke a model or execute a proposed tool.

The maintained host contract is **Hermes v0.21.7**, commit
`71d34bad1045610252eda02ee79549436896e784`. See the upstream
[shell hook guide](https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks),
[middleware guide](https://hermes-agent.nousresearch.com/docs/developer-guide/middleware),
and [pinned launcher source](https://github.com/NousResearch/hermes-agent/blob/71d34bad1045610252eda02ee79549436896e784/agent/shell_hooks.py).
Other releases require contract verification before use.

## Setup and verification

Install the development checkout in an isolated Python environment. On Linux
or macOS, preview and create a new, dedicated Hermes profile configuration:

```sh
ordin-hermes-hook doctor
ordin-hermes-hook pre < examples/hermes-pre.json
ordin setup hermes --root "$HERMES_HOME" --state --audit --observations --dry-run
ordin setup hermes --root "$HERMES_HOME" --state --audit --observations
ordin setup smoke hermes --root "$HERMES_HOME"
ordin setup status hermes --root "$HERMES_HOME"
```

Use the actual profile directory as `--root`; if omitted, setup uses
`HERMES_HOME` or `~/.hermes`. An empty `HERMES_HOME` shell variable should be
replaced with that explicit directory. Setup writes JSON to `config.yaml`
(valid YAML), plus a private ownership receipt. Existing files cause a
conflict and remain untouched. The fixture returns `{}`, allowing review
without executing `git status`.

For an existing profile, first create an owned **fragment** instead:

```sh
ordin setup hermes --root "$HERMES_HOME" --config ordin-hooks.json --state --audit --observations --dry-run
ordin setup hermes --root "$HERMES_HOME" --config ordin-hooks.json --state --audit --observations
```

Manually copy its `hooks` entries into the existing `config.yaml`. Keep
`ordin-hooks.json` and its receipt unchanged: hook commands use `--root` to
verify their owned settings before review. Preserve `fail_closed: true` on
`pre_tool_call`. Commands use an absolute Python path and direct argv execution;
shell assignments and `|| exit 2` are incompatible with Hermes' launcher.
Moving the Python environment requires regenerating and reviewing the fragment.

Trust these commands through Hermes' own hook consent flow. Ordin does not
auto-accept hooks or verify a running host has registered them. `doctor`,
`status` and smoke explicitly report host enablement as unverified. Hermes safe
mode disables user hooks, so do not assume Ordin protection in that mode.
Native Windows hook parsing is contract-tested; automated setup installation is
maintained on Linux and macOS, matching the existing setup platform policy.

## Decisions and tool coverage

| Proposed call | Review behavior |
| --- | --- |
| Ordinary foreground `terminal` | Shared shell analysis; explicit absolute `workdir` becomes context |
| `terminal` with timeout, background, PTY, force or other options | Unknown execution mode, requiring approval by default |
| `read_file` | File read effect and exact supplied path |
| `write_file`, `patch` in `replace` mode | File write effect and exact supplied path; contents become a digest |
| Multi-file `patch`, cross-profile file options | Unknown scope, requiring approval by default |
| `execute_code`, `delegate_task`, search and unknown tools | Unknown semantics, requiring approval by default |
| Exact reviewed MCP alias | Bound to explicit server/tool semantics; naming patterns confer no trust |

Allowed actions return `{}`. A denied decision returns `action: block` with a
message. Escalation returns **`action: approve`**, which invokes Hermes' human
approval gate. This action means request approval. It does not automatically
allow the call. The rule key binds the complete reviewed action, preventing a
tool-wide approval allowlist. Malformed input, unavailable state or failed
configuration returns a block and exit 2. Hermes' `fail_closed` flag protects
against launcher failures, crashes, malformed output and timeouts.

The hook's `cwd` is the host process directory and can differ from a container,
SSH backend or session terminal directory. Ordin does not invent a backend
directory or repository root from it. Relative file paths retain their supplied
identity with unknown backend context. Use reviewed policies for that uncertainty.

Use an isolated profile **without modifying pre-tool hooks, tool execution
middleware or overridden native tool implementations**. Hermes collects modify
directives against the original arguments, then applies them after all pre-tool
hooks; ordering Ordin last does not repair this limitation. Execution middleware
can also rewrite after review. These paths require a host-side enforcement
boundary to guarantee final-argument review. Direct tool registry calls, tools
called inside `execute_code`, hook-skipping dispatch paths and delegated child
activity without its own registered guard are outside this hook's coverage.

## Sessions, evidence and configuration

`--state` enables bounded SQLite history under `.ordin/private/hermes`. Identity
combines the explicit Hermes profile and conversation ID. Pre-tool reviews can
initialize resumed conversations; post-tool evidence cannot create a missing
session. Child conversations need distinct session IDs and their own guard.
Repeated `on_session_start` events preserve history. `on_session_reset` resets it
and `on_session_finalize` removes it. **`on_session_end` is per-turn** and is
intentionally not wired to conversation cleanup.

Action identity binds profile, conversation, tool call ID, tool identity, full
input digest and pinned contract. Changed post-tool arguments, missing reviews,
duplicate observations and cross-session evidence are rejected. Blocked host
results do not become observations. Custom-tool results can be ordinary text
or Hermes multimodal envelopes; their contents are validated for size and
format but are not retained or interpreted as exit codes. Terminal completion
uses only an explicit integer `exit_code`; background acceptance remains `reported`. Host-reported
success does not prove physical effects. Raw result output is not retained.
Approval keys use the reviewed action snapshot, even if a caller or audit
callback changes its original input. A failed observation trace write leaves
in-memory session state unchanged so the same matching observation can be retried.

`--audit` records private review evidence; `--observations` enables metadata-only
trace capture. Sensitive native file contents, code and delegation prompts are
hashed before review. Ordinary shell commands and operator-configured custom
arguments may contain sensitive data; protect local state and audit storage.
Default trace exports contain digests and reviewed effects. Hermes captures can
use the shared trace sanitize/replay/promotion workflow. Removal deletes only
unchanged owned configuration and receipts; evidence is retained:

```sh
ordin setup remove hermes --root "$HERMES_HOME" --dry-run
ordin setup remove hermes --root "$HERMES_HOME"
```

For a manually merged fragment, remove its entries from `config.yaml` before
removing the owned fragment. Existing configuration remains your responsibility.

Manual launchers support `ORDIN_HERMES_STATE`, `ORDIN_HERMES_AUDIT`,
`ORDIN_HERMES_TRACE`, `ORDIN_HERMES_TRACE_RAW` (explicit `0` or `1`),
`ORDIN_HERMES_POLICY`, `ORDIN_HERMES_SEMANTICS`, `ORDIN_HERMES_MCP_MAP`, and
`ORDIN_HERMES_FAIL_ON`. An MCP map uses
`{"tools":[{"hook_name":"exact_alias","server":"reviewed-server","tool":"read"}]}`.
Native names cannot be shadowed. Custom semantics must name runtime `hermes`,
or the exact mapped MCP server/tool. Discovery alone is not trust.

## Compatibility evidence

```sh
python -I scripts/check_hermes_integration.py --json-out hermes-contract-report.json
```

The dedicated CI check builds and installs an isolated Ordin wheel, fetches
five upstream files at the pinned commit and verifies their SHA256 digests. It
runs Hermes' real shell launcher/parser plus unmodified AST-selected production
approval, pre-dispatch, result-normalization and post-tool emission functions.
It verifies allow, approval/denial, approval errors, malformed identity,
profile isolation, crashes, timeouts, missing
executables, lifecycle callbacks, plain/multimodal post-tool results and changed
post-tool arguments. It also tests and reports the downstream rewrite coverage
limit. Transient download failures
get at most three attempts; missing files, bad hashes and exhausted retries
fail the check. Profile, environment, approval UI, ACP, post-hook suppression
and tool execution are explicit harmless fixtures. This proves
the pinned hook contract, not a live model run or sandbox containment.
