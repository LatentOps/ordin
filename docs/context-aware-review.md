# Context-Aware Command Review

Ordin can accept explicit execution context when command safety depends
on where or how a command would run. Context is caller-supplied and local; the
core library does not inspect the process working directory, UID, shell, or
agent identity implicitly.

## Versioned request

The machine-readable request contract is `ordin.review_request.v1`:

```json
{
  "schema_version": "ordin.review_request.v1",
  "command": "rm -rf .",
  "intent": "clean generated files",
  "context": {
    "cwd": "/repo/build",
    "shell": "bash",
    "euid": 1000,
    "interactive": false,
    "repo_root": "/repo",
    "agent": "coding-agent"
  }
}
```

All context fields are optional. Missing fields remain unknown; Ordin
does not substitute ambient process state.

## Supported context

- `cwd`: absolute working directory used to resolve relative targets;
- `shell`: caller-declared shell/runtime name;
- `euid`: effective user ID, where `0` represents root;
- `interactive`: whether execution is interactive;
- `repo_root`: optional repository/workspace boundary;
- `agent`: optional caller/runtime identifier.

## Context-sensitive policy

Typed analyzer evidence preserves filesystem targets. With `cwd`, a target such
as `.` can be resolved deterministically. Destructive deletion resolving to `/`
is critical. Other filesystem mutations of `/` are elevated to high risk.

When `repo_root` is provided, mutating filesystem effects that resolve outside
the repository are elevated to high risk and explained as outside-repository
mutation.

When `euid` is `0`, mutation or code-execution effects are elevated to at least
high risk. Read-only effects are not elevated merely because the caller is
root.

These checks complement, rather than replace, command-family analyzers and
existing exact risk rules.

## CLI

Both `check` and `review` accept context fields:

```bash
ordin check "rm -rf ." --cwd / --euid 0 --json

ordin review \
  --command "chmod 600 secret.txt" \
  --intent "restrict file permissions" \
  --cwd /tmp \
  --repo-root /repo \
  --agent coding-agent \
  --non-interactive \
  --json
```

A complete context object can also be supplied with `--context-json`. Explicit
individual flags override fields from that object.
