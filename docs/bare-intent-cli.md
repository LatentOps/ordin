# Bare intent CLI mode

The installed `commandgraph` and `cmdgraph` entrypoints treat natural-language text as search by default.

```bash
cmdgraph how to ssh
cmdgraph make file runnable --json
cmdgraph what is using port 3000 --limit 3
```

These are equivalent to explicit search calls:

```bash
cmdgraph search "how to ssh"
cmdgraph search "make file runnable" --json
cmdgraph search "what is using port 3000" --limit 3
```

Explicit subcommands remain unchanged:

```bash
cmdgraph check "rm -rf /"
cmdgraph review --command "git status"
cmdgraph explain chmod
cmdgraph doctor
```

The same default mode is used by `python -m commandgraph`.

## Ambiguity

If the first token is an existing subcommand name such as `check`, `review`, or `search`, CommandGraph treats it as that explicit subcommand. Use `search` explicitly when the intended natural-language query itself begins with a reserved subcommand word.

Bare search supports `--json`, `--limit N`, and `--limit=N`. Use `--` to force all following tokens to be literal query text.
