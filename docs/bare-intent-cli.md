# Bare intent CLI mode

The installed `ordin` command treats natural-language text as search by default.

```bash
ordin how to ssh
ordin make file runnable --json
ordin what is using port 3000 --limit 3
```

These are equivalent to explicit search calls:

```bash
ordin search "how to ssh"
ordin search "make file runnable" --json
ordin search "what is using port 3000" --limit 3
```

Explicit subcommands remain unambiguous:

```bash
ordin check "rm -rf /"
ordin review --command "git status"
ordin explain chmod
ordin graph
ordin packs
ordin doctor
```

The same normalization is available through `python -m ordin` for source checkouts and Python-module invocation.

## Ambiguity

If the first token is an existing subcommand name such as `check`, `review`, or `search`, Ordin treats it as that explicit subcommand. Use `search` explicitly when a natural-language query itself begins with a reserved subcommand word.

Bare search supports `--json`, `--limit N`, and `--limit=N`. Use `--` to force all following tokens to be literal query text.
