# Ordin

Intent-aware command discovery and safety checks for humans and AI agents.

Ordin is an open-source LatentOps project and an advanced
`apropos`-style tool for Linux terminals. It maps natural-language intent to
relevant commands, examples, templates, typed command effects, and local safety
checks.

## Goals

- Help users find commands by intent, not exact command names.
- Explain why a command matched the user's query.
- Fill simple command templates from query slots like ports, paths, package names, and hosts.
- Show safe examples before mutation.
- Classify command risk before execution.
- Represent command, subcommand, flag, effect, resource, privilege, and safer-alternative relationships explicitly.
- Provide a simple JSON review interface for AI agents.

## Non-Goals

- No automatic command execution by default.
- No cloud dependency.
- No free-form shell generation.
- No replacement for careful operator judgment.

## Example

```bash
ordin search "make file runnable"
```

```text
chmod
  why: matched intent "make script runnable"
  example: chmod +x script.sh
  risk: medium
```

```bash
ordin search "make file runnable" --json
```

```json
[
  {
    "schema_version": "ordin.search_result.v1",
    "command": "chmod",
    "summary": "Change file mode bits and permissions.",
    "risk": "medium"
  }
]
```

```bash
ordin check "git reset --hard HEAD~1"
```

```text
decision: warn
risk: high
- changes local source-control state (subcommand git reset)
- can rewrite or discard source-control history (subcommand git reset flag --hard)
```

```bash
ordin review \
  --intent "clean dependencies" \
  --command "rm -rf node_modules" \
  --json
```

## Installation

For the CLI, the recommended packaged installation is:

```bash
pipx install ordin
```

or:

```bash
uv tool install ordin
```

A normal Python environment can use:

```bash
python -m pip install ordin
```

For an unreleased source checkout:

```bash
python -m pip install .
```

The package installs two equivalent console commands:

```bash
ordin --help
ordin --help
```

The shorter `ordin` command supports bare intent queries directly:

```bash
ordin how to ssh
ordin make file runnable --json
```

See [docs/installation.md](docs/installation.md) for packaged, source, and optional semantic-reranker installation details.

## CLI

```bash
ordin how to ssh
ordin search "what is using port 3000"
ordin search "make file runnable" --json
ordin search 'find files named "*.py" in ./src'
ordin explain chmod
ordin check "cat .env" --json
ordin check "git status --short" --json
ordin review --intent "make file runnable" --command "curl https://example.com" --json
ordin index
ordin doctor --json
```

Machine-readable output includes schema versions so agents can depend on stable
contracts. The bundled graph currently seeds 30 command cards, can suggest
commands from simple templates, can merge an optional local man-page index built
from `apropos` or `man -k`, and can build a typed in-memory effect graph from
curated command metadata.

## Levels

### Level 1: Semantic Apropos

Local command search using:

- bundled command graph files;
- optional local man-page data from `apropos` or `man -k`;
- synonym expansion;
- slot extraction for common values such as ports, paths, packages, hosts, and patterns;
- command templates;
- lightweight scoring;
- command popularity and availability signals later.

Template suggestions do not invent missing path or depth targets. A template
that has a genuinely safe default may opt into it explicitly with
`safe_defaults`; otherwise missing slots leave that suggestion incomplete.

### Level 2: Typed Ordin

Curated command cards can express:

```text
intent -> command
command -> subcommand
command/subcommand -> flag
command/subcommand/flag -> effect
effect -> resource
command -> safer alternative
command -> required privilege
```

The graph is local and built in memory; there is no graph-database dependency.

Effects have a shared vocabulary and policy metadata in `data/effects.json`.
Migrated commands can therefore distinguish behavior inside one executable.
For example, `git status` produces a low-risk read effect while
`git reset --hard` produces a high-risk history-rewrite effect.

See [docs/effect-graph.md](docs/effect-graph.md) for the command-card extensions,
effect catalog, graph API, and validation rules.

### Level 3: Command Guard

Review shell commands before execution:

```text
intent + command + context -> allow / warn / block / ask
```

Decision semantics are conservative:

- `allow`: the command has a known low-risk semantic/default baseline with no higher-risk finding;
- `warn`: Ordin found a known medium/high-risk behavior that should be reviewed before execution;
- `ask`: the command is unclassified, incomplete, or cannot be parsed confidently enough to treat as safe;
- `block`: Ordin found a known critical condition.

Unknown is not treated as safe. Compound shell input is segmented at common
operators such as `&&`, `||`, `;`, and pipes, and risk from any dangerous
segment propagates to the overall review. Shell payloads passed through common
`sh -c`/`bash -c` forms are reviewed recursively, and sensitive output
redirection is surfaced explicitly.

For command cards with typed effects, Command Guard consumes those effects
before falling back to the card's coarse `default_risk`. Existing risk rules
remain active and can still raise the final result, including critical blocks.

### Later Learning

Do not start with RL. Start with retrieval, ranking, templates, typed effects,
and deterministic risk rules.

Later learning can use:

- click and accept/reject feedback;
- supervised learning-to-rank;
- contextual bandits for next suggestion;
- offline/constrained RL only for multi-step planning in sandboxes.

## Project Layout

```text
ordin/
  ordin/          Python package
    graph.py             Typed graph construction + effect resolution
    resources/           Packaged data mirror
  data/
    commands/            Command graph entries
    effects.json         Typed effect catalog and risk metadata
    synonyms.json        Intent expansion terms
    risk_rules.json      Local command risk rules
  docs/
    architecture.md
    effect-graph.md
  examples/
  tests/
```

## Contributing

Contributions should keep Ordin local-first, explainable, and safe by
default. See [CONTRIBUTING.md](CONTRIBUTING.md) for command-card, effect,
risk-rule, testing, and pull request requirements.

## License

Ordin is licensed under the Apache License 2.0. See [LICENSE](LICENSE)
and [NOTICE](NOTICE).
