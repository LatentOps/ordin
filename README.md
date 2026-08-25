# Ordin

**Local command intelligence and pre-execution safety for humans and AI agents.**

Ordin turns shell intent and command text into structured, explainable decisions. It can find commands from natural language, resolve typed command effects, review risky actions with execution context, reason over recent action traces, and provide an opt-in shell gate before execution.

Ordin is local-first. Core search and safety review do not require a cloud service, telemetry, or remote command execution.

## What Ordin does

```text
natural-language intent
        |
        v
command discovery ---------> examples / templates
        |
        v
shell parsing + normalization
        |
        v
semantic analyzers + typed effects
        |
        v
context + recent action trace
        |
        v
policy evaluation
        |
        v
allow / warn / ask / block
```

The same engine is usable from a terminal, shell integration, or machine-readable JSON interface for agents.

## Install

For the CLI, use an isolated tool environment:

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

For an unreleased checkout:

```bash
git clone https://github.com/LatentOps/ordin.git
cd ordin
python -m pip install .
```

Ordin installs one canonical command:

```bash
ordin --help
```

See [docs/installation.md](docs/installation.md) for development and optional semantic-reranker installation.

## Quick start

Search directly from natural language:

```bash
ordin how to ssh
ordin make file runnable --json
ordin what is using port 3000 --limit 3
```

Explicit search is also available:

```bash
ordin search "find large files"
```

Inspect the semantic knowledge Ordin has about a command:

```bash
ordin explain chmod
ordin graph --json
ordin packs
```

Review a command before execution:

```bash
ordin check "git reset --hard HEAD~1"
```

Example result:

```text
decision: warn
risk: high
- changes local source-control state
- can rewrite or discard source-control history
```

Add intent and execution context:

```bash
ordin review \
  --intent "clean generated dependencies" \
  --command "rm -rf node_modules" \
  --cwd "$PWD" \
  --json
```

Machine callers can send a versioned review request through stdin:

```bash
cat request.json | ordin review --stdin --json
```

## Safety model

Ordin uses four decisions:

- **allow**: known low-risk behavior with no stronger finding.
- **warn**: known elevated behavior that should be reviewed before execution.
- **ask**: Ordin cannot establish enough semantic confidence to treat the action as safe.
- **block**: a known critical condition was detected.

Unknown commands are not silently treated as safe.

Review combines several layers:

1. shell-aware parsing of compound commands, pipelines, substitutions, and shell payloads;
2. semantic analyzers for high-value command families;
3. typed effects such as filesystem deletion, network upload, privilege escalation, package installation, source-control mutation, and container changes;
4. exact risk rules for dangerous combinations;
5. optional execution context such as working directory, repository boundary, privilege level, shell, and agent identity;
6. bounded trace-aware rules for multi-action sequences such as secret read → network upload or download → permission change → execute.

A later layer can raise a decision, but it does not weaken a stronger safety finding from an earlier layer.

## Command intelligence

Ordin's search path is deterministic by default. It combines BM25-style lexical retrieval with intent, alias, template, local command availability, and Linux distribution signals.

```bash
ordin search "lookup dns for example.com" --json
```

An optional local semantic reranker can rerank only a bounded deterministic candidate set. It is not part of the default dependency set and Ordin does not automatically download a model.

```bash
python -m pip install "ordin[semantic]"
```

See [docs/semantic-reranking.md](docs/semantic-reranking.md).

## Typed effect graph

Curated command metadata can express relationships such as:

```text
intent -> command
command -> subcommand
command/subcommand -> flag
command/subcommand/flag -> effect
effect -> resource
command -> safer alternative
command -> required privilege
```

The graph is built locally in memory and does not require a graph database.

```bash
ordin graph
ordin graph --json
```

See [docs/effect-graph.md](docs/effect-graph.md) and [docs/schema-contracts.md](docs/schema-contracts.md).

## Shell integration

Shell integration is explicit and reversible. Ordin does not modify shell startup files automatically.

For Bash:

```bash
source <(ordin shell-init bash)
orun 'git status --short'
orun 'rm -rf ./build'
```

For Zsh:

```zsh
source <(ordin shell-init zsh)
```

The Zsh integration also provides an opt-in review widget. See [docs/shell-integration.md](docs/shell-integration.md).

## Machine-readable contracts

Public payloads carry stable schema versions under the Ordin namespace, for example:

```json
{
  "schema_version": "ordin.review_request.v1",
  "command": "git status --short"
}
```

Schemas are published in [`schemas/`](schemas/) and packaged with the Python distribution. `ordin doctor` validates schemas, resources, command packs, risk rules, templates, and graph relationships.

## Repository layout

```text
ordin/              Python package and packaged resources
data/               Curated command cards, effects, packs, and risk rules
schemas/            Public JSON Schema contracts
benchmarks/         Search-quality fixtures
examples/           Example machine-readable requests
docs/               Architecture and feature documentation
tests/              Unit, integration, packaging, and safety tests
.github/workflows/  CI and release pipelines
```

The source data and packaged resource mirror are validated for parity in CI.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check ordin tests
ruff format --check ordin tests
pytest -q
python -m ordin doctor
```

Pull requests also run staged mypy checks, Python 3.10–3.13 tests, wheel/sdist validation, clean installed-CLI smoke tests, and packaged installation checks on Debian and Fedora.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/development-workflow.md](docs/development-workflow.md).

## Design constraints

Ordin intentionally does not:

- execute commands automatically by default;
- require a cloud service for core behavior;
- upload shell history or command text;
- generate arbitrary shell programs from free-form prompts;
- treat unclassified behavior as safe.

## License

Ordin is licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
