# Ordin documentation

Start with what you are trying to do. The implementation details are linked after the user-facing paths.

## I want to install Ordin or use it from a terminal

- [Installation](installation.md)
- [Bare intent CLI](bare-intent-cli.md)
- [Generic action review](action-review.md)
- [Interactive shell integration](shell-integration.md)
- [Enforcement and exit codes](enforcement.md)

Typical commands:

```bash
ordin what is using port 3000
ordin check "git reset --hard HEAD~1"
cat action.json | ordin action --stdin --json
source <(ordin shell-init bash)
orun 'git status --short'
```

## I want to embed Ordin in an application

- [Python API](python-api.md)
- [Generic action review](action-review.md)
- [Schema contracts](schema-contracts.md)
- [Context-aware review](context-aware-review.md)
- [Trace-aware review](trace-aware-review.md)

The Python API reviews actions but never executes them.

## I want to gate an AI agent

- [Agent runtime integration](agent-integration.md)
- [Generic action review](action-review.md)
- [Python API](python-api.md)
- [Trace-aware review](trace-aware-review.md)
- [Enforcement and exit codes](enforcement.md)

The canonical integration is:

```text
agent proposes action -> Ordin -> execute / escalate / deny -> caller runtime
```

Ordin does not become the agent framework, shell executor, sandbox, or approval service.

## I want to understand how Ordin decides

- [Architecture](architecture.md)
- [Generic action review](action-review.md)
- [Typed effect graph](effect-graph.md)
- [Semantic analyzers](semantic-analyzers.md)
- [Context-aware review](context-aware-review.md)
- [Trace-aware review](trace-aware-review.md)

## I want to understand command discovery

- [Search quality benchmark](search-quality-benchmark.md)
- [Deterministic ranking](deterministic-ranking.md)
- [Availability and Linux platform signals](availability-and-platforms.md)
- [Optional semantic reranking](semantic-reranking.md)
- [Command packs](command-packs.md)

## I want to extend or contribute to Ordin

- [Development workflow](development-workflow.md)
- [Generic action review and adapter contract](action-review.md)
- [Command packs](command-packs.md)
- [Schema contracts](schema-contracts.md)
- [Releasing Ordin](releasing.md)
- [Contributing guidelines](../CONTRIBUTING.md)

The local quality contract is:

```bash
python -m pip install -e ".[dev]"
pre-commit install
pre-commit run --all-files
pytest -q
```

The core design rule across safety layers is conservative composition: richer semantic, contextual, or trajectory evidence must not erase a known stronger risk finding. Execution policy is applied separately by the caller or shell integration.
