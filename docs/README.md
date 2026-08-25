# Ordin documentation

Ordin's documentation is organized by the path a command takes through the system.

## Start here

- [Installation](installation.md)
- [Bare intent CLI](bare-intent-cli.md)
- [Architecture](architecture.md)
- [Development workflow](development-workflow.md)

## Command intelligence

- [Search quality benchmark](search-quality-benchmark.md)
- [Deterministic ranking](deterministic-ranking.md)
- [Availability and Linux platform signals](availability-and-platforms.md)
- [Optional semantic reranking](semantic-reranking.md)
- [Command packs](command-packs.md)

## Safety and semantics

- [Typed effect graph](effect-graph.md)
- [Semantic analyzers](semantic-analyzers.md)
- [Context-aware review](context-aware-review.md)
- [Trace-aware review](trace-aware-review.md)
- [Enforcement and exit codes](enforcement.md)
- [Interactive shell integration](shell-integration.md)

## Contracts and releases

- [Schema contracts](schema-contracts.md)
- [Releasing Ordin](releasing.md)

The core design rule across these layers is monotonic safety: richer semantic, contextual, or trajectory evidence may elevate a review decision, but it must not weaken an already stronger finding.
