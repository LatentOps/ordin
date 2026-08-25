# Contributing to Ordin

Ordin is an open-source LatentOps project for local, intent-aware
Linux command discovery and safety review. Contributions should keep the
project local-first, explainable, and useful without cloud services.

## Development setup

Install the project and repository tooling into a development environment:

```bash
python -m pip install -e ".[dev]"
pre-commit install
```

Run the same local quality and integrity gate used by CI:

```bash
pre-commit run --all-files
```

The hooks run Ruff lint and format checks, staged mypy checks for typed API
boundaries, Python compilation, `ordin doctor`, and the Ordin namespace guard.
The hooks use the development dependencies declared in `pyproject.toml`, so
local tooling and CI do not maintain separate tool-version configurations.

The full test suite remains a separate required gate:

```bash
pytest -q
```

## Requirements

Before opening a pull request:

- Run `pre-commit run --all-files`.
- Run `pytest -q`.
- Keep core behavior offline by default.
- Do not add telemetry, command upload, shell history upload, or required remote services.
- Keep dependencies small and justify any new dependency in the pull request.
- Preserve stable schema versions for search, risk review, command review, man indexes, and typed graph exports.

## Command Cards

New or changed command cards must include:

- `schema_version`
- `command`
- `summary`
- `aliases`
- `intents`
- `default_risk`
- `risk_tags`
- at least one safe example when possible
- templates only when slot extraction can fill them predictably

Typed graph metadata is optional for backwards compatibility, but new cards
that cover mutation, network transfer, package changes, source control,
containers, process control, or other safety-relevant behavior should declare
semantic effects when the shared effect catalog has an appropriate term.

Supported graph metadata includes:

- `effects` on a command;
- `flags` with aliases and effects;
- `subcommands` with their own effects and flags;
- `requires_privileges`;
- `safer_alternatives`.

Effect references must exist in `data/effects.json`. Prefer a reusable semantic
effect such as `filesystem.delete` over a command-specific label such as
`rm.delete`.

Template targets must not be invented implicitly. If a template has a benign
default that is safe to apply without additional user intent, declare it
explicitly with `safe_defaults`. Do not use `safe_defaults` to choose mutation
targets such as files, directories, branches, processes, or remote resources.

Command-card pull requests should also include:

- one search test for a natural-language query;
- one graph/effect test when adding typed semantics;
- one risk test when the command can mutate files, permissions, processes, packages, network state, containers, or system configuration;
- conservative wording for risky examples.

Avoid adding destructive examples unless the example is clearly labeled,
narrowly scoped, and paired with a safer inspection step.

## Effect Catalog

Effect catalog changes affect multiple commands and need explicit review.

New effects must include:

- a stable dotted effect name;
- `risk`;
- `category`;
- `description`;
- `reason`;
- `safer_next_step` when the effect is mutating or otherwise elevated.

Use effects to describe observable action semantics, not policy decisions.
Command-specific parsing belongs in command metadata or semantic analyzers;
the catalog should remain reusable across command families.

Run `validate_effect_graph_data()` indirectly through the normal test suite and
`ordin doctor`. Unknown effect references or broken graph relationships
must fail validation.

## Risk Rules

Risk rules affect safety behavior and need stricter review than ordinary metadata.

Changes to risk rules must include:

- tests for the risky command pattern;
- tests that normal read-only commands are not over-blocked when relevant;
- a conservative risk category;
- a clear `safer_next_step`.

Typed effects and risk rules are complementary. Effects provide reusable
command semantics; risk rules remain useful for exact dangerous combinations,
critical path patterns, shell composition, and other cases that require more
specific matching.

False-safe behavior is the highest-priority bug class. If a command can cause
data loss, expose secrets, broaden permissions, terminate processes, install
untrusted code, or mutate infrastructure, prefer warning over silence. If the
command is not classified well enough to establish safety, prefer `ask` over
silently treating it as low risk.

## Man-Page Indexing

The local man-page indexer must remain optional. Ordin should still work
from bundled curated data when `apropos` or `man -k` is unavailable.

Man-page entries intentionally remain valid without typed effects; curated
cards can add richer semantics incrementally.

Tests for index behavior should use saved input text rather than requiring
local man-db tools on the test machine.

## Pull Request Checklist

- Scope is focused and unrelated cleanup is avoided.
- `pre-commit run --all-files` passes.
- Tests pass.
- `python -m ordin doctor` passes.
- New JSON output keeps a schema version.
- Effect references and typed graph relationships validate.
- Command cards and risk rules are conservative.
- Documentation is updated when CLI behavior, graph semantics, or contributor requirements change.
