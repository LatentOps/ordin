# Contributing to CommandGraph

CommandGraph is an open-source LatentOps project for local, intent-aware
Linux command discovery and safety review. Contributions should keep the
project local-first, explainable, and useful without cloud services.

## Requirements

Before opening a pull request:

- Run `pytest -q`.
- Run `python -m commandgraph doctor`.
- Keep core behavior offline by default.
- Do not add telemetry, command upload, shell history upload, or required remote services.
- Keep dependencies small and justify any new dependency in the pull request.
- Preserve stable JSON schema versions for search, risk review, command review, and man indexes.

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

Template targets must not be invented implicitly. If a template has a benign
default that is safe to apply without additional user intent, declare it
explicitly with `safe_defaults`. Do not use `safe_defaults` to choose mutation
targets such as files, directories, branches, processes, or remote resources.

Command-card pull requests should also include:

- one search test for a natural-language query
- one risk test when the command can mutate files, permissions, processes, packages, network state, containers, or system configuration
- conservative wording for risky examples

Avoid adding destructive examples unless the example is clearly labeled, narrowly scoped, and paired with a safer inspection step.

## Risk Rules

Risk rules affect safety behavior and need stricter review than ordinary metadata.

Changes to risk rules must include:

- tests for the risky command pattern
- tests that normal read-only commands are not over-blocked when relevant
- a conservative risk category
- a clear `safer_next_step`

False-safe behavior is the highest-priority bug class. If a command can cause
data loss, expose secrets, broaden permissions, terminate processes, install
untrusted code, or mutate infrastructure, prefer warning over silence. If the
command is not classified well enough to establish safety, prefer `ask` over
silently treating it as low risk.

## Man-Page Indexing

The local man-page indexer must remain optional. CommandGraph should still work
from bundled curated data when `apropos` or `man -k` is unavailable.

Tests for index behavior should use saved input text rather than requiring
local man-db tools on the test machine.

## Pull Request Checklist

- Scope is focused and unrelated cleanup is avoided.
- Tests pass.
- `python -m commandgraph doctor` passes.
- New JSON output keeps a schema version.
- Command cards and risk rules are conservative.
- Documentation is updated when CLI behavior or contributor requirements change.
