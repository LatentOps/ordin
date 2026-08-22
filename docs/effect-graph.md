# Typed Command and Effect Graph

CommandGraph keeps its graph local and deterministic. The graph is built in
memory from versioned command cards and the bundled effect catalog; it does not
require a graph database, hosted model, or network service.

## Graph Model

The graph uses typed nodes:

- `command`
- `intent`
- `subcommand`
- `flag`
- `effect`
- `resource`
- `privilege`

and typed relationships:

- `intent --satisfies--> command`
- `command --contains--> subcommand`
- `command/subcommand --contains--> flag`
- `command/subcommand/flag --produces--> effect`
- `effect --affects--> resource`
- `command --safer_alternative--> command`
- `command --requires--> privilege`

The public graph export uses
`commandgraph.effect_graph.v1`.

## Command Card Extensions

The original `commandgraph.command_card.v1` fields remain valid. Typed graph
metadata is additive, so older cards continue to load.

A command-level effect:

```json
{
  "command": "rm",
  "effects": [
    {
      "effect": "filesystem.delete",
      "resource": "filesystem.target"
    }
  ]
}
```

Flag-specific effects:

```json
{
  "flags": {
    "-r": {
      "aliases": ["-R", "--recursive"],
      "effects": [
        {
          "effect": "filesystem.recursive_delete",
          "resource": "filesystem.target"
        }
      ]
    }
  }
}
```

Subcommand-specific effects:

```json
{
  "subcommands": {
    "reset": {
      "effects": [
        {
          "effect": "git.local_write",
          "resource": "repository"
        }
      ],
      "flags": {
        "--hard": {
          "effects": [
            {
              "effect": "git.history_rewrite",
              "resource": "repository"
            }
          ]
        }
      }
    }
  }
}
```

Optional graph relationships:

```json
{
  "requires_privileges": ["container_runtime_access"],
  "safer_alternatives": [
    {
      "command": "find",
      "reason": "Preview the target set before deleting recursively."
    }
  ]
}
```

`requires_privileges` names a local capability or privilege boundary; it does
not assert that CommandGraph can verify that capability yet. Context-aware
verification is a later layer.

## Effect Catalog

`data/effects.json` is the canonical local vocabulary. The packaged mirror is
`commandgraph/resources/effects.json`.

Each effect defines:

- risk level;
- risk category;
- description;
- human-readable reason;
- optional safer next step.

Examples include:

- `filesystem.read`
- `filesystem.delete`
- `filesystem.recursive_delete`
- `filesystem.permission_change`
- `network.download`
- `network.upload`
- `process.signal`
- `package.install`
- `git.read`
- `git.remote_write`
- `git.history_rewrite`
- `container.read`
- `container.delete`
- `container.prune`

Effect names are intentionally about observable action semantics rather than a
particular CLI syntax.

## Safety Evaluation

Command review now has two complementary evidence layers:

```text
shell input
  |
  +--> known risk rules
  |
  +--> command-card semantics
          |
          +--> command effects
          +--> subcommand effects
          +--> flag effects
  |
  +--> conservative decision merge
          |
          +--> allow / warn / ask / block
```

If a migrated command produces semantic effects, their catalog risk is used
instead of the command card's coarse `default_risk`. This allows, for example,
`git status` to be treated as a low-risk read while `git reset --hard` is
elevated to high risk.

Existing regex rules remain active. A critical rule such as deletion of the
filesystem root still overrides a lower semantic baseline. Commands without
typed semantic metadata continue to use `default_risk`, preserving backwards
compatibility while cards are migrated incrementally.

## Validation

`validate_effect_graph_data()` checks:

- effect catalog risk/category/reason fields;
- unknown effect references;
- malformed `flags` and `subcommands` metadata;
- malformed privilege relationships;
- missing safer-alternative command references;
- graph construction invariants.

`commandgraph.data.data_health()` includes graph errors and graph node/edge
counts. `commandgraph doctor --json` therefore exposes graph health today;
broader JSON Schema validation is tracked separately.

## Scope Boundary

This layer deliberately does not implement command-specific parsing heuristics
for every CLI. The generic resolver understands command-level effects,
subcommands, multi-token subcommands, aliases for flags, short flag bundles,
and `python -m <module>` normalization.

Richer command-family analyzers, execution context, and trajectory-aware
semantics build on this graph rather than expanding the graph loader into a
complete shell or application parser.
