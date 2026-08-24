# Command packs

CommandGraph can load domain-specific command knowledge as versioned local
packs. Packs keep command cards, dedicated risk rules, and analyzer bindings
outside the core command directory while reusing the shared typed effect
vocabulary and review policy.

## Layout

A built-in pack lives under `data/packs/<name>/` in a source checkout and is
mirrored under `commandgraph/resources/packs/<name>/` in installed packages:

```text
data/packs/git/
  pack.json
  commands/
    git.json
  risk_rules.json
```

A manifest uses `commandgraph.command_pack.v1`:

```json
{
  "schema_version": "commandgraph.command_pack.v1",
  "name": "git",
  "version": "1.0.0",
  "description": "Git source-control commands and safety metadata.",
  "enabled_by_default": true,
  "commands": ["commands/git.json"],
  "risk_rules": ["risk_rules.json"],
  "effect_catalogs": [],
  "analyzers": ["git"]
}
```

The manifest can contribute:

- command-card files;
- risk-rule bundle files;
- additional effect-catalog files;
- names of command-family analyzers registered by the Python package.

Paths are pack-relative and may not escape the pack directory.

## Loading

When `COMMANDGRAPH_PACKS` is unset, every pack with
`enabled_by_default: true` is loaded.

Use an exact comma-separated list to select packs:

```bash
COMMANDGRAPH_PACKS=git commandgraph packs
```

Disable all packs:

```bash
COMMANDGRAPH_PACKS='' commandgraph packs
```

Load every discovered pack, including future packs that may default to off:

```bash
COMMANDGRAPH_PACKS='*' commandgraph packs
```

Unknown configured names are reported by `commandgraph doctor` instead of
being silently treated as installed packs.

Inspect the active state:

```bash
commandgraph packs
commandgraph packs --json
```

The JSON output uses `commandgraph.pack_list.v1`.

## Runtime isolation

Pack selection affects the runtime as one unit. If the Git pack is disabled:

- the Git command card is not returned by search or explain;
- Git pack risk rules are not loaded;
- the Git semantic analyzer is not invoked;
- a raw Git command falls back to the normal unclassified/uncertain review.

This avoids the misleading state where metadata looks disabled while hidden
pack-specific policy remains active.

## Validation

`commandgraph doctor` validates all discovered built-in packs, including packs
that are not currently enabled:

- manifest schema and version;
- referenced file existence and safe relative paths;
- command-card schemas and templates;
- risk-rule schemas, regexes, IDs, and risk levels;
- typed effect references;
- analyzer bindings;
- duplicate commands/rules across core and packs;
- source/package resource parity.

Git and Docker are the first two built-in packs and serve as reference
implementations for future Kubernetes, cloud CLI, and database packs.

## Contribution rules

A new pack should stay narrowly scoped to one domain and include:

1. a versioned manifest;
2. safe command examples;
3. typed effects for known operations;
4. dedicated risk rules only when generic typed effects are insufficient;
5. a semantic analyzer only when command-specific option grammar requires it;
6. tests for default loading and selective/disabled behavior;
7. mirrored packaged resources.

Packs remain local data/code. The pack system does not download remote content
or discover third-party code at runtime.
