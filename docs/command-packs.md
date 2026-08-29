# Command packs

Ordin can load domain-specific command knowledge as versioned local
packs. Packs keep command cards, dedicated risk rules, effect catalogs, and analyzer bindings
outside the core command directory while reusing the shared typed effect
vocabulary and review policy.

## Layout

A built-in pack lives under `data/packs/<name>/` in a source checkout and is
mirrored under `ordin/resources/packs/<name>/` in installed packages:

```text
data/packs/git/
  pack.json
  commands/
    git.json
  risk_rules.json
```

A manifest uses `ordin.command_pack.v1`:

```json
{
  "schema_version": "ordin.command_pack.v1",
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

When `ORDIN_PACKS` is unset, every pack with
`enabled_by_default: true` is loaded.

Use an exact comma-separated list to select packs:

```bash
ORDIN_PACKS=git ordin packs
```

Disable all packs:

```bash
ORDIN_PACKS='' ordin packs
```

Load every discovered pack, including future packs that may default to off:

```bash
ORDIN_PACKS='*' ordin packs
```

Unknown configured names are reported by `ordin doctor` instead of
being silently treated as installed packs.

Inspect the active state:

```bash
ordin packs
ordin packs --json
```

The JSON output uses `ordin.pack_list.v1`.

## Runtime isolation

Pack selection affects the runtime as one unit. If the Git pack is disabled:

- the Git command card is not returned by search or explain;
- Git pack risk rules are not loaded;
- the Git semantic analyzer is not invoked;
- a raw Git command falls back to the normal unclassified/uncertain review.

This avoids the misleading state where metadata looks disabled while hidden
pack-specific policy remains active.

## Infrastructure and remote-action packs

Ordin ships focused packs for the high-value operational domains where command names alone
are not enough to review an action safely:

| Pack | Commands/analyzers | Representative semantics |
| --- | --- | --- |
| `kubernetes` | `kubectl` | resource reads, apply/patch/create, delete, exec, copy, secret output |
| `terraform` | `terraform`, `tofu` | plan/state reads, apply/import, destroy/state removal, provider download |
| `remote` | `ssh`, `scp`, `rsync` | remote connection, remote execution, upload/download, delete synchronization |
| `systemd` | `systemctl`, `journalctl` | service inspection/control, configuration changes, journal cleanup, power state |
| `github` | `gh` | repository/PR reads and writes, API mutation, secrets, auth, downloads/uploads |
| `database` | `psql`, `mysql`, `mariadb`, `sqlite3`, `mongosh`, `redis-cli` | query reads, data/schema writes, destructive queries, permission changes |
| `aws` | `aws` | infrastructure reads/writes/deletes, IAM, secrets, S3 transfer, Lambda invoke |
| `gcloud` | `gcloud` | infrastructure reads/writes/deletes, IAM, secrets, Cloud Storage transfer |
| `azure` | `az` | infrastructure reads/writes/deletes, roles, Key Vault secrets, Blob transfer |

These packs use the existing `ORDIN_PACKS` selection mechanism and are enabled by default.
Each carries the same versioned shared domain-effect vocabulary so any pack remains
independently selectable. Shared effects include infrastructure read/write/delete, remote
execution, service control, database read/write/delete, identity permission changes, secret
writes, and system power changes. Existing core effects such as `network.upload`,
`network.download`, `network.connect`, `secret.read`, `filesystem.write`, and
`confirmation.bypass` are reused instead of duplicated.

Dedicated analyzers are limited to argument-sensitive behavior. For example, `ssh host`
is a low-risk remote connection while `ssh host command` produces `remote.execute`;
`aws s3 cp` distinguishes upload from download; SQL/Redis command text distinguishes
reads from mutations; and cloud identity or secret operations emit structured effects
that generic policy and temporal rules can match.

All semantics are computed from local command text. Tests do not require cloud credentials,
a cluster, a database server, network access, or the corresponding CLI binaries.

## Validation

`ordin doctor` validates all discovered built-in packs, including packs
that are not currently enabled:

- manifest schema and version;
- referenced file existence and safe relative paths;
- command-card schemas and templates;
- risk-rule schemas, regexes, IDs, and risk levels;
- typed effect references;
- analyzer bindings;
- duplicate commands/rules across core and packs;
- source/package resource parity.

Git and Docker remain compact reference packs. The infrastructure packs extend the same
contract without adding remote discovery, credential access, or network-dependent validation.

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
