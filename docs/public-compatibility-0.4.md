# v0.4 public contracts and upgrade policy

The [v0.4 inventory](../data/public-surface-0.4.json), shipped in the core wheel,
records 99 root exports, eight core console scripts, 202 registered schemas,
documented module exports and the five distribution entry-point sets. These
counts describe this source revision. Tests compare the inventory with actual
declarations and packaged resources; intentional additions require an audit.
The [v0.3 inventory](../data/public-surface-0.3.json) remains byte-for-byte intact.
The new inventory's `previous_inventory.sha256_lf` records repository LF bytes
so normal Git checkout line-ending translation does not appear to change the
compatibility baseline.

An inventory entry identifies a public interface and its stability category.
It does not make a report, serialized handle or matching schema an execution
permit. Constructor and method behavior is limited to the linked module guides;
compiled objects and original authority handles are factory results, not an
extension mechanism. Importable private helpers remain internal.

| Surface | v0.4 contract |
| --- | --- |
| Existing core `Ordin`, `AgentGate`, typed actions, policies, sessions and MCP interfaces | Supported documented APIs; existing stable v1 meanings remain intact. Valid v0.2/v0.3 convenience inputs retain their documented defaults. |
| Claude Code, Codex, Cursor and Hermes hooks | Supported only when the actual host invokes the documented hook protocol. Hermes qualification is pinned to v0.21.7. Host execution, permissions and approval remain independent. |
| Existing stable-v1 schemas and Cursor MCP mapping | Supported data interchange. Unknown members, finite-number rules, recursive bounds and semantic checks still apply. |
| Runtime capability/request APIs, including request v2 | Experimental opt-in formats and typed APIs. A runtime contract or compiler result requires separate original backend evidence before an enforcing claim. Unsupported or ambiguous request constraints fail closed. |
| Assurance, Ordin Security and decision-model interfaces | Experimental opt-in analysis, solver, import and validation interfaces; findings and diagnostics confer no execution authority. |
| `ordin.swarm`, `ordin_swarm` and managed MCP host | Experimental opt-in public interfaces with the scoped behavior in the [support matrix](swarm/support-matrix.md). Durable budgets, delegation and human approvals remain original host authority, not restorable JSON grants. |
| LangGraph / AutoGen | Exact pinned framework conformance only. Async callbacks provide interception; native asynchronous broker/coordinator dispatch is unsupported. AutoGen is a legacy, archived integration. |
| CrewAI | Quarantined: no active extra, provisioning or execution, including matching externally installed SDK versions. |
| Diagnostics, trace/promotion formats, optional reranking | Experimental, as in v0.3. A version marker does not freeze every diagnostic field. |
| SQLite layouts, caches, private workers and handle registries | Internal. Do not edit tables, restore live grants from records, subclass private executors or rely on underscore-prefixed helpers. |

Core wire readers still validate their own documented forms. The lightweight
schema validator implements bundled keywords, not an arbitrary JSON Schema
dialect. JSON booleans are distinct from numbers in constants and enums, so
`0` cannot substitute for `false`, including inside nested structures. Numeric
equivalents such as `1` and `1.0` remain equal for those constraints. Tightening
malformed-input acceptance is a correctness fix, not a new permissive reader.

## Platforms and authority

Python 3.10–3.13 core qualification includes the maintained Linux matrix and
macOS 15/Python 3.13 lane. Windows portable installed-package, schema, protocol
and transaction fixtures are useful evidence for those paths; they do not
establish native shell/path-policy compatibility or Windows kernel protection.

Physical worker enforcement requires the supported Linux x86-64 kernel setup
and original Landlock/seccomp/namespace/identity outcomes. An ordinary MCP
client's other processes, sockets, credentials and tools remain outside the
managed service. Protected launch applies to a fresh supported child, not an
arbitrary existing interpreter. Test diagnostics and zero exit status do not
prove arbitrary agent safety. See [compatibility](compatibility.md) and the
[managed host](swarm/managed-tool-host.md) for deployment requirements.

## Upgrade from v0.3

1. Keep the prior environment and verified artifacts. Test v0.4 in a separate
   environment using the [artifact quickstart](quickstart-0.4.md). Installing a
   development checkout is not qualification of a release bundle.
2. Keep core and `ordin-swarm` on the same tested 0.4.0 bundle. Optional
   `ordin-runtime`, `ordin-security` and `ordin-decision-models` have their own
   0.1.0 versions; use the exact set recorded in the bundle manifest. Installing
   a base package does not provision optional SDKs, a prover or a model.
3. Export only documented data forms. Validate v1 readers against the v0.3
   baseline and audit intentional new v2 request forms explicitly. Private
   database tables and serialized authority objects are not migration inputs.
4. Preview hook/setup changes and preserve unrelated host configuration. A new
   hook or MCP route covers only calls actually sent through it. Keep uncovered
   routes visible and deny work that requires missing enforcement evidence.
5. For an existing managed installation, stop admission and reconcile original
   uncertain work before changing executables. Keep intact private state and
   replay history. Follow the host's explicit fresh-epoch restart procedure;
   expired approvals and earlier handles never migrate to a renewed lease.

Use the [packaged pilot procedure](release-pilot-0.4.md) before operator
acceptance. A short fixture run is engineering evidence; it does not establish
an elapsed multi-day pilot or authorize a production rollout.

## Rollback and deprecation

Stop new dispatches first. Retain the original service/cleanup owner until
children and transports actually close; inspect uncertain outcomes and holds
before any retry. Keep an immutable copy of the complete state and exact
artifact/source identity for diagnosis. Never delete budget, replay or
coordinator history to regain capacity.

Return portable review/hook clients to the prior isolated environment and its
matching configuration only after checking their documented v1 forms. Do not
open a v0.4 private database with a v0.3 executable: no down-migration of internal
tables is promised. If the previous version cannot read retained state safely,
keep execution fenced and preserve that installation for reconciliation. A
separate empty test installation is not a continuation of the old authority.

Supported v1 meanings are retained within their documented line. Breaking
interchange changes require a new wire version and migration notes. Planned
removals should be announced one minor line ahead where practical; malformed
input and safety bugs may be rejected immediately with regression tests.
Experimental APIs may evolve with release notes. Future versions must preserve
the historical v0.3 inventory rather than rewriting its compatibility baseline.
