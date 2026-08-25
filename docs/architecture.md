# Ordin architecture

Ordin is a local action-intelligence and pre-execution safety engine. Command discovery and action safety share curated semantics, but ranking, semantic evidence, temporal reasoning, and caller policy remain separate stages so one layer cannot silently fabricate authority for another.

## End-to-end pipeline

```text
natural-language intent -> deterministic search -> command candidates

proposed action
      |
      v
structural parsing / adapter normalization
      |
      v
semantic analyzers + typed effects + resources
      |
      v
single-action safety review
      |
      +--> execution context
      +--> exact risk rules
      +--> bounded action history
      |        |
      |        v
      |   temporal state machines
      |        |
      +--------+
      |
      v
caller-owned declarative policy
      |
      v
allow / warn / ask / block
```

The deterministic core requires no hosted service.

## 1. Command intelligence

Search maps user intent to known command metadata using BM25-style lexical retrieval plus intent, aliases, templates, local executable availability, and Linux distribution compatibility. Optional local semantic reranking can reorder only a bounded deterministic candidate set and cannot bypass safety review.

## 2. Action normalization

Shell actions are parsed structurally instead of treating the full string as one regex target. Generic action envelopes let future adapters represent file, network, MCP, database, and tool actions without pretending they are shell commands.

Adapters may produce confident semantics only when deterministic logic or curated metadata establishes them. Unsupported action semantics remain `ask`.

## 3. Semantic evidence

Dedicated analyzers and the typed graph produce reusable effects and resources, for example:

```text
rm -rf ./build
  -> filesystem.delete
  -> filesystem.recursive_delete
  -> path:/workspace/repo/build

curl --data-binary @payload.json https://example.com
  -> network.upload
```

Effects describe what happens; resources describe what is targeted. Policy decisions are applied later.

## 4. Context-aware review

Callers may provide working directory, shell, effective UID, interactive state, repository root, and agent/runtime identity. Missing context stays unknown rather than being inferred as benign.

## 5. Bounded temporal review

Generic callers can provide up to 32 prior `ActionEnvelope` values through `ActionHistory`. Legacy command `ActionTrace` is retained as a compatibility surface and is normalized through the same temporal engine.

Multi-action behavior is described by `ordin.temporal_policy_set.v1` data and compiled into deterministic bounded state machines. The default rules preserve the original trajectory detections:

- secret read -> network upload
- download -> permission change -> execute
- repeated destructive actions
- repeated privilege escalation

A temporal rule matches only when its final step is satisfied by the current action. A sequence that occurred entirely in old history therefore does not automatically contaminate an unrelated new action.

The temporal engine is bounded by 32 prior actions, 128 rules, eight steps per rule, 64 signals per step, and at most 32 live states per rule. Temporal evidence can only preserve or strengthen the current review.

## 6. Declarative caller policy

`ordin.policy_set.v1` applies caller-owned constraints over normalized action kind, operation, effects, resources, context, agent identity, intent state, risk, decision, and temporal categories.

The policy language is data-only and explicit. It has no callbacks, shell execution, expression language, hidden discovery, or remote fetching. Policy conflict resolution uses execution order `allow < warn < ask < block` and cannot downgrade a stronger core safety requirement.

## 7. Interfaces

The same engine is exposed through:

- `ordin` CLI
- Python API
- versioned JSON action/review/history/policy schemas
- Bash/Zsh shell integration
- `AgentGate`
- typed graph export and command packs

Core review APIs never execute the reviewed action.

## Project boundaries

Ordin deliberately does not provide remote command execution, automatic history upload, required cloud inference, arbitrary shell generation, hidden policy synchronization, or a centralized enterprise control plane. External runtimes can use Ordin as a local decision primitive while retaining ownership of execution, sandboxing, approval, and persistence.
