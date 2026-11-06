# Ordin swarm extension

Ordin's swarm APIs compose existing action review with authenticated agent
identity, data lineage, shared budgets, current delegation and explicit host
mediation. Core review remains local and usable without a coordinator, model,
framework SDK, database driver or network service.

The optional `ordin-swarm` package supplies maintained host adapters and fixture
entry points. PostgreSQL is an optional dependency for a central multi-host
authority; SQLite is for a single host or development. Install only the adapter
extras and exact versions you intend to operate.

Start with the [offline quickstart](quickstart.md), then read the
[architecture](architecture.md), [trust model](threat-model.md),
[coverage matrix](support-matrix.md) and [operator runbook](operator-runbook.md).
The [framework guide](framework-adapters.md) records pinned LangGraph and CrewAI
coverage and the separate legacy AutoGen compatibility boundary.

## Adoption stages

1. Enroll original host sessions and record actual routing/coverage. Observation
   collects evidence without controlling execution. Earlier history is unknown.
2. Compare shadow decisions on the same bounded workload. Shadow output is data,
   never a forwarding ticket or production approval.
3. Enable a narrow mediated canary with original gateway/broker bindings. Verify
   allowed and refused calls, stale-ticket rejection and direct-path coverage.
4. Request restricted physical enforcement only on a supported owned route after
   actual backend validation and current operator approval. Preserve unknown or
   unsupported paths in the inventory.

Stage transitions require protected operator configuration and a fresh policy
epoch where authority changes. JSON reports, model recommendations and a clean
simulation do not approve deployment. A default installation starts no service,
attaches no running process and enables no automatic incident response.

## Host integration guides

- [Identity and lifecycle](identity.md), [authenticated events](events.md) and
  [causal graph](causal-graph.md).
- [Pure decision composition](gate.md), [tool gateway](gateway.md),
  [running-agent attachment](late-attach.md) and [framework adapters](framework-adapters.md).
- [Source flow](source-flow.md), [messages](messages.md), [artifacts](artifacts.md)
  and [temporal rules](temporal.md).
- [Budgets](budgets.md), [online delegation and credentials](distributed-delegation.md),
  [owned enforcing broker](enforcing-broker.md) and [durable coordinator](coordinator.md).
- [Policy reload](policies.md) and [incident containment/recovery](containment.md).

The owned Linux read-file worker proves enforcement for its exact fresh child
route. It does not confine an existing host process or all of its tools,
credentials, descriptors and sockets. Applied OpenShell policy admission,
authenticated host callbacks and observed kernel outcomes remain separate
evidence categories. The release manifest must retain those distinctions.
