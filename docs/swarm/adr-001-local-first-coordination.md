# ADR-001: local authority with optional coordination

Status: accepted architecture requirement for the planned opt-in swarm work.
This records a design choice, not an implemented coordinator.

## Context

Ordin's deterministic core is local-first, has no required dependencies or
network service and reviews caller-owned actions without executing them.
Swarm-wide budgets, revocation and cross-host causal transfer need shared state,
but imposing a coordinator on every existing caller would change that contract.
An observer also cannot provide the same guarantees as a controlling broker.

## Decision

Keep the core, `AgentGate`, `ActionEnvelope`, `IntegrationSession`, Assurance
contracts and v0.3 public behavior compatible. Add swarm behavior only through
explicitly configured host integrations. A single host may own identity,
bounded state and atomic local reservations without any network access.

An optional coordinator is required when a policy promises shared transactional
budgets, durable revocation or ordered authenticated transfers across hosts.
The coordinator supplies state authority; it neither orchestrates agents nor
executes tools. The actual broker must validate that authority at dispatch.
Deployment must authenticate both sides, bind every operation to a tenant and
preserve monotonic fences across failover. These protocol/storage details need
their own implementation and adversarial conformance evidence.

If required coordination is unavailable, high-impact actions fail closed.
Explicit preissued offline capabilities may permit narrow bounded work, with
expiry and revocation latency disclosed. No automatic allow fallback, hidden
service discovery or retroactive enforcement is permitted. Operators control
configuration and retention; local redacted evidence remains the default.

## Alternatives and consequences

A mandatory central service would simplify global state ownership but make
offline core callers depend on network availability and remote data handling.
Independent per-host counters cannot enforce a global concurrent budget.
Reconstructing authority from asynchronous logs cannot prevent an effect or
guarantee revocation at use time. None is a substitute for an explicit broker
and an atomic authority boundary.

The chosen approach preserves existing embedding and privacy properties, while
making distributed guarantees more expensive to implement and verify. A local
deployment must not advertise cross-host guarantees it does not provide.
Framework adapters remain thin normalization/enrollment integrations; they do
not get to fork the safety engine or turn semantic inference into authority.

See the [architecture](architecture.md), [coverage contract](support-matrix.md)
and [threat acceptance recipes](threat-model.md).
