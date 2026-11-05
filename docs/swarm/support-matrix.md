# Swarm coverage and adoption contract

Status: swarm adoption contract with local host enrollment available. No
universal swarm enforcement is shipped by these documents. Current single-session
features remain available under their
existing [integration](../integration-sessions.md),
[Assurance](../assurance/README.md) and
[OpenShell](../openshell-integration.md) contracts.

## Coverage vocabulary

Coverage is recorded per principal, capability, resource, route and time window,
with the enforcing component and its verified generation. It is not a single
boolean attached to a swarm.

| State | Required evidence | Permitted claim |
| --- | --- | --- |
| Observe-only | Authenticated observations from a stated collection boundary | Report observed effects and gaps; cannot prevent a proposal |
| Mediated | Host controls a stated interceptor/proxy route before forwarding | Gate future calls through that route; direct alternatives remain uncovered |
| Physically enforced | Broker/runtime constrains actual capability use, with verified admission and current fencing | Prevent effects within the explicitly tested capability boundary |
| Unsupported | No adapter or enforcing mechanism exists for the requested semantics | No enforcement plan; reject a request requiring that coverage |
| Coverage-gap | Expected enrollment, event continuity, identity or runtime evidence is missing/stale | Report unknown; deny high-impact actions needing the missing fact |

A successful review, compiler output, replay, complete log or model score cannot
upgrade a coverage state. A route can be mediated while another route for the
same process is unsupported. Coverage expiration or revocation must be visible;
it must never silently become observe-only while retaining an enforcement label.

## Current capabilities versus planned swarm support

| Runtime/integration | Current supported boundary | Planned opt-in swarm work and limitations |
| --- | --- | --- |
| [Local identity registry](identity.md) | Host-bound identity, heartbeat/lifecycle, bounded manifests and local generation/epoch fencing | No action execution, distributed state or physical-enforcement receipt; unlisted routes remain unknown |
| [Local event substrate](events.md) | Protected sender/receipt checks, bounded append-only fixture journal, exact review correlation and explicit sequence/causal gaps | No execution authorization, automatic historical trust restoration or concrete multihost durable backend |
| [Swarm decision composition](gate.md) | Monotonic pure baseline/Assurance/delegation review, protected global-check receipts and exact snapshot binding | No reservation, execution, automatic human approval or physical containment; missing mandatory checks remain conservative |
| [Explicit tool gateway](gateway.md) | One-use host-correlated SDK forwarding plus actor/server MCP and maintained-hook host adapters | Bypassed calls remain gaps; no automatic CLI identity, delegated broker commit or host-wide physical enforcement |
| [Causal graph](causal-graph.md) | Bounded authenticated explicit handoffs, current delegation verification, redacted deterministic projection | Reachability is not exploitation or permission; opaque/unobserved channels remain gaps |
| [Sensitive-data lineage](source-flow.md) | Protected exact-content references, conservative transfer/transform labels and action-bound mediated egress checks | No universal taint tracking; missing handoffs or opaque inputs remain unknown; declassification requires current operator authority |
| [Late attach](late-attach.md) | Explicit authenticated host SDK, verified future dispatch routing, lifecycle fencing, continuity and offline CLI diagnostics | No injection, automatic hook installation, retrospective history or live physical-enforcement admission |
| [Inter-agent messages](messages.md) | Authenticated peer/channel grants, bounded data-only envelopes, replay/rate/TTL checks and inherited lineage with shared callback/queue/RPC adapters | Direct channels remain uncovered; an inbox acceptance is not receiver execution or durable exactly-once delivery |
| [Managed artifacts and shared memory](artifacts.md) | Exact-agent/version/label grants, conditional immutable writes, retention and protected memory/POSIX filesystem backends | Raw backing access and opaque vector queries remain uncovered/unsupported; no automatic multi-host transaction or physical containment |
| [Causal temporal policies](temporal.md) | Bounded DAG patterns and causal quotas with exact current-action/source-use correlation and protected gate assessments | Missing collection or semantics stay unknown; no unrelated-history concatenation, path-only artifact-execution proof or physical enforcement claim |
| [Transactional budgets](budgets.md) | Atomic scoped/ancestor reservations, one-use forwarding, authenticated settlement, SQLite recovery fencing and optional gateway admission | Admission accounting does not physically cap uncapped remote billing; missing hard enforcement remains unsupported; uncertain effects retain holds |
| Python `AgentGate` / `IntegrationSession` | Local review and bounded session history; caller owns execution | Host enrollment and composition; no prevention if caller ignores the decision |
| Native Claude/Codex/Cursor/Hermes hooks | Host-specific pre-tool interception where installed and invoked | Bind enrolled identities; uncovered tools/processes remain gaps |
| MCP stdio / Streamable HTTP proxy | Gate traffic actually routed through the configured proxy | Authenticated swarm context and per-route inventory; direct server access is not covered |
| Assurance delegation | Protected local issuance, subset checking and exact-action commit tickets | Distributed fencing and causal transfer; current local locks do not coordinate hosts |
| OpenShell optional integration | Compile/prove supported capabilities; applied runtime evidence is a separate boundary | Broker admission and generation checks for enrolled agents; unsupported protocols cannot become broad TCP permissions |
| Vetted Linux sandbox fixtures | Isolation and evidence for the documented fixture and supported host | Not a general attach-to-any-process containment service |
| Existing uninstrumented swarm | Protected host endpoint can explicitly attach observation or verified future dispatch mediation without restarting an existing session | Direct sockets, existing credentials and unwrapped executors remain uncovered; unsupported live restrictions require restart |
| LangGraph / CrewAI / AutoGen / custom orchestrators | No swarm-wide framework conformance claim | Dedicated adapters and pinned conformance tests required |
| Shared files, memory, messages and delegated credentials | Existing action review does not prove all accesses are mediated | Enroll the actual storage/transport/credential broker; unwrapped access remains uncovered |

## Late attachment and running processes

Record the attachment time, principal generation, known children, capabilities,
open handles/credentials and inspected routes. Earlier history is unverified.
An observer cannot recover missed effects or authenticate earlier caller logs.
Installing an interceptor only covers subsequent calls through that interceptor.
Existing sockets, file descriptors, subprocesses, cached credentials and direct
tool endpoints require independent containment or explicit gaps.

An operator must see a capability inventory and partial coverage before enabling
a high-impact policy. Physically enforced coverage requires a controlled launch,
verified runtime admission or a supported containment transition that actually
restricts existing authority. If the transition cannot be verified, retain the
gap and deny actions whose authorization requires it. Never claim retroactive
enforcement or infer a clean past from a clean post-attachment trace.

## Adoption and conformance

Adoption proceeds from explicit observation, to verified route mediation, to
tested physical enforcement where available. Each step is independently
configured and reversible by an authorized host/operator; removing protection
invalidates dependent permits before new dispatches. A future release may claim
support only with positive and bypass/negative tests, installed-wheel evidence,
bounded failure behavior and an exact tested version/platform record. Until
those gates exist, the framework and distributed entries above remain planned.

See the [architecture](architecture.md), [threat scenarios](threat-model.md) and
[local-first ADR](adr-001-local-first-coordination.md).
