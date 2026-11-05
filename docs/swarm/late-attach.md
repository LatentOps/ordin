# Attach to an existing host session

The opt-in `SwarmAttachManager` attaches Ordin's local registry and gateway to
an already-running host session. It does not inject into a process, discover
agents by executable name, install hooks silently or retrofit a sandbox.
The maintained `ordin_swarm.attach` and `ordin_swarm.coverage` modules expose
the same SDK.

## Authenticated host integration

The host connector first authenticates its integration channel and discovers
the actual runtime session. Bind that original adapter with the registry's
`bind_channel`, then construct a protected `HostSessionEndpoint`. Its
`identify` callback returns the same original `RunningSessionIdentity` handle
while the session exists, or `None` after disconnection. It must not build
identities from model text, process names, JSON headers or caller assertions.

The endpoint's `get_router` and optional `set_router` callbacks inspect and
replace the runtime host's actual future-call dispatch entry. The callback
must affect the existing runtime, rather than a separate unused dispatch table.
These are protected integration functions, not callbacks loaded from policy
or agent-supplied code. The host must control endpoint objects, session/channel
handles, discovery, route configuration and executors.

Construct a manager with the same registry, event ingestor, gateway and swarm
gate. Call `register(endpoint)`, inspect `attach(handle, dry_run=True)`, then
`attach(handle)` explicitly. Registration and planning do not change routing.
No process ID or process name supplied by an agent can authenticate this API.
The existing host's authenticated connector remains responsible for identifying
the actual process/session behind its protected channel.

## Coverage and lifecycle

`AttachCoverage` lists supported future routes, explicit observed pathways,
and paths requiring restart. In `observe` mode, attachment leaves the host's
dispatcher unchanged. Only listed connected telemetry pathways are described
as observe-only. It cannot stop an action.

In `intercept` mode the manager enrolls a fresh context, installs a
`MediatedSessionRouter` into that actual dispatch entry, then verifies the
original installed object. The router checks session liveness and route
ownership before every call, and reuses the ordinary gateway prepare/forward
sequence. Warnings, unknown actions and stronger core findings retain their
existing restrictions. Unsupported restart-required routes receive no ticket.
No approval UI is inferred from attachment.
An optional protected `assessment_provider` supplies fresh action/snapshot-bound
receipts through the existing gateway API. Mandatory checks remain unknown and
restricted when that provider does not establish them.

The synthetic two-agent regression host starts its worker threads before
attachment. Observation and mediation attach without restarting either worker.
This is a tested host integration boundary; it is not automatic compatibility
with every framework or native CLI. A runtime that cannot change its live
dispatch entry must report restart-required or remain observable only.

Inventory always includes hooks, MCP, SDK, gateway, outbound network,
credentials and executor paths. Wrapped HTTP calls do not establish host-wide
outbound-network control. Existing sockets, direct commands and existing
credentials remain uncovered unless an actual enforcing runtime controls them.
Diagnostics prescribe explicit credential revocation/rotation, egress routing
or a stop/restart in a constrained runtime. Attachment performs none of those
host configuration changes automatically.

`enforce` refuses attachment: this API has no verified live enforcing-broker
admission. A requested physical restriction cannot become a mediation label
merely because it cannot be applied live.

Attach/detach are idempotent for the original endpoint and session. Detach
fences the registry context, pending tickets and retained gateway facades,
then restores the preceding route only if its own router is still installed.
It waits for a currently mediated host callback to finish; it cannot undo
effects already in flight. It does not overwrite a newer dispatcher installed
by another host component. Restore failures remain explicit.

Reattachment preserves the actual host agent/session identity and issues a
new registry generation. Earlier contexts, source handles, routers and tickets
cannot be reused. A replaced original identity handle, foreign channel,
expired heartbeat, closed channel or lost routing fails closed. Status checks
fence lost/stale attachments and downgrade effective coverage. Limits on
sessions, registry entries, retained journal sources and events are explicit;
exhaustion rejects attachment rather than forgetting identity history.

## Event continuity

Every attachment reports `pre_attach_history: unknown`. No empty initial
journal proves benign past behavior. `context(handle)` returns the protected
current context and event-source handle to the host collector.

Submit events through `ingest` using the local attach clock, current identity
and source sequence starting at one. Events predating enrollment are rejected;
sequence or causal gaps keep the current window unknown, including after late
backfill. An explicitly configured original `RuntimeEvidenceSource` may
supply matching original observations through `ingest(..., observation=...)`;
ordinary host telemetry cannot invent backend-observed authority.

An uninterrupted current stream can report `continuous_since_attach`.
Disconnect/detach and reattach reset that window to unknown. These facts must
be used by mandatory temporal/coverage policies; a status label is not an
execution permit or proof that uninstrumented history is safe.

## CLI and diagnostics

Preview the host requirements without changing a runtime:

```bash
ordin swarm attach --dry-run --mode intercept --route shell --route mcp --json
```

Standalone CLI planning has no authenticated host endpoint, so it explicitly
reports `supported: false` and the missing host requirement. Live attachment
uses the protected SDK inside the existing host. The CLI never restores
attachment authority from a report or imports an arbitrary connector.

Export `manager.status(handle)` explicitly from the host, then inspect it:

```bash
ordin swarm status --report ./attach-status.json --json
ordin swarm doctor --report ./attach-status.json --json
```

The CLI labels that input `report_source: untrusted_file` and
`verified_live: false`. It validates bounded closed schemas, rejects duplicate
keys and incomplete pathway inventories, and does no network access or
implicit home-directory discovery. Live `status` and `doctor` are available
through the protected manager. Reports redact agent/session identifiers into
digests and never claim physical enforcement or execution authority.

Contracts:
[attach plan](../../schemas/swarm-attach-plan.v1.schema.json),
[attach status](../../schemas/swarm-attach-status.v1.schema.json).
