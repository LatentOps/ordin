# Local host enrollment and identity

`ordin.swarm` provides an opt-in identity registry for a trusted host integration.
It starts no services, scans no processes, reads no global configuration and
changes no `ActionEnvelope` or `IntegrationSession` serialization. Each registry
is scoped to one tenant and swarm. A host with multiple scopes creates separate
registries and keeps them outside agent control.

```python
from ordin.swarm import CoverageEntry, CoverageManifest, InMemoryAgentRegistry

registry = InMemoryAgentRegistry("tenant-1", "swarm-1")
adapter = object()  # Replace with the host's already verified adapter instance.
channel = registry.bind_channel(adapter, runtime_id="python-worker")
context = registry.enroll(
    channel,
    adapter,
    agent_id="worker-1",
    session_id="session-1",
    task_id="task-1",
    coverage=CoverageManifest("intercept", (
        CoverageEntry("tool.read", "mcp-proxy", "/workspace", "proxy-1", "mediated"),
        CoverageEntry("network", "direct", "*", "host-1", "coverage_gap"),
    )),
)
registry.authenticate(context, channel, adapter)
registry.heartbeat(context, channel, adapter)
print(context.as_dict())
```

The host must verify the adapter and its actual transport before binding it.
The example opaque object demonstrates reference binding only; it does not
attest a process, container, operating-system user or remote worker. A claimed
PID, runtime name, agent-signed JSON or model-authored tool argument is never
proof of origin. Do not expose registry administration or protected channel
objects to agents. As with existing Assurance host objects, hostile code sharing
the host's memory is outside this in-process API boundary.

## Authoritative context and lifecycle

`SwarmIdentity` binds tenant, swarm, agent, runtime, session, task, parent,
parent generation, delegation reference, policy epoch and issuance generation.
`SwarmContext` adds registry incarnation, enrollment time and a bounded coverage
manifest. Its [v1 schema](../../schemas/swarm-context.v1.schema.json) is shipped
in both source and installed packages. `from_dict()` restores inspectable data;
even an exact round trip cannot authenticate. Only the original current context,
issuing registry, channel and exact protected adapter reference authenticate.
Mutating an issued context also invalidates it.

Restoration bounds keys, collections and enum types before schema validation.
Validation errors omit rejected payload values and property names.

The host advances lifecycle explicitly: `pause()`, `end()`, `restart()` and
`close_channel()`. Restart requires the previous protected binding and a new
session ID, issues a higher generation and defaults coverage back to `uncovered`.
It can bind a new verified adapter/channel without reviving the old context.
Heartbeat expiry is checked at every authentication; an expired heartbeat cannot
renew itself. `state()` returns `active`, `paused`, `ended` or `stale` without
creating authority. No background clock or cleanup thread is started.

`advance_policy_epoch()` only increases the epoch and fences all older contexts.
They require explicit reissuance. Parent references bind a generation, so a
parent restart, pause, expiry or removal invalidates dependent authentication;
reusing its ID does not reparent children. These are identity relationships, not
capability grants: a delegation reference does not replace Assurance delegation
issuance, subset checks, approval or an enforcing broker.

The memory backend is deterministic with an injected monotonic clock and an
explicit registry ID. The default ID is a fresh UUID. A host-supplied registry ID
must be unique per incarnation. A new registry accepts none of an older
registry's channels or context objects, even if serialized IDs match. This is
local fencing, not durable coordination between live hosts.

## Coverage and limits

Attach modes are `observe`, `intercept`, `enforce` and `uncovered`. They describe
requested enrollment mode; they do not attest interception. Manifest entries
identify a capability, route, resource, boundary and coverage state. Unlisted
capabilities remain unknown. Late enrollment records its current time and does
not authenticate earlier history, inherited handles or alternate tool routes.

This identity-only registry accepts host-reported observe-only, mediated,
unsupported and coverage-gap entries with mode consistency checks. It refuses
`physically_enforced` entries: those require a separate enforcing-broker receipt,
which enrollment cannot issue. `enforce` mode can therefore record incomplete
coverage without making a physical-enforcement claim. Host integrations must
verify any mediation they report and retain uncovered routes explicitly.

Defaults are 256 retained principal records, 256 channels, 16 parent edges and
a 30-second heartbeat deadline. Configured maxima are 4,096 records/channels,
32 parent edges and a 3,600-second deadline. Manifests contain at most 64 unique
capability/route/resource entries; IDs are bounded to 128 ASCII characters and
resource descriptions to 512 characters. Generations and policy epochs are
bounded 63-bit counters. The complete context is limited to 64 KiB of canonical
UTF-8 JSON, including multibyte resources. Backward, non-finite and invalid clocks
fail closed.

Ended records still consume capacity until the host calls `forget_ended()` or
closes their channel. Forgetting frees bounded storage without resetting the
incarnation's generation counter. Limits never evict active principals or reset
fences. There is no default persistence, telemetry, raw content retention or
network coordination. Distributed recovery and physical containment require
their own authority boundary and conformance evidence.
