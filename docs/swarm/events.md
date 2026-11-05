# Authenticated local swarm events

The opt-in event layer records bounded, redacted facts from a protected host
gateway or collector. It reviews no actions, executes no tools and issues no
permits. Event hashes and evidence-class labels are data; sender authority comes
from the original host-issued channel, live identity and protected source handle.
See [host enrollment](identity.md) and the [architecture](architecture.md).

## Event contract

The source and installed wheel ship
[`ordin.swarm_event.v1`](../../schemas/swarm-event.v1.schema.json). A `SwarmEvent`
contains an event ID/kind, registry incarnation, immutable `SwarmIdentity`,
source ID/sequence, timestamp, evidence class, confidence, optional exact action
ID/digest, reviewed-event anchor, scoped parent event IDs and resource digests.
Backend observations also retain the original receipt digest and reported
outcome. There are no raw prompt, message-body, tool-result or arbitrary metadata
fields.

Parent IDs are `EventRef(tenant_id, swarm_id, event_id)` values. Cross-scope,
duplicate and self references are rejected. Runtime semantic validation augments
the JSON Schema with scope equality, parent/review relationships and encoded
byte limits. An unknown parent stays a gap. Matching timestamps or resource
digests do not establish a causal edge.

Kinds are `proposed`, `reviewed`, `reserved`, `committed`, `forwarded`,
`completed`, `observed`, `failed`, `denied`, `canceled`, `delegated`,
`message_sent`, `message_received`, `artifact_read`, `artifact_write` and
`revoked`. Action stages require exact action identity. Stages after review
require an existing authenticated gateway review for that exact
registry/agent/session/generation/policy epoch and action digest. A new attempt
uses a new action ID; retries use the original event ID and identical content.
Only one authoritative review is admitted for an action attempt.

`from_dict()` and `from_json()` restore validated event data, never a sender
credential. JSON input has a 64 KiB UTF-8 limit and rejects duplicate keys,
non-finite numbers, unsupported versions and unexpected fields. Individual IDs,
collections and numeric fields are bounded before interpretation. Rejected
payload values are omitted from errors.

## Protected ingest

~~~python
from ordin.swarm import InMemoryAgentRegistry, SwarmEvent, SwarmEventIngestor

registry = InMemoryAgentRegistry("tenant", "swarm")
adapter = object()  # Host's already verified gateway instance in a real integration.
channel = registry.bind_channel(adapter, runtime_id="python-worker")
context = registry.enroll(channel, adapter, agent_id="worker", session_id="session")
ingest = SwarmEventIngestor(registry)
source = ingest.bind_source(context, channel, adapter, source_id="gateway")
proposal = SwarmEvent(
    "proposal-1", "proposed", context.registry_id, context.identity,
    "gateway", 1, context.enrolled_at,
    evidence_class="host_authenticated",
    action_id="action-1", action_digest="a" * 64,  # Derive from the actual action.
)
receipt = ingest.ingest(source, proposal)
assert "action_lifecycle_gap" in receipt.gaps
~~~

Keep the registry, adapter, channel, source handle and journal outside agent
control. The host verifies the actual transport before binding it. This is an
in-process API trust boundary; it does not attest OS/container identity or
protect a compromised host process.

Sender roles are:

| Role | Admitted evidence | Boundary |
| --- | --- | --- |
| `asserted` | `caller_asserted` | Preserve claims without promoting them into trusted lifecycle facts |
| `gateway` | `host_authenticated` or explicitly weaker caller assertions | Host-reported proposal/review/dispatch/call-result facts; no physical-enforcement proof |
| `collector` | `backend_observed` / `backend_enforced` on `observed` events | Requires an original sealed `RuntimeObservation` from the bound `RuntimeEvidenceSource` |

Every admission authenticates the current context and channel. Stale epochs,
expired/paused/ended identities, restarted sessions, changed senders and sibling
principal claims are rejected. This API does not automatically restore old sender
authority or accept late traffic from an expired identity; missing history stays
explicit. Durable recovery and privileged historical reconciliation belong to
the coordinator integration.

Collector admission revalidates the original receipt and matches its source
key, action ID/digest, receipt digest, reported outcome and canonical resource
digests. Ordinary observation JSON and tool-supplied `observed_effects` cannot
enter this path. Source configuration must correspond to the actor's actual
runtime session, sandbox and policy. As in the existing runtime evidence API,
the strong labels describe a host-owned reporting boundary, not independent
remote attestation.

Confidence is bounded annotation only. It cannot authenticate a sender, validate
an outcome or create permission.

## Ordering, replay and gaps

`JournalRecord.ingest_index` records local arrival order. A source sequence
identifies its own stream, while explicit parent references define causal
relationships. These orders are separate. No ordering is inferred between
concurrent hosts from their clocks.

Identical event-ID/content retries are idempotent. Changing content under an
existing ID, reusing a source sequence, changing an action ID's canonical digest
or crossing the receive window is rejected. Out-of-order packets within the
bounded window may fill a sequence gap later. Parent backfill checks the affected
descendants too, so it cannot introduce a cycle or a graph deeper than the limit.

`action_state()` reports authenticated stages, missing stages, unresolved
parents, sequence gaps and whether a complete causal lifecycle chain exists.
Gap reporting follows trusted parent ancestry across actions and agents;
referenced caller assertions remain explicitly untrusted. A direct parent
arriving cannot erase a missing ancestor or that ancestor's stream gap.
A complete chain requires actual parent links through proposed, reviewed,
reserved, committed, forwarded and completed; mere stage presence is
insufficient. Caller assertions cannot complete or contaminate that trusted
chain.

An authenticated `completed` event means a gateway reported call completion
linked to a review. It does not prove that the proposed effect happened.
`observed_outcomes` preserves a collector's exact `allowed`, `denied`, `failed`,
`completed` or `unknown` outcome. Observing an admission or denial does not
invent completion, a resource read/write or a missing forwarding stage.
Events never retroactively authorize an action.

## Bounded journal and adoption

The default private journal is in memory. Defaults are 4,096 events, 256
sources, a 128-sequence receive window and 64 causal edges of depth. Configurable
ceilings are 16,384 events, 4,096 sources, a 1,024-sequence window and 128 edges
of depth. An event has at most eight parent references and 64 resource digests.
Capacity exhaustion rejects new admissions without evicting deduplication,
sequence or action-binding state. Original identical retries remain idempotent
at capacity.

The host-owned `EventJournal` append abstraction requires atomic append or an
exception with no storage change, expected-index checking and immutable records.
Ingest state advances only after successful storage. It supplies an integration
point for a future durable coordinator; this version does not load a persisted
JSON journal or claim crash-safe multihost transactions.

Journal snapshots contain bounded IDs, digests and dispositions, not raw
messages or secrets. Use opaque IDs and protect the journal; hashes of
low-entropy resource names are not anonymization. There is no default network,
upload, collector discovery or background retention task.

The offline tests replay fixture packets through newly issued protected sender
handles and compare causal projections across different arrival orders. Reusing
an old handle fails. Fixture replay proves protocol behavior, not historical
production authority or enforcement.
