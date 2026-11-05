# Authenticated swarm causal graph

SwarmCausalGraph projects a protected event journal without combining unrelated
IntegrationSession histories. It is a bounded evidence view and policy input,
not an executor, capability grant or claim of successful exploitation.

The graph accepts an original SwarmEventIngestor, protected sender handle and
current context. It authenticates that scope before and after projection, checks
stored event digests and filters stale policy epochs and inactive sender
identities into explicit proof gaps. Collector policy/source changes are rejected.
Ordinary event JSON or a caller-built collection cannot replace the ingestor.

## Explicit relations

Relations are depends_on, message_sent/received, artifact_written/read,
observed_data_flow, delegated_to and hypothesized_influence.

Within an actor/session/generation, explicit parent references preserve action
dependencies. Across actors or sessions, a message-received event must reference
an authenticated message-sent event with a shared resource digest; artifact
reads similarly reference authenticated writes. Equal resource hashes/names or
nearby timestamps alone create no edge. A caller assertion remains a weaker
hypothesized relation and is excluded from ordinary reachable() queries.

An observed_data_flow edge means a host-authenticated explicit handoff with the
same content/resource digest. Its trust is the host reporting boundary, not
independent remote attestation or proof that arbitrary opaque tools propagated
every byte. Missing transfers stay gaps. The graph does not infer unobserved
channels or persuasion from agent text.

Delegation is an authority relationship, not data causality. A SwarmDelegationLink
must carry current original issuer/grant/source objects and exact enrolled
parent/child contexts. It reuses the existing delegated-path relationship
verification, checks current parents and generations and rejects stale/revoked
grants. A plain delegated event/reference cannot create that edge.

## Intended, reported and observed

Nodes distinguish intended stages, host call results, authenticated backend
attempts/completions and unverified claims. A host completed callback does not
become an observed effect. Backend completion preserves the already validated
receipt's reported outcome, rather than inventing all predicted effects.

Evidence-kind classification is shared with ordin.assurance attack paths:
host observations, deterministic inference and caller assertions remain
different classes. Graph reachability reports a possible authenticated path,
not successful exploitation. Every export fixes successful_exploitation to
unknown and execution_authority to false.

## Bounds, privacy and replay

Defaults are 256 nodes, 1,024 edges and a 1,024-arrival event window. Configured
ceilings are 4,096 nodes, 16,384 edges and 16,384 arrivals. A per-source time
window defaults to 3,600 seconds and is capped at one day. Clocks are compared
only within their protected source stream, never to infer cross-host order.
Caller assertions cannot move the trusted stream's time-window frontier.

Omitted windows/nodes/edges, missing parents, source-sequence gaps, untrusted
events and stale identities are reported explicitly. Truncation never implies
complete observation. Parent backfill and cycle/depth admission are inherited
from the bounded event ingestor.

The [v1 JSON view](../../schemas/swarm-causal-graph.v1.schema.json) contains
event IDs, actor/session digests, action/resource digests and evidence categories.
It omits raw messages, arguments, source paths, tenant names and credentials.
Mermaid labels use fixed event kinds and phases instead of caller text.
Digests do not anonymize low-entropy data; keep the host journal and graph
behind the same tenant/operator boundary.

Nodes and edges are ordered deterministically by event ID. Fully admitted
offline replay produces the same causal projection across arrival orders;
the snapshot binding separately retains the exact ingestion state. Export is
non-authoritative and cannot restore a sender or permit.
