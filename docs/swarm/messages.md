# Authenticated inter-agent data messages

`SwarmMessageGateway` mediates data delivery between explicitly enrolled peers.
It authenticates the sender and destination, applies an exact channel grant,
checks protected sensitivity lineage and records send/receive events. It never
executes a tool, changes policy or treats another agent's text as operator
authority. Direct channels that bypass this gateway remain uncovered.

## Host setup

Use the same local registry, event ingestor and `SwarmSourceFlow` service as
the protected host gateway. Bind a protected host evidence source and original
event source for each peer. The event source must have the gateway role; a
caller-asserted stream or a raw collector receipt cannot issue message events.
Actual collected bytes can be correlated into that protected stream with
explicit authenticated lineage, rather than inventing backend observation.

Configure an `EgressSink` for each permitted message destination. Its route
class is `message`, action kind `tool`, operation `call` and destination path
`("parameters", "arguments", "destination")`. Its destination is the exact
protected recipient agent ID and its allowed labels are operator policy.
The corresponding body path is `("parameters", "arguments", "body")`.

The internal `ActionEnvelope` is an exact source-use representation. It is
never passed to a tool executor and confers no execution authority. Subsequent
actions remain subject to the existing action/tool gates and their stronger
findings. A message cannot wrap an executable action or approval override.

`register(context, source, channel, adapter, inbox)` requires original current
handles and a protected inbox callback. It returns an opaque `MessagePeer`.
Then `grant(sender, recipient, sink_id=...)` authorizes that exact pair of
enrolled identities/generations for a bounded lifetime, byte limit and
per-channel rate. The grant captures actual source/destination task identities;
message task metadata comes from the enrolled sender. This authorizes a data
handoff, not a delegated tool grant or workload credential.

Host discovery, grants, callbacks, transport authentication and lineage
collection must remain outside agent control. The service is a Python host API
boundary, not protection against hostile code sharing its protected memory.
Serialized identities, role text and HTTP headers cannot register a peer.

## Sending and receiving

`send(peer, channel, body, inputs=(original_lineage_handle, ...))` checks
the current identities, TTL, rate, exact body bytes and complete protected
lineage before admitting a delivery. Unclassified or incomplete inputs remain
restricted. A host collector must derive a combined output handle when
summarization, encoding or composition changes bytes; incoming data cannot be
re-registered as public merely by changing an envelope label.

Bodies are UTF-8 strings capped at 64 KiB; channel limits may be smaller.
Metadata, parent pointers, peers, grants, drafts and replay history are bounded.
The service retains metadata/digests/status, not bodies. Public audit exports
hash identities and omit body text, credentials and raw transport exceptions.

The receiver gets `PrivateMessage(envelope, body)`. Its body is omitted from
the object's representation. Its `instruction_authority` is always `data`.
Supported content classes are `data`, `task_handoff` and `tool_result`.
Structured policy updates, operator/system role claims, tool-identity changes
and unknown metadata fields are rejected. Natural-language instructions inside
the body remain untrusted data; the gateway does not claim to prove their
semantic truth or a model's resistance to persuasion.

After successful inbox acceptance, the gateway records an authenticated
`message_received` event parented to the actual send event and derives the
recipient's original lineage handle. The returned `MessageOutcome` makes that
handle available to the protected host for the next relay. The metadata alone
cannot issue it. A legitimate public A → B → C handoff preserves protected
sender identity and data labels at each step.

Task handoffs and tool-result forwarding do not issue action permissions.
Operator-controlled instructions and policy changes use the separate protected
operator/governance channel; no agent message can promote itself into it.

## Ordering, replay and uncertain delivery

Each admitted message has a host-generated ID and per-channel sequence.
Concurrent sends serialize admission and callback invocation for that channel.
The gateway consumes the ID before attempting delivery; duplicate and conflicting
submissions cannot invoke the inbox again.

`prepare` optionally emits metadata without delivery. `submit` accepts that
metadata or its JSON form only when this gateway issued it for the same
original peer and channel. It rechecks the exact body, lineage, generation,
policy epoch, expiry and sequence. It cannot import a foreign message as an
authenticated proposal. Parallel drafts are previews, not sequence reservations;
a stale draft must be replaced rather than treated as a new authorization.

Send events commit before the callback. Receive events and recipient lineage
commit after callback acceptance. A transport error, expired/revoked peer during
delivery or journal failure leaves an unknown outcome and no authenticated
receiver-execution claim. The ID remains consumed. Transport uncertainty closes
the channel; journal/lineage uncertainty fences further sends through the service.
There is no automatic retry after an uncertain external effect.

Exactly-once delivery means at most one inbox invocation for an admitted message
at this live gateway boundary. It does not mean exactly-once receiver execution,
durable cross-process delivery or automatic replay restoration after restart.
Replay history is retained until the explicit service capacity is reached;
exhaustion rejects new messages instead of forgetting old IDs.

Callbacks should enqueue promptly and must not interpret bodies as commands.
The gateway cannot retract data already handed to a callback. An explicit new
operator grant after uncertainty is a recovery decision, not proof that retrying
the same external operation would be harmless.

## Transports and quarantine

`SwarmMessageAdapter` binds the original sender and channel and routes all calls
through the same gateway checks:

- `CallbackMessageInbox` wraps a protected in-process inbox callback.
- `QueueMessageInbox` enqueues into an explicitly bounded private `queue.Queue`.
  A full queue produces an uncertain outcome and closes the channel.
- `RPCMessageInbox` wraps an existing authenticated host connection. The
  connector must first bind the actual recipient to an original opaque peer
  handle. The adapter checks that handle before and after transmission and
  validates an exact message/envelope/recipient ACK. An ACK describes inbox
  acceptance, not execution.

RPC framing, TLS, credentials, peer authentication and private body transfer are
owned by the protected connector. An arbitrary JSON `accepted` flag cannot
authenticate a remote recipient. These adapters neither open an automatic
network connection nor establish physical control over unrelated sockets.
The same API is re-exported by `ordin_swarm.message_gateway`.

An established unauthorized sensitive send quarantines its authenticated sender
by default. `quarantine_on_violation=False` is an explicit host option that
preserves rejection without automatic quarantine. Unknown provenance is
restricted without being relabeled as confirmed compromise. The host can also
call `quarantine` directly with a bounded reason code; every affected channel
is revoked. `peer_status` exposes redacted state and journal continuity.
Quarantine never erases replay history or silently reopens old grants.

Contracts:
[message metadata](../../schemas/swarm-message.v1.schema.json),
[outcome](../../schemas/swarm-message-outcome.v1.schema.json),
[peer status](../../schemas/swarm-message-peer-status.v1.schema.json).
All explicitly deny execution authority, and outcomes leave receiver execution
unknown.
