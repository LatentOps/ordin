# Online delegation and private credential routes

`SwarmDelegationService` extends the existing private `DelegationIssuer` and
`DelegatingAssuranceGate` across independently authenticated host connections.
The authority retains original issued objects, the selected operator/task
maximum, per-child sessions and real operation reservations. Serialized
`IssuedDelegation` objects, principal text and cached reports cannot restore
current authority.

## Authentication and scope

Create an explicit server `ssl.SSLContext` with a selected trusted CA,
`CERT_REQUIRED` and minimum TLS 1.2. `WorkloadAuthenticator` accepts only an
actual server-side `SSLSocket` using that original protected context after a
successful mutual-TLS handshake. It checks verified leaf certificate bytes,
pins, current registry enrollment and TLS configuration before issuing an
opaque `AuthorityChannel`. A certificate dictionary or JSON `verified` flag
cannot authenticate.

The trusted operator binds each distinct workload certificate to an original
live registry context, host ID and `HostEvidenceSource`. Tenant, swarm, task,
principal, session and policy epoch come from that protected mapping. A shared
host certificate does not distinguish unrelated workloads and cannot be enrolled
twice. Broker certificates have a separate role and host binding. A workload
cannot promote itself into the broker role through a request header.

Enrollment, CA/pin selection, TLS private keys, registry channels and the clock
must remain outside agent control. Channels have short bounded lifetimes.
Every authority operation revalidates the current enrollment and ancestry;
closing a channel, revoking its enrollment or changing registry generation
invalidates its unused admissions. The connector must close channels on EOF and
manage TLS credential rotation. This API does not infer instantaneous remote
process liveness from a socket or a model claim.

## Grant protocol

The operator first publishes an original current root grant for its enrolled
issuer principal with `publish_root`. A workload can use `issue_child` only
with its own current parent reference and an already enrolled child target.
The requested child authority is checked by existing
`verify_delegation_subset`/`DelegationIssuer` against its parent, operator
maximum and task maximum. Lifetime, depth, fanout and operation quotas are
preserved. A broader child is refused rather than silently narrowed.

The returned random reference identifies a protected server-side grant. Its
knowledge alone grants nothing: the current authenticated workload must own it.
Duplicate issuance request IDs are idempotent only for identical proposals;
conflicting reuse is rejected. Grant reports expose digests, task/host scope,
depth, limits, expiry and issuer generation. They explicitly require online
authority and deny execution authority.

The explicit framed protocol supports `current`, `issue`, `review`, `cancel`,
`revoke` and the broker-only `scope` operation. `serve_one` processes one
length-prefixed JSON request on an existing verified TLS socket. Frames and
responses are capped at 64 KiB, aggregate transport I/O has a ten-second
deadline, duplicate keys/unknown fields are rejected, and malformed requests
close the channel. No wire operation accepts executable callbacks or silently
loads a connector. Importing the package starts no server or network request.

## Exact rights and use

Filesystem access/scope, literal network protocols/endpoints, exact
GraphQL/MCP/JSON-RPC request commitments, tool identity/version, executable and
spawn requirements, privilege, credential bindings and approval requirements
remain intact. Unknown database operations, unrepresentable rights and
unsupported child languages cannot compile into an empty grant.

The additive `DelegationAuthority.rest_requests` field preserves exact REST
scheme, URL, verb, headers and body commitments. It is omitted when empty, so
existing authority JSON and canonical digests remain unchanged. Nonempty
requests must remain inside all three maxima. The original REST composite
verifier accounts for its explicit request requirement; no unknown is stripped
and returned as a broader execution contract. Broad TCP is not substituted for
specific REST authority.

`review` uses the original child `DelegatingAssuranceGate` and reserves a
real core use ticket only if that decision permits. It returns a short-lived
admission reference. Core warning/approval requirements remain restrictions;
representable JSON-RPC rights do not automatically approve unknown RPC effects.

Only a live broker channel on the actual subject's configured host can call
`guarded_dispatch` (or its `commit` alias). The service consumes that exact
admission once, rechecks action bytes, workload/parent state, issuer generation,
expiry and the original sealed decision, then commits the original core ticket
immediately before invoking the protected forwarder. Issuer revocation and this
callback boundary are serialized. There is no reusable positive boolean lease.

A callback failure remains unknown and cannot be retried with the admission.
A host callback completion does not prove physical enforcement or receiver
execution. The broker must forward exactly the captured action and constrain
the actual runtime effects.

`admission_scope` provides current scope data for broker compilation, including
the original sealed decision/gate and exact `review_context`/`review_history`
to trusted in-process code. Its public report is redacted. Its explicit private
wire form carries data that cannot restore a private gate or issuer handle.
`guarded_dispatch` remains mandatory after compilation. Stronger fresh core or
swarm-global findings must still prevent forwarding.

Because `review` retains the action in the child's existing session, a broker
must not re-review the same action ID through that session as if it were new.
Compose fresh global checks using the original protected inputs and the live
admission, or use a retained-decision path that verifies the original ticket.
Duplicate-history checks are not bypassed.

## Rebinding an already-running child

`bind_delegation_context(reference, operator=...)` verifies the original
current private parent/child relationship before calling the registry's trusted
`rebind_delegation` API. It preserves the actual runtime and session ID,
increments authorization generation, and records the exact parent generation
and issued grant ID. This supports existing `SwarmGate` delegation-context
checks without pretending the process restarted.

Old registry contexts, descendant parent-generation references, TLS channels and
unused admissions are fenced. The pinned workload enrollment is updated only
to the new original current context; JSON grant IDs cannot rebind authority.
An ended, paused, expired, foreign-task or revoked workload cannot be revived
by this operation. Root authorization remains separately operator-selected.

## Revocation, partitions and restart

A parent can revoke only itself or its descendants, not siblings. Core
revocation invalidates descendants and every stale unused operation ticket.
Other siblings retain their grant but need a fresh review after the issuer
generation changes. Workload/certificate revocation and stale ancestor registry
contexts also invalidate current descendant use.

Issuer partitions fail closed. `set_available` transitions fence unused
admissions; reconnecting does not revive them. `fence_policy` invalidates core
grants, TLS channels and unused admissions before policy/maximum changes.
Changed issuer/profile/semantics configuration requires a fresh protected
issuer/service. Expired admissions release pending core slots without refunding
committed operations.

This implementation retains bounded volatile server-side state. It does not
restore grants, quota history or pending authority from JSON after restart.
Restart recovery must fence old runtime capabilities and bootstrap a new
operator-approved generation; durable multi-host coordination is a separate
boundary. Capacity exhaustion rejects further authority instead of forgetting
old control state or presenting stale caches as live.

## Credentials

`SwarmCredentialBroker` stores bounded private credential bytes and exact
operator-selected destination routes. A route binds a `CredentialBinding` to a
fully represented request template, including its protocol/request commitment.
Agent-provided credential headers are refused. Broad network access does not
provide credential access.

`prepare` creates an original host credential-use receipt for the exact action,
then includes it in the ordinary full-domain delegation review. A child without
that specific credential/destination right cannot receive an executable
admission. URL, scheme, verb, header/body and argument changes refuse the route.
Caller correlation IDs are replaced with host IDs before credential review;
the original caller action is still bound by digest. This keeps correlation
text out of private credential matching and core review/audit without changing
the actual request body or protocol ID.

`dispatch` supplies a `PrivateCredentialRequest` only to its protected
transport after current delegated commit. The credential is excluded from
representations, action parameters, public events and audits. Transport return
bodies are discarded, so a response that echoes a credential cannot become a
public result through this API.

The adapter must enforce the configured TLS destination and reject redirects,
keep actual secret placement outside model context, and protect its own host
credentials. Revoking a route cancels its unused admissions. Public credential
audit contains only route/binding/action/admission digests and bounded status.

Software grants alone do not contain processes with preexisting filesystem,
network or credential privileges. Actual enforcing broker/runtime restrictions,
old-credential revocation and mediated egress are required for containment.

The optional `ordin_swarm.delegation_service` and
`ordin_swarm.credential_broker` modules re-export these APIs. Tests use real
local mutual TLS with an explicitly public synthetic CA and distinct leaf keys;
those fixtures must never be trusted outside isolated tests.
