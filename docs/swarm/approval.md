# Human approval and recovery

Governance is an opt-in protected host integration. Without an approval source,
existing core dispositions, configuration digests and runtime contracts retain
their previous shapes. Importing the package starts no listener or execution.

An original `warn` or `ask` remains visible in the core review and its enclosing
`escalate` disposition. An authenticated approval can fulfill only its operator
review obligation. The original decision's live `approval_fulfilled`,
`execution_eligibility` and `may_execute` properties expose that distinction.
Approval never changes the original risk, effects, action or policy result.
Serialized receipt, decision and lease reports have `execution_authority: false`.
They cannot restore an original approval or authorize a job.

## Install an explicit finite authority

Create `SwarmApprovalBootstrap(registry, hosts, approved_profile,
operator_maximum, operator=installation_capability, clock=coordinator_clock)`
before sealing the native assurance configuration. Its finite original host
sources must be the same sources used by the native delegated workloads. Pass
`bootstrap.authority` as `AgentGate(..., approval_source=...)` to that assurance
gate. Keep the installation capability outside workload/model access.

Create `SwarmOperatorDirectory` over the same original workload authenticator.
Configure finite roles, for example `approve`, `observe`, `break_glass` and
`recover`. Enroll each human principal with a distinct pinned certificate and
explicit task IDs. Neither wildcard tasks nor aliased human credentials count
toward quorum. The host transport obtains an operator channel using
`directory.authenticate(actual_server_ssl_socket)`. Every operation rechecks
current TLS enrollment, certificate revocation and scoped RBAC. TLS proves
possession of the enrolled credential; it cannot establish biometric identity
or human presence by itself. The deployment must protect those credentials.

Construct `SwarmApprovalService(coordinator, scope, directory, bootstrap,
policy, control=control, operator=installation_capability,
factory_proofs={host_id: original_broker_activation_proof})`, then explicitly
call `initialize(operator=installation_capability)`. Governance uses the same
durable coordinator authority and clock. A configured native service accepts
governed dispatch only through its original owned broker preparation.
Configuring the approval source arms native admission immediately: an
unacknowledged or partially bound installation cannot fall back to ordinary
`allow` admission. Explicit installation recovery must complete the binding.

After acknowledged installation, an ordinary action whose fresh core review,
complete capability contract, mandatory requirements and independent policy all
allow execution can use the original native/coordinator/broker route without a
human vote. Each admission, consumption and owned-effect boundary checks that
condition again against the original action and protected evidence. A previous
allow cannot authorize a subsequently changed warning. `warn`, `ask`, `block`
and unresolved requirements cannot use this route.

## Approve an exact proposal

The workload proposes an action; the human resolves it over a distinct original
operator channel. In this example the host retains all channels and receipts:

```python
request = governance.request(
    workload_channel, lease_id, native_reference, action,
    idempotency_key="proposal-17",
)
resolution = governance.resolve(
    human_channel, request.request_id, "approve", idempotency_key="vote-17",
)
if resolution["status"] == "approved":
    receipt = resolution["receipt"]  # Original host object, never JSON authority.
    reservation = governance.prepare(receipt, workload_channel, lease_id, action)
    outcome = governance.dispatch(receipt)
```

A protected operator service can instead call
`governance.fulfill(human_channel, request.request_id)` after approval. This
facade checks the current scoped human role and uses the service's retained
original receipt, caller action, workload channel, lease and grant. It still
requires the complete current quorum and permits exactly one owned job. The
operator supplies no replacement action or serialized receipt. The requesting
workload channel cannot serve as the human operator channel.

`fulfill` returns the existing `CoordinatorDispatch` accounting result. A trusted
host that needs byte custody or actual physical evidence can call
`fulfillment_result(human_channel, request.request_id)` to retrieve the retained
original completed `BrokerResult`. The accessor checks the current owner, scoped
human role, durable completed request, exact authorization and original executor
witness. It rejects uncertain or missing outcomes; a serialized report cannot
restore that object or authorize another execution.

`request`, queue inspection and review do not reserve quota, consume approval or
execute. The request binds a detached canonical action, exact context/review/risk,
policy and revocation epochs, owner fence, delegation, operator maximum,
capabilities, represented fixed-worker costs, operator directory and expiry.
Requests persist only digests, known effects, finite reason codes and scoped
audit metadata. Prompt text, raw action arguments and credentials are excluded
from the queue. Operators should compare the binding with the exact original
proposal in their trusted host interface, applying deployment-specific redaction
there. The queue is not an arbitrary action-text renderer.

`two_person_effects` and high/critical risk require the configured quorum, which
is at least two. One principal cannot vote twice under different idempotency
keys. Voters must retain their original task/role authority through consumption.
`prepare` durably holds the approval before creating a private execution lease.
The coordinator consumes the approval in the transaction that marks the actual
reservation forwarding. The original lease then binds one broker, executor and
owned job; the executor checks it immediately before starting the fixed worker.
Copies, mutated arguments, foreign contexts, stale epochs and replay fail closed.

Use `resolve(..., "deny", ...)`, `cancel(human, request_id,
idempotency_key=...)` or `expire(human, request_id, idempotency_key=...)` for
terminal requests. Expiration cannot be forced early. Cancellation refunds only
an original known unstarted reservation; stale or uncertain effects retain their
holds. A consumed request cannot be canceled into another execution attempt.
Vote and idempotency histories are bounded; exhausted capacity rejects new work.

Core `block`, mandatory unknowns, required independent policy escalations,
unrepresented requests/prover/runtime domains, revoked delegation, operator
maximum and hard budget failures remain restrictive even with a valid approval.
Generic callback gateways cannot execute an approved core warning. The concrete
supported routes use the original finite Linux read worker or managed-tools
backend, with their exact action validation, fixed resource bounds and original
job leases. Managed writes retain their core warning and compare-and-swap
requirements through approval and the final write boundary. Credentialed HTTP
actions retain the same original host credential-use receipts through review,
preparation and effect checks; approval cannot supply missing credential proof.
Custom cost providers are rejected because their
represented cost binding is not supported by this approval producer.

## Break-glass

`SwarmApprovalPolicy.break_glass` defaults to false. An enabled profile exposes
`break_glass(human_channel, workload_channel, lease_id, native_reference, action,
reason_code=..., idempotency_key=...)`. Only a current scoped human with the
configured break-glass roles can initiate it. It creates a new exact request,
requires at least two distinct humans and expires within 60 seconds (and within
the original workload lease). The initiator does not automatically cast a vote.

Reasons are finite codes: `incident_response`, `safety_recovery`, `availability`
or `data_preservation`. Initiation and votes record the operator digest, scope
and reason. The action is evaluated afresh and follows the same one-job path.
Break-glass does not relax persistent policy or waive core blocks, mandatory
unknowns, missing enforcement, independent restrictions, rights or hard budgets.
It accepts no agent-provided approval boolean or unsigned override profile.

## Recover uncertain execution

Containment and reconciliation remain governed by the
[original incident controller](containment.md). Resume requires current original
backend and durable outcomes, a fresh owner or policy fence, and a separate
human quorum:

```python
recovery = governance.request_recovery(
    human_a, controller, original_incident_receipt, task_id="task",
    reason_code="safety_recovery", idempotency_key="recover-17",
)
governance.resolve_recovery(human_a, recovery.request_id, "approve",
                            idempotency_key="recover-a")
resolved = governance.resolve_recovery(human_b, recovery.request_id, "approve",
                                       idempotency_key="recover-b")
governance.resume(human_b, resolved["approval"])
```

The supported ceremony covers one original coordinator scope and one exact task;
broader or cross-authority incidents reject this producer rather than borrowing
another task's human roles. Unknown/inflight jobs cannot authorize resume. The
human recovery approval is consumed durably before calling the low-level
controller with its original receipt. A changed reconciliation, expired quorum,
copied incident/approval or changed fence invalidates it. Old workload channels,
grants, evaluations and permits are never restored. Resume does not undo effects
or refund uncertain holds.

Compensating actions are new proposals with new reviews and approvals. Retrying
a non-idempotent remote effect requires original remote idempotency or settlement
evidence; this finite local producer offers no automatic retry or compensation
execution. Model text and caller completion claims are insufficient evidence.

## Operator CLI and installed API

`ordin swarm approval validate explicit-policy.json` validates an explicit
offline policy. The live verbs are `queue --task TASK`, `show REQUEST`,
`approve REQUEST --idempotency-key KEY`, `deny`, `cancel`, `expire` and
`resume REQUEST`; approvals for recovery also use `--recovery`. Live verbs
require a host-injected `SwarmApprovalOperatorSession(governance,
original_human_channel)` passed to `ordin.swarm.approval_cli.main(...,
session=session)`. The standalone process has no implicit live connection and
rejects live mutations. Command-line roles, files or JSON cannot restore it.
The session retains original receipt objects privately; CLI output omits them.
The owned TLS smoke tests exercise these verbs against the original service.

`snapshot`, `get_request`, `describe_receipt` and `audit` provide bounded reports;
queue/request/audit inspection requires current scoped `observe` authority.
`describe_receipt` requires the original host receipt. The optional `ordin_swarm`
integration re-exports the same types through `approval_service.py`.
Published root/package schemas include policy, action/recovery requests,
receipt reports, resolution, queue, audit, core scope/fulfillment and job lease.

## Faults and restarts

Live request/receipt/lease publication happens only after a confirmed durable
acknowledgement. Lost resolution acknowledgement exposes no receipt; an explicit
idempotent current retry may confirm the recorded vote. Lost forwarding
acknowledgement does not start the worker and retains uncertain quota. Exceptions
and completion close the live lease; historical witness digests remain stable
for exact outcome correlation while actual execution still needs the live job.

`initialize(recover=True, operator=installation_capability)` repairs a lost
installation acknowledgement for the same original controller. A replacement
controller requires a fresh owner fence and original compatible protected host
components. Existing pending/approved/held rows become canceled; consumed rows
become uncertain. Historical votes never become replacement live handles.
Missing or corrupt initialized namespaces are never silently recreated. Partial
installation rejects dispatch until explicit protected installation recovery.
There is no file-based restoration of executable approvals or approval-bearing
runtime sessions.

Keep one `CoordinatorClock(store)` object shared by the registry, authenticator,
issuer, budgets, coordinator and approval bootstrap. Create the private database
only during explicit initialization; restart opens the intact existing database.
Reconstructing the approval authority changes its original configuration
binding. A protected operator restart therefore selects a fresh monotonic policy
epoch for all components and calls `coordinator.start(scope, control=control,
takeover=True)`. Reusing the old epoch with a changed configuration fails closed.
Keep the same scope and budget dimensions: takeover retains spent quota and
forwarded uncertain holds, fences old leases/evaluations and cancels only known
unforwarded reservations. Never recreate a database or rename actors to reset
that history. `coordinator.checkpoint(scope, control=control)` persists historical
projection state, without restoring live authority.

Authenticated transport and readiness proofs have their own finite lifetimes.
Before admitting fresh work, the protected host may renew an actual broker TLS
channel using `coordinator.refresh_broker_channel(scope, channel, control=control,
operator=installation_capability, expected_owner_fence=fence)`. This requires the
same original broker enrollment, certificate, host and current database owner,
with no pending broker work. It moves the coordinator and broker pins together
after durable acknowledgement. A fresh actual activation probe can then supply
`governance.refresh_factory_proof(host_id, proof,
operator=installation_capability, expected_owner_fence=fence)` for the same
registered enforcing factory and selected policy. These operations extend no
grant, workload lease, approval deadline or vote. A request whose original
workload channel or lease expired needs a fresh proposal and fresh human votes.

This is scoped mediation of represented owned-worker jobs. Unmediated paths,
general filesystem/process control, arbitrary other agents and uncapped remote
billing remain uncovered. Risk inference is separate evidence; it cannot issue
human approval or prove completion.
