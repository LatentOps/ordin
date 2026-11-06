# Action-bound enforcing broker

`SwarmExecutionBroker` is an opt-in host component. Importing it starts no
process, network listener or policy update. The operator supplies the original
online delegation service, authenticated same-host broker channel, registry,
SwarmGate, transactional BudgetLedger and an owned executor. JSON reports,
copied dataclasses and LLM assertions never restore execution authority.

## Check and forward

`prepare(workload_channel, grant_ref, action, idempotency_key=...)` authenticates
the original workload and current parent grant, reserves the actual core
delegation use, reserves budget, and runs fresh global checks against the exact
original review inputs. The one-use authorization retains the canonical action,
contract, agent/session, epoch/generation, policy/configuration, ancestry, budget
ticket, runtime history and expiry. `authorization_scope()` is a protected host
accessor for the coordinator; its JSON view contains digests only.

`dispatch(authorization, action=original_caller_action)` rechecks all bindings
under the execution barrier. The original service consumes its core use ticket
through `guarded_dispatch` immediately before the exact bound action reaches
the executor. Budget forwarding is persisted before starting the worker. A
changed argument, tool, epoch, policy, runtime observation, parent enrollment,
revoked grant, stale review, expired or replayed ticket cannot execute. A failed
or missing post-effect acknowledgement retains uncertain budget holds and
cannot be retried using the same authorization.

Policy runtime integration uses a fresh facts receipt after reservation,
evaluates the existing decision with the original delegation gate, and checks
the evidence digest again under `execution_guard(context, broker=self)`.
No duplicate-history check is bypassed to compensate for quota reservation.

## Concrete owned Linux route

`LinuxFileReadBackend` implements EnforcementBackend for one narrowly scoped
tool: an exact `read_file` call with exactly one configured path argument. Its
workspace is a private, canonical, explicitly owned directory with a finite
allowlist of flat regular files. The parent opens the exact reviewed target
read-only with no-follow semantics, verifies inode/owner/mode/size and passes
only that descriptor to a pinned standalone worker. Unsupported network,
credential, process or tool requirements fail compilation; they are never
discarded or projected into broader TCP authority.

Each call starts a fresh Linux x86-64 worker with an empty environment and
closed inherited descriptors. Before reading, it installs no-new-privileges,
Landlock, a fixed seccomp allowlist, non-root UID/GID and hard memory, CPU,
process, descriptor and output limits. The worker performs denial canaries
against new path access, file writes, sockets, fork/exec and resource widening.
The parent verifies the complete request/nonce/action/contract/policy/file and
kernel evidence before issuing an original completion receipt and trusted
runtime observation. Missing kernel support produces non-success, with no
weaker physical fallback.

Payload bytes and serialized output are different limits. The payload is
bounded before base64 encoding. Both stdout and stderr share one anonymous
write-only regular file with a hard RLIMIT_FSIZE on the **entire combined JSON
control frame**, including metadata and encoding overhead. The read parent
also measures that frame bound. Physical budget admission supports only the
actual fixed route's bounded counts and combined output metric. Tokens,
uncapped remote billing and arbitrary caller cost declarations cannot satisfy
`require_physical_enforcement`. The generic ledger report remains admission
accounting and does not claim whole-policy physical coverage.

The owned child is the enforcement boundary. Host filesystem access, an agent
holding an independent host shell, existing sockets or credentials, and paths
routed around this broker remain explicitly uncovered. The containment test
records both a mediated denial and a separate successful raw host read. An
operator must isolate or remove those other channels before making a wider
deployment claim.

## Gateway and OpenShell

`broker.bind_gateway(..., operator=...)` creates an original protected route
binding. `SwarmToolGateway.bind_broker_agent(broker, binding, routes=...)` uses
that route; `prepare()` records the original caller digest and a separate
host-normalized canonical action ID. The actual compilation and execution use
the canonical scope action. `forward()` accepts no callback on a broker route.
Ordinary DelegatingAssuranceGate enrollment still refuses unmediated execution.

The optional `ordin_swarm.openshell_backend.SwarmOpenShellBackend` preserves
the complete supported capability/v1/v2 request contract, explicit capability
maximum and native backend maximum through the existing OpenShell compiler,
prover, approval and readback pipeline. Exact REST composites or missing exact
request domains return unsupported; they are not reduced to raw TCP. Missing
runtime identity/prover domains and live startup filesystem/process changes
return non-success. Network policy updates use the existing live policy path.
Management apply/readback does not execute a tool or prove completion, so this
adapter cannot replace the owned executor with an arbitrary callback. Its
currently supported role is verified policy admission; the concrete execution
route in this release is the owned Linux read worker.

## Controls and policy activation

`cancel()` releases a queued authorization when possible. `request_stop()` sets
the owned job's cancellation signal without waiting on the policy/issuer
execution barrier; `status()` reports original completed/canceled/unknown or
unable-to-stop evidence. The implementation acts only on original owned job
handles, never a supplied PID. `verify_control_receipt(receipt, authorization)`
checks original receipt membership and exact action/context/epoch/job binding.
No method claims rollback or atomic cancellation of an already-running kernel
operation. A confirmed process stop can coexist with uncertain expenditure.

`activation_proof(policy_digest, operator=...)` runs a separate benign owned
kernel probe. `verify_activation`, `describe_activation` and `policy_fits`
authenticate the original expiring factory proof and its finite read/tool
permissions. It supports only `broker.enforce` in scope
`broker_owned_fresh_worker_route`, requires a fresh per-action admission after
each policy epoch change, and always reports `physical_policy_applied:false`.
It does not assert coverage of already-running agents or generic filesystem,
process, network or credential access.
