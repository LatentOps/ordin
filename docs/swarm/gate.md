# Pure swarm decision composition

SwarmGate is an explicit review wrapper over AgentGate, AssuranceGate or
DelegatingAssuranceGate. It preserves the original ActionReview and adds
host identity, policy and evidence bindings. It never executes a tool, issues a
credential, appends session history, reserves an operation or commits a ticket.
The executor still owns those steps and must recheck authority at use time.

## Default and monotonic behavior

~~~python
from ordin import ActionEnvelope
from ordin.swarm import InMemoryAgentRegistry, SwarmGate

registry = InMemoryAgentRegistry("tenant", "swarm")
adapter = object()  # Replace with the host's verified adapter instance.
channel = registry.bind_channel(adapter, runtime_id="python")
context = registry.enroll(channel, adapter, agent_id="worker", session_id="session")
gate = SwarmGate(registry)
action = ActionEnvelope.shell("git status --short", action_id="read-status")
decision = gate.evaluate_action(context, action, channel=channel, adapter=adapter)
assert gate.binding_matches(decision, context, action, channel=channel, adapter=adapter)
~~~

With a current identity and no swarm policy, the ordinary default baseline
decision is preserved. Composition uses execute < escalate < deny. A core block
always remains denied. Core warn/ask requirements remain escalated even when
the caller configured a permissive ordinary ReviewPolicy. No swarm rule,
confidence score or host assessment can weaken the underlying result.

SwarmPolicy is immutable operator configuration, supplied to the gate constructor
separately from action parameters. Its bounded rules select protected agent/task
IDs and core-derived action kinds/effects. Rules only join a disposition with the
existing result. A matching execute rule therefore grants no extra authority.
There are no policy callbacks, expression evaluators, network lookups or model
safety approvals.

Pure review suppresses the optional baseline audit sink. The caller may record
the returned redacted decision separately. Review arguments and the baseline
configuration remain bound even when audit emission is suppressed.

## Mandatory global checks

A policy can name mandatory check IDs. Concrete lineage, budget and coordinator
components supply their facts through an operator-owned SwarmAssessmentSource.
This is a protected host API boundary, not independent physical attestation.
Keep both the source and its issue() method outside agent control.

Assessments bind an exact action digest, context digest, policy digest and global
evidence snapshot. They also bind provider incarnation/generation and a bounded
expiry. Only the original receipt issued by the configured source verifies;
matching JSON, copied receipts and another provider with the same display name
do not. Validation and binding checks recheck expiry. Provider fence() invalidates
older receipts without resetting its generation.

Unknown or absent mandatory checks default to deny. An explicit operator policy
may choose escalate for unknown checks, which still requires a separate approval
flow. Violations always deny. Unverified, ambiguous or unexpected assessments
deny rather than becoming claims of satisfaction. Assessments cannot override
core warnings or blocks and do not constitute human approval or a reservation.

The initial composer does not invent concrete budget availability or lineage
facts; those components are separate workstreams. Configuring such a check
without a current protected provider receipt remains conservative.

## Binding and serialization

The installed [decision schema](../../schemas/swarm-decision.v1.schema.json)
contains only dispositions, protected identity, digests, bounded reason/rule IDs
and check statuses. It omits raw action arguments, prompts, host receipt payloads
and baseline review details. Python callers retain decision.review for the
original ActionReview and provenance. Treat that explicit detailed view according
to the host's privacy policy.

Decisions bind the canonical action, exact current principal/session/generation,
context/coverage, policy/configuration, supplied history/observations and known
global evidence snapshot. With an event ingestor configured, a protected event
sender for that exact context is required. Admitting a new event changes the
snapshot. Changed inputs, expired identity/assessments, policy epochs, source
fences or mutable review results invalidate binding_matches().

The same baseline review arguments used during evaluation must be supplied to
binding_matches(). JSON cannot restore a gate-issued decision, and a different
gate instance cannot use its binding. A matching review binding is not a ticket;
it does not provide atomic quota enforcement or kernel containment.

## Assurance and delegation

AssuranceGate composition retains approved profiles and protected host contexts.
Swarm configuration cannot weaken its escalation or denial.

DelegatingAssuranceGate now has a reservation-free preview_action() that shares
the existing exact-operation and quota checks. It reads the child session's
current bounded history, observations and trusted runtime evidence without
appending, emitting audit records or reserving a ticket. Existing
evaluate_action()/commit_use() behavior remains unchanged. A preview itself
cannot be committed.

For delegation, configure delegation_context explicitly when constructing
SwarmGate. It must identify the issued child principal and grant; the exact
context digest also binds session, parent generation and policy epoch. A
different agent/session cannot borrow the configured child's authority.
Reissue the binding after a context change. The child gate owns its protected
history; callers cannot replace it with a fabricated history in a swarm review.

The global snapshot includes the child history/runtime state, issuer generation,
pending-operation facts and consumed quotas. State changes require re-review.
The preview only checks current availability; the existing issuer/broker must
still reserve and validate the exact action at actual use.
