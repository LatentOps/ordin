# Declarative swarm policy and safe reload

`SwarmPolicySet` is bounded data under `ordin.swarm_policy_set.v1`. Loading or
compiling a document never authorizes deployment or execution. The protected
operator separately supplies a `SwarmPolicyMaximum`, approves an exact compiled
version after simulation, and activates a new epoch.

Existing `SwarmPolicy` / `SwarmRule` host APIs remain available. The declarative
policy layer is opt-in through `SwarmGate(policy_runtime=runtime)`.

## Selectors, permissions and precedence

Every document names one exact tenant and swarm. It cannot select a foreign
tenant/swarm or use a wildcard to widen the scope. Rules combine bounded
selectors over current agent/task identity, operator role bindings, action kind,
operation, core effects, exact tools/resources/destinations, protected data labels,
input message classes, temporal categories and remaining budget.

Role bindings belong to the protected maximum. A role string in a prompt, action
parameter, HTTP header or incoming message cannot assign that role. Tool identity
uses the existing core tool parser and captured review semantics. Effect and
resource conditions use the existing `ActionReview`, not caller risk labels.
Unknown tool semantics retain the core escalation.

Permission arrays are finite exact allowlists. `null` inherits the corresponding
operator maximum; it never means “ignore the maximum.” An empty array permits
no values in that category. Resource/destination matching is literal equality,
with no glob, prefix program or regular-expression language. Exact HTTP(S) URL
literals can include a query or IPv6 host; embedded URL credentials and wildcard
expressions are rejected.

The maximum is always retained. Candidate permissions outside it fail compilation.
Budget constraints may tighten the operator's selected aggregate/specific maxima;
wildcard selectors cannot raise a narrower maximum. Unknown-cost authority stays
in protected budget configuration rather than policy JSON.

For matching rules, the most restrictive result wins:
`execute < escalate < deny`. With no matching rule, the document's default
applies. That result is joined with the existing baseline, legacy swarm rules,
mandatory checks and maximum constraints. An execute rule cannot override a core
block, warning/approval requirement, mandatory Assurance escalation or revoked
delegation. Missing relevant protected facts use the document's escalation/deny
fallback; an unknown fallback cannot execute.

Required checks from the operator maximum are retained even if omitted by the
candidate. Legacy mandatory checks still need their original existing assessment
source. The composed rule/check counts are bounded and ambiguous collisions are
rejected rather than truncated into a permissive result.

## Protected facts

`SwarmPolicyFactsSource` authenticates original host declarations bound to the
exact action, original context, policy digest, evidence snapshot and short TTL.
Its issuing API must remain outside model/transport control. The host collector
must validate actual lineage, message provenance, temporal findings and budget
state before issuing categorical facts. Receipt JSON or a copied record cannot
authenticate those declarations.

Facts distinguish unknown (`None`) from a known empty collection. Unclassified
data always retains uncertainty. Known sensitive data can still trigger a deny
rule even when another input is unknown. A fact receipt describes host evidence;
it is not independent physical proof or a tool execution permit.

For a configured gate, issue against `gate.policy_digest` and
`gate.evidence_snapshot_digest(context, ...)`, then pass the original receipt as
`policy_facts`. Protected providers can be supplied to the tool gateway through
`policy_facts_provider`. They are host integration code, never names or callbacks
loaded from the declarative document.

The runtime snapshot includes current budget counters and the independent
flow/temporal bindings. A protected declassification without a new event still
changes the binding. Budgeted gateway preparation reissues/reviews evidence
after its own reservation, so the reservation neither bypasses the low-budget
rule nor invalidates its own earlier snapshot silently.

Policy message-class selectors describe the protected message provenance of an
action's inputs. They confer no instruction authority on message text. The
separate authenticated message gateway still controls direct inbox delivery,
sharing ACL and sensitive-data transfer; bypassed channels remain uncovered.

## Prepare, simulate, approve and activate

Construct `SwarmPolicyRuntime` with the original registry, immutable operator
maximum, protected operator capability and host clock. Optional budget, flow,
temporal and delegation components must belong to that original scope.
Importing the package starts no service or database.

The protected workflow is:

1. `prepare(policy_set)` validates/compiles the exact document against the maximum
   and current supported capabilities. Missing required capability rejects the
   deployment; it does not silently relax to an uncovered route.
2. `simulate(deployment, cases)` performs bounded offline replay using actual core
   action review and the same compiled restriction evaluator. Reports contain
   digests/outcomes rather than raw actions or message bodies.
3. `approve(deployment, simulation, operator=...)` requires the original exact
   simulation and operator capability. Observed or structural relaxation needs
   explicit `allow_relaxation=True`. Structural review does not rely on a sparse
   corpus happening to exercise the widened path. Annotated unsafe executable
   cases reject approval.
4. `activate(approval, operator=...)` consumes that original approval for the
   exact compiled selection, maximum, base binding and target epoch.

Simulation facts and benign/unsafe corpus annotations are hypotheses, not live
authority. Simulation does not certify current runtime/Assurance/delegation
coverage. Those independent requirements remain enforced on the real action.
Neither a serialized simulation nor its summary can substitute for operator
authorization.

The runtime exposes `active_policy_digest` for the exact source document and
`selection_digest` for the immutable compiled selection. `binding_digest` adds
the current approval/epoch/configuration fences. `evidence_digest(context)`
additionally binds mutable protected quota/flow/temporal state. Production
coordinators must enforce the same exact epoch/selection and live binding in
their own linearizable admission transaction; the local lock is not multi-host
consensus.

## Cutover, in-flight work and rollback

Dispatchers share `runtime.execution_barrier`. The local tool gateway and bound
online delegation service take it before final policy checks and forwarding.
Activation takes that same registry-owned barrier before runtime, registry and
budget/delegation state locks. Separate local runtime objects for one registry
therefore cannot bypass each other's cutover.

An already-running synchronous callback may delay activation until it finishes.
This is not atomic kernel cancellation and does not undo external effects already
in flight. New callbacks cannot use an earlier epoch after cutover completes.

Activation advances the registry epoch, fences fact receipts and unused
delegated admissions, clears temporal collection coverage, and migrates budget
authority over the same accounting store. Consumed/uncertain expenditure is
retained. A fresh zero-history budget store cannot be rebound as existing
accounting. Old source handles, contexts and unused authorizations fail current
binding checks.

Live host sessions need fresh authorization contexts and collection sources.
`registry.refresh_policy_context` preserves the physical session ID while
issuing a new generation. Refresh parents before children. It does not revive
ended/expired principals, renew a delegated grant or infer fresh coverage.
Coverage defaults to uncovered until the host verifies routing again.

The activation result exposes the fresh budget ledger to the protected host.
Rebind flow/temporal/delegation sources explicitly with `rebind_sources` after
current-context enrollment. Source replacement fences prior facts and remains
inside the same maximum; budget history cannot reset. Fresh delegation requires
current original issuer/profile/workload/TLS sources. Merely refreshing a context
does not restore old grants.

Validation/approval failure before fencing leaves the prior selection intact.
If a component fails after fencing begins, the new epoch remains consumed and
the runtime reports `failed_closed` with no active selection. It never
reinstates older tickets to hide a partial failure. Recovery requires a new
approved activation.

Rollback selects the earlier document through a fresh prepare/simulate/approve
workflow and a strictly newer epoch. Reusing an old source document does not
resurrect its earlier approval, context generation or execution ticket.

## Actual enforcement scope

Read-only policy compilation cannot prove applied kernel/runtime enforcement.
Activation reports explicitly keep `physical_enforcement: false`.

Budget readiness uses the ledger's protected `admission_available` check. A hard
budget still requires an original per-action proof from the actual fixed worker
and revalidation before forwarding. A read-file factory cannot cap remote token
or dollar billing. Such a required budget blocks activation; it is not inferred
from a cost estimate or a caller-provided physical-enforcement flag. Epoch reload
preserves charged and uncertain history; a replacement hard-budget ledger needs
its current enforcing broker rebound before actions can pass.

The runtime's read-only evidence digest includes the protected source-flow
records, declassification audit, configured sinks, current causal graph and
source lifecycle. Revoking a source session changes this binding even when no
new event or lineage record is added. Reading the digest does not issue evidence
or renew an expired fact receipt.

A required `broker.enforce` needs an original verified broker factory proof
bound to the exact document, with explicit
`enforcement_scope: broker_owned_fresh_worker_route`. The candidate's finite
tool/effect/file permissions must fit that actual owned factory. Every action
still needs fresh per-action broker admission. A generic tool-gateway callback
cannot borrow that proof; its execution guard must use the same original
registered enforcing broker.

An owned fresh-worker capability is not containment of an arbitrary already-running
agent, every filesystem path, or every process/socket. Generic
`filesystem.enforce`, `process.enforce` and `all_agent_paths` requirements
remain unsupported unless an actual matching boundary exists. Unsupported live
restrictions require verified re-enrollment/restart or rejection, never a broad
permission fallback.

## Read-only CLI

Files and corpora are explicit, bounded JSON. No policy code, prompts, regex
programs, remote includes, callbacks or implicit home-directory search are loaded.

```bash
ordin swarm policy validate policy.json --maximum maximum.json --json
ordin swarm policy explain policy.json --maximum maximum.json --json
ordin swarm policy diff before.json after.json --json
ordin swarm policy simulate policy.json --before before.json --maximum maximum.json --corpus cases.json --json
```

The maximum file is `ordin.swarm_policy_maximum.v1` data for static review;
parsing it issues no protected operator capability. A corpus uses
`ordin.swarm_policy_corpus.v1` with bounded cases containing a case ID, identity,
action, optional expectation and hypothetical facts. Foreign-tenant cases remain
denied. CLI output explicitly marks offline simulation or unverified live
capabilities and never deploys a policy or changes a host.

The host APIs are also re-exported through `ordin_swarm.policy`. Contracts include
[policy data](../../schemas/swarm-policy-set.v1.schema.json),
[maximum data](../../schemas/swarm-policy-maximum.v1.schema.json),
[compilation](../../schemas/swarm-policy-compilation.v1.schema.json),
[simulation](../../schemas/swarm-policy-simulation.v1.schema.json),
[activation](../../schemas/swarm-policy-activation.v1.schema.json),
[diff](../../schemas/swarm-policy-diff.v1.schema.json) and
[validation](../../schemas/swarm-policy-validation.v1.schema.json).
