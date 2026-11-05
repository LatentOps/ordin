# Cross-agent causal temporal policies

`SwarmTemporalEngine` evaluates bounded temporal patterns over the authenticated
swarm graph. It does not concatenate per-agent 32-action histories. Only actual
causal ancestors of the current proposal can satisfy prior steps; timestamps,
equal resources and unrelated concurrent actions do not create a sequence.
Importing the module starts no collector, background worker or remote service.

## Policy and evidence

The additive `ordin.swarm_temporal_policy_set.v1` format contains a policy ID,
monotonic revision and at most 64 bounded rules. A rule has two to eight steps,
an event/duration window, task or swarm scope, severity and prevention
recommendation. Predicates select shared core effects, action kind/operation,
event kind, evidence class, agent relation, authenticated transfer edge, protected
sensitivity/origin and configured sink identity.

The engine reuses core `TemporalPredicate` / `TemporalActionEvidence` and
the existing deterministic action/shell adapters. It does not parse shell
commands independently or trust effect labels in event JSON. Unknown current
semantics remain unknown; an absent predicted effect is not proof that an
unclassified action is safe.

`record_event(source, event_id, ...)` binds facts to an already-ingested event
from its original protected sender. Pass the original exact `ActionEnvelope`
when recording action semantics. Sensitivity and origin predicates require
original `LineageHandle` / `InstructionOrigin` objects from the same protected
host scope and exact content hash. JSON cannot create those authorities.
Immutable artifact-read origins from the storage gateway can be recorded this
way; private bytes are not copied into temporal reports.

An intended effect remains an intended effect even on a host-reported completion.
An `effect_evidence: observed` predicate requires the original sealed
`RuntimeObservation`, matching collector, action, review anchor and outcome.
Only backend completion contributes observed-effect signals. Allowed and denied
requests never become completed effects. A late observation is a new
authenticated event, not a promotion of an earlier proposal.

Capture times come from the protected coordinator clock. Event JSON timestamps
are ignored for temporal windows. `observed_at` may supply an original
normalized host capture/admission time for delayed delivery; never copy an
agent-authored timestamp into it. Repeating the same capture without an explicit
time preserves the first admission time. Conflicting captures are rejected.
Replay under shuffled ingest with unchanged authenticated parents and capture
times produces the same findings and causal paths; snapshot binding still
identifies the actual journal/fact state.

## Causal automata and quotas

`aggregation: path` advances compiled predicate states only along verified DAG
edges. Steps may skip intermediate causal nodes, but all nodes on the selected
path count against `within_events` and the capture-time window. Cross-agent
steps require actual handoffs; caller hypotheses never count.

`aggregation: causal_ancestors` applies a quota to distinct events, actions or
agents that are each authenticated ancestors of the exact current proposal.
It has one prior predicate and one current final predicate. This supports
coordinated retries and delegation fanout without claiming that parallel
branches happened sequentially. Findings declare their aggregation; their
`path_event_ids` are a deterministic union of the selected actual causal paths.
Repeated stage/observation records for one action do not inflate an
`actions` quota. A `same_sink` quota requires protected configured sink IDs.

Agent relations compare actual enrolled identities/generations. Siblings must
share the exact parent generation; child relations require the current parent.
Delegation edges require the graph's original current issuer/grant/source link.
A serialized grant or parent name cannot create a fanout authority.
Task rules do not join different protected tasks. A missing task identity
remains unknown rather than creating a common implicit task.

The optional maintained bundle
[swarm_temporal_policies.json](../../data/swarm_temporal_policies.json) contains
seven families: sensitive read/relay/upload, untrusted artifact/code execution,
destructive sibling retries, delegation fanout, permission/privilege escalation,
recovery loops and coordinated same-sink API misuse. It is explicitly selected
by `default_swarm_temporal_policy()` or a supplied path, not enabled globally.
Operators should choose rules/windows/quotas for their actual workflow.

## Exact current action and coverage

Evaluate using the current original context, event source and exact action:

```python
result = engine.evaluate(
    context,
    source,
    action,
    parent_event_ids=(received_event_id,),
    uses=(LineageUse(received_lineage, ("parameters", "arguments", "code")),),
)
```

Current parents must belong to that actor. A pointer to another actor's event
cannot substitute for an authenticated receive. When a rule depends on data
flow, its current `LineageUse` must match the actual proposed UTF-8 field bytes
and be causally connected to those parents. A public output is not labeled
exfiltration merely because a secret read happened elsewhere in its ancestry.
Summaries and encodings require the protected derived-output handle.
Data-dependent prior steps are restricted to the actual protected handle
ancestry and matching content references. A control or delegation dependency
alone cannot attribute an independently collected source to earlier bytes.
Ambiguous source origins stay unknown. This temporal guard complements the
ordinary source-flow sink guard; a direct sensitive upload may violate the
sink guard without matching a multi-step relay pattern.

Path-only execution of an artifact cannot establish that file's actual bytes
from a pathname alone. It remains unknown until a supported enforcing boundary
binds the immutable artifact version to execution; direct code arguments can
be correlated exactly. No finding claims successful exploitation or completed
execution of the current proposal.

An established forbidden path can be reported even with incomplete unrelated
history. A negative applicable result requires explicit complete protected
collection for the relevant bounded window. The host collector can call
`cover(source, complete_from=...)` only for collection it actually owns.
Pre-enrollment/pre-attach history cannot be declared complete. Coverage cannot
be extended retrospectively, and stale/disconnected original senders do not
establish a complete window. This is a protected host declaration, not
independent proof that every real-world channel was observed.

Missing parents, capture times, source-use correlation, task/sink identity,
truncated graph windows, untrusted evidence and machine quotas produce gap
codes. No speculative non-match becomes a safe applicable result. A rule whose
known current final selector is definitively inapplicable requires no history
for that rule. Unknown current action semantics still remain unknown.

## Gate integration and lifecycle

Use `issue_assessment` with the existing protected `SwarmAssessmentSource`,
fresh gate policy/snapshot digests and the same current action/parents/uses.
Configure `temporal` as a mandatory `SwarmPolicy.required_checks` entry and
pass the original receipt to `SwarmGate` before the host gateway forwards.
Matched rules issue a violated check; missing facts issue unknown. The gate's
existing deny/escalate policy applies, and stronger baseline findings remain.
The prevention field is a recommendation, never an approval override.

Policy upgrades require a higher revision of the same policy ID, clear coverage
and fence older receipts. New captured facts, coverage changes and protected
lineage/declassification changes also fence issued assessments, including when
the event journal itself did not change. Current action changes, source/session
restart and epoch changes cannot reuse an exact-action assessment.
The engine exposes its policy and configuration digests; configuration includes
the provider incarnation, semantic selection and quotas. When replacing the
provider object rather than upgrading it, the host must fence the shared
assessment authority before adopting the new provider configuration.
Its read-only `binding_digest` additionally includes protected records,
coverage, the actual graph projection and current source lifecycle states for
the host coordinator's runtime snapshot. Keep the independent source-flow
record/configuration binding in that snapshot as well.

Facts, graph nodes, retained automaton states and transitions have independent
caps. Quota exhaustion remains explicit unknown; the engine does not silently
evict safety history and claim completeness. It retains bounded capture metadata
until its fact capacity is reached, then requires an explicit host lifecycle
decision. No JSON snapshot automatically restores live authority.

Validate an explicit file without executing anything:

```bash
ordin swarm temporal validate --policy ./swarm-policy.json --json
```

Contracts:
[policy](../../schemas/swarm-temporal-policy-set.v1.schema.json),
[evaluation](../../schemas/swarm-temporal-evaluation.v1.schema.json),
[validation](../../schemas/swarm-temporal-validation.v1.schema.json).
Reports contain rule/evidence IDs, actor digests, severity, gaps and the exact
current action digest. They omit action bodies and always deny execution authority.
