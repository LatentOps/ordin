# Typed invariants and conservative review

`AssuranceGate` composes with an existing `AgentGate`. It calls that gate first,
retains the complete original `AgentDecision`/review, and returns an independent
`AssuranceDecision`. It never runs the action, applies OS permissions, invokes a
scanner/model, or mutates core review/provenance. With no selected/required
profile, disposition and review remain identical to the baseline.

Hard core denial returns immediately without optional evidence. A baseline
escalation cannot become execute. With an active profile, core ask/warn labels
retain an escalation requirement even under a permissive baseline threshold.
Satisfied constraints cannot relax anything; violated operator-selected rules
add escalate or deny. Unsupported/inconclusive mandatory rules add escalation.
Final dispositions use execute < escalate < deny only; existing review-label
precedence and enforcement ordering remain separate and unchanged.

| Invariant | Required facts / behavior |
| --- | --- |
| `require_approval` | Exact host-issued approval for action/profile/current host scope; optional exact contract binding |
| `forbid_effect` | Established core effect and operator scope; missing effects remain inconclusive |
| `protected_policy_mutation` | Known filesystem mutation and exact/slash-bounded protected path; multiple resource/effect associations remain inconclusive |
| `resource_subset` | Named host capability boundary; all existing capability domains checked by `verify_runtime_capability` |
| `network_request_subset` | Named exact v2 request boundary; existing parsers/verifier bind protocol, method, body/parameters and original capability |
| `credential_binding` | Host-controlled opaque credential-use receipt plus independent credential maximum and reviewed network destination |
| `temporal_action_guard` | Existing review trajectory category, plus host-bound retained history to establish absence |
| `source_flow_guard` | Matching authenticated host assessment; static/imported/model influence claims cannot establish causal flow |
| `delegated_authority_subset` | Matching authenticated current host assessment; grant subset/lifecycle verifier integration is M7 work |

Current resource selectors support canonical path/policy resources. Ambiguous
paths and unsupported resource identities stay unsupported, rather than being
projected into broader selectors. A generic `file.write` envelope cannot supply
effects via its arguments; ordinary core unknown semantics still require review.

Host context is constructed through a protected `HostEvidenceSource` with the
actual principal, repository/revision, session, epoch, runtime policy and selected
profile identity. `source.context()` binds named capability/request maxima,
approval receipts, credential routing, assessments and optional exact history.
Ordinary JSON cannot activate context, approval, routing, assessment or decisions.
Receipts from another principal/session/epoch/policy fail source matching.

`record_approval` must be called only after real host-authorized approval.
`record_assessment` records a result already verified on an authenticated host
channel; it does not infer taint, validate a child grant, or execute a reproducer.
An assessment with proof gaps cannot declare satisfied/violated. Its origin is
`host_authenticated_assessment`, never `runtime_backend_observed`. M6/M7 supply
the actual source-flow/delegation verification; missing results remain explicit.
These constructors, like `RuntimeEvidenceSource`, do not protect against
malicious Python inside the trusted host process or incorrect host wiring.

Credential-use receipts contain only an opaque ID and destination, never a
credential value. The gate adds these exact host-bound requirements beside the
existing contract. Destination mismatch violates the invariant. Credential-only
verification isolates that domain using the existing verifier; this internal
question is never exported as an execution contract or claimed to cover process,
filesystem or application request permissions. Use independent required subset
invariants and an enforcing executor for those domains.

`AssuranceDecision.as_dict()` defaults to a compact redacted report with baseline
labels, safe effect categories, evidence/contract/action/configuration hashes,
reason codes and separate invariant results. Raw arguments, paths, profile
content, host principal/session and credential destinations are absent. The SDK
`baseline`/`review` properties retain private original evidence for the caller.
Digests are neither signatures nor encryption.

Before forwarding, the caller must check `gate.binding_matches(decision,
decision.review.action, host_context=host, history=history)` against the actual
current action/context/configuration. It detects changed arguments, original
review, baseline configuration, profile, policy/session/epoch/context or history.
Use the exact normalized reviewed action: a core default context may differ from
the original input envelope. Refuse or re-review changes. This API supplies no
kernel enforcement, atomic filesystem object binding, execution grant or human
approval bypass; the external host remains responsible at use time.
