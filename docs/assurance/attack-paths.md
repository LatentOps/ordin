# Bounded attack-path evidence

`build_attack_path` constructs an immutable, versioned graph over at most 32
sealed `ReviewedAction` records from one host principal/repository/session/epoch.
Every record's decision, baseline review and host context are checked before and
after construction. Runtime observations reuse `RuntimeObservationHistory`'s
exact action/contract/source correlation. Completed/allowed observations after
an Assurance denial are refused. Sibling, stale epoch/session and changed policy
sources cannot be silently combined. Cross-agent paths await M7's authenticated
delegation integration.

The graph retains principals, sources, actions, normalized tool/server identities,
resources, intended capabilities, boundaries, observations, sinks and controls.
Edges distinguish predicted requirements, host-observed effects, caller assertions,
imported claims and influence hypotheses. Evidence kinds must match their
underlying origins; confidence is independent and cannot promote trust. Strong
evidence requires private issuance and cannot be restored from ordinary JSON.

Reviewed filesystem/network/code effects describe intended requirements. Only
an authenticated `completed` event establishes a completed effect. A backend
permission or denial is not completion. A secret-path/temporal risk signal can
support a hypothesis while the read remains unobserved. Caller/MCP/model prose
containing `secret.read` cannot produce an authenticated secret read. The existing
temporal engine remains responsible for risk patterns; the graph explains its
signals rather than replacing it. If the supplied sequence does not match the
sealed review history, ordering is explicitly caller asserted.

An `InstructionOrigin`/`SourceUse` pair can establish exact byte inclusion under a
protected host declaration. It cannot establish persuasion or the cause of a
decision. Untrusted instruction inclusion therefore adds a separately identified
influence hypothesis. Without host spans, origins remain `unknown_origin`.

Exposure, intended permissions, reachability, possible impact and proof gaps have
separate fields. The final action is the graph's focus. Its core/profile denial,
backend denial or trusted execution failure becomes counterevidence and blocked
reachability. A severe-looking sink alone establishes no exploit. Generic code
execution is distinct from a download/permission/execute hypothesis, so a benign
package-install control does not acquire the latter label. No graph confirms a
vulnerability, performs an action or grants permission.

Graphs default to 256 nodes, 512 edges and depth at most 64. A non-recursive walk
rejects cycles and excessive depth. Node/edge or per-review detail exhaustion is
reported as an explicit gap; omission never implies safety. Private commands,
arguments, source paths, tool output, identities and resource values are represented
by digests or fixed vocabulary. `render_attack_path` produces a Mermaid view
whose labels also come from a fixed vocabulary. JSON or Mermaid rendering is not
an execution or approval interface.

`deduplicate_attack_paths` keys by required bypass/root cause and authority scope,
while preserving occurrence IDs and distinct evidence outcomes. It cannot merge
different boundaries because descriptions sound alike. `propose_attack_path_tests`
returns a non-authoritative `SecurityProfileDraft` with candidate restrictions.
Safe reproduction, review and protected operator installation remain separate.

Source-flow guard integration uses an explicit `SourceProvenance` host collection
receipt. Complete coverage is an attestation from the instrumented host collector,
not a conclusion from an empty list. Unknown or transformed inputs must remain
partial/unknown. The `assess_source_flow` helper checks a sealed review and selected
approved profile, then exact source/use/action and collection digests. Sensitive
bytes in proposed egress arguments, or untrusted bytes supplied as instruction
context, violate the guard. Absent/partial collection or unknown classification
cannot yield a satisfied result. A non-applicable protected selector remains
non-applicable. The scope-bound assessment is supplied to a **fresh** gate review;
the original escalation never turns into an execution permission.

```python
from ordin.assurance import ReviewedAction, build_attack_path, render_attack_path

# `decision` and `host_context` come from the protected host's actual gate review.
row = ReviewedAction(decision, host_context)
graph = build_attack_path(host_context.source, (row,))
assert graph.reachability == "hypothesis"  # No completed event was supplied.
print(render_attack_path(graph))
```

Tests cover predicted/authenticated secret-read/upload, fake MCP text, source
instructions, denied/failed execution, download/chmod/execute with an install
control, duplicate/foreign/stale evidence, review mutation, cycle/depth/resource
bounds, privacy, proposals and source-flow guard re-review. These are synthetic
offline host-channel fixtures; no real kernel or remote exploitation is claimed.
Cross-agent graphs and finding closure remain M7/M10 work.
