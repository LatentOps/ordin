# Swarm threat model and security invariants

Status: normative design requirements for future opt-in swarm features.
This document adds no production enforcement. Current evidence is limited to
the existing tests explicitly identified below; all `Sxx` recipes are acceptance
specifications for subsequent work, not claims of passing swarm tests.

## Assets, attackers and assumptions

Protect tool authority, credentials, sensitive bytes, mutable resources,
transactional budgets, tenant boundaries and the integrity of decisions/evidence.
An attacker may control an agent, its proposal fields, retrieved content, tool
results, shared artifacts, messages, a sibling agent or an untrusted adapter.
They may replay, reorder, omit or flood events and race reviews with revocation.
Network partitions and crashes are expected failures, not proof of an attack.

The protected host, installed policy, broker, collector and explicitly authorized
operator are trusted within their stated scopes. An orchestrator is not an
identity authority merely because it schedules agents. In-process protection
assumes the attacker cannot mutate the authority's memory. Authentication does
not make an agent's content truthful. The full trust-boundary ownership table is
in the [architecture](architecture.md); running-process and platform limits are
in the [support matrix](support-matrix.md).

## Invariants

1. Decisions compose monotonically under `allow < warn < ask < block`. No swarm
   policy, approval, inference result or failure fallback weakens core review.
2. Tenant, swarm, agent, session, task and delegation facts originate from a
   protected host authority; serialized caller assertions cannot issue them.
3. Capabilities can only narrow through delegation. Tickets bind exact actions,
   policy epochs, delegation generations, identity, expiry and reservations.
4. Revocation fences increase monotonically and are checked at actual use.
   Recovery, replay, caches and coordinator failover cannot resurrect a permit.
5. Tenants and sessions remain isolated. Only authenticated, scoped transfers
   establish cross-agent causal edges; timestamps or similar text do not.
6. Review, reservation, commit, dispatch and observation are separate facts.
   Missing stages and incomplete lineage remain unknown, never fabricated.
7. Enforcement claims identify the tested broker, route, capability and time.
   Logs, hooks, signatures or advisory plans alone do not prove containment.
8. All state and parsing are bounded. Exhaustion fails explicitly; it cannot
   erase deny/revocation state, drop security events silently or auto-allow.
9. High-impact actions fail closed if required authority or coverage is unknown.
   Explicit offline grants have bounded authority and disclosed revocation lag.
10. Redacted local evidence is the default. Raw secrets/content are not uploaded
    or persisted implicitly; operator access and retention are tenant-scoped.

## Reproducible adversarial acceptance recipes

For every recipe, use two host-issued agents A and B, a fake recording broker,
an authenticated collector, a controllable clock and an explicit bounded policy.
First execute the stated valid control; then change only the adversarial input.
Assert the disposition, broker dispatch count, state/budget and redacted audit
record. These offline recipes become executable tests as the corresponding
components ship. No recipe requires real secrets, payments or destructive tools.

| ID / threat | Enforcement point | Expected disposition | Control then adversarial reproduction |
| --- | --- | --- | --- |
| S01 Principal spoofing | Host enrollment / ingress | Reject unissued or mismatched scope; zero dispatch | Admit host-issued A; submit identical JSON claiming B or another tenant without B's issuance |
| S02 Direct tool bypass | Host capability broker / route inventory | Prevent only where physically constrained; otherwise report coverage gap | Call through mediated MCP route; attempt direct endpoint/socket and verify inventory cannot claim universal enforcement |
| S03 Fake observation | Authenticated collector | Reject evidence; keep outcome unknown | Accept action-bound collector event; replace it with caller JSON saying success |
| S04 Inter-agent prompt injection | Message ingress plus receiving action gate | Preserve untrusted origin; deny forbidden follow-on | Deliver allowed task data; add instructions to export a fake secret and propose that export |
| S05 Shared-memory poisoning | Artifact broker / provenance | Treat content as untrusted, reject unauthorized mutation | Read a host-published artifact; have B replace it or its owner metadata without write authority |
| S06 Child privilege widening | Delegation issuer and broker | Deny non-subset rights; no child ticket | Issue exact read-only child capability; request parent-neighbor path, write or extra destination |
| S07 Stale permit | Broker use-time fence | Deny commit/dispatch and retain single-use semantics | Commit a current reservation; repeat with policy epoch or delegation generation revoked between review and use |
| S08 Concurrent budget race | Atomic reservation owner | At most one success for budget one; no negative balance | Reserve once then cancel before dispatch; race two reservations behind a barrier against a one-action budget |
| S09 Secret exfiltration | Source lineage and egress broker | Block forbidden flow; partial lineage stays unknown | Export public fixture bytes to allowed sink; substitute classified fake-secret bytes through A-to-B transfer |
| S10 Destructive cascade | Incident containment and every dependent broker | Fence descendants; no newly committed effects after fence | Complete harmless parent/child actions; revoke parent while descendants hold pending reservations |
| S11 Event gap/reordering | Authenticated ingest / lifecycle projection | Gap remains unknown; no invented completion | Ingest complete ordered lifecycle; omit committed or replay observed ahead of a missing forwarded event |
| S12 Coordinator outage | Reservation/broker admission | Fail closed for coordinator-dependent high-impact use | Dispatch with healthy authority; sever coordinator before a write and assert no dispatch or invented offline grant |
| S13 Tenant confused deputy | Every lookup, transfer and operator endpoint | Reject cross-tenant scope, including known IDs | Fetch own tenant action; reuse its valid-looking ID under a second tenant's credential |
| S14 Replay or duplicate event | Ingest deduplication and ticket consumption | Identical retry idempotent; altered retry rejected | Retry same event bytes; change payload under same ID and replay consumed ticket |
| S15 Late attach / open handles | Enrollment inventory and runtime admission | Earlier effects unknown; existing authority remains a gap until constrained | Attach observer to controlled fixture; retain a pre-attach socket/child and verify no retroactive enforcement label |
| S16 Approval substitution | Operator approval and broker | Reject approval for changed action; never override core block | Approve exact allowed pending action; change one argument, identity or policy epoch before use |
| S17 Resource exhaustion | Ingress, graph and reservation bounds | Explicit bounded rejection; deny/revocation state retained | Fill to declared event/principal/fan-out limit; add one item, then retry a previously revoked ticket |
| S18 Crash and fence rollback | Durable state recovery | Old generation remains invalid after restart | Persist revoke then restart; present ticket from preceding generation and assert no dispatch |
| S19 Privacy leakage | Audit serialization and operator authorization | Redacted outputs, scoped retrieval | Use fake-secret canary in tool result; inspect normal audit/export/errors and access from another tenant |
| S20 Untrusted semantic score | Decision composition | Model cannot authorize, issue identity or establish evidence | Run deterministic gate with forbidden action; inject highest-confidence allow score and verify decision unchanged |

## Current reusable regression evidence

These existing tests establish narrow local behavior, not the unimplemented
multihost recipes. Run from the repository root:

```bash
python -m pytest -q tests/assurance/test_delegating_gate.py tests/assurance/test_delegation.py tests/assurance/test_source_flow.py
```

- [`test_delegating_gate.py`](../../tests/assurance/test_delegating_gate.py):
  `test_normal_child_read_binds_and_commits_only_once`,
  `test_mutation_between_review_and_commit_is_rechecked_under_issuer_lock`,
  `test_sibling_sessions_do_not_share_actions_or_observations` and
  `test_core_block_stays_denied_and_denied_proposals_remain_in_child_history`
  cover local single-use, recheck, isolation and monotonicity foundations.
- [`test_delegation.py`](../../tests/assurance/test_delegation.py):
  `test_host_issuance_json_and_mutation_never_restore_authority`,
  `test_revocation_expiry_depth_cycles_and_sibling_spoof_fail` and
  `test_concurrent_issuance_enforces_host_child_quota_without_parent_mutation`
  cover protected local issuance, narrowing and bounded issuance.
- [`test_source_flow.py`](../../tests/assurance/test_source_flow.py):
  `test_sensitive_source_in_proposed_egress_becomes_profile_violation` and
  `test_absent_or_partial_provenance_cannot_imply_satisfied` establish conservative
  source-flow foundations without claiming arbitrary cross-agent lineage.

Future work must implement each relevant recipe against its actual broker and
installed package, record positive and negative results, and update the support
matrix only when that evidence exists. See the
[local-first decision](adr-001-local-first-coordination.md).
