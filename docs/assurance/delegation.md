# Host-issued delegation

`verify_delegation_subset` checks a proposed child authority against its current
parent, protected operator maximum and task maximum. The accepted child is the
requested subset of their intersection; a broader proposal is refused rather
than silently rewritten. Filesystem access/scope, literal endpoints/protocols/
methods/paths, exact request commitments, tool identities, executables/spawn,
privilege/euid, credential destination bindings and approval requirements are
retained. Broad TCP cannot substitute for specific protocol authority.

`DelegationAuthority` is immutable data. JSON parsing can inspect it but cannot
issue a grant. `DelegationVerification` reports complete domain coverage only
when all checks pass. Unrestricted child executable authority, child wildcard
network languages and other unrepresentable rights remain unsupported; no such
constraint is discarded. Exact child rights can be checked against supported
wildcard parent network grants. No proof establishes actual OS enforcement.

`DelegationIssuer` is selected by the protected host with an approved profile,
actual operator/task maxima, a host-owned clock and bounded quotas. It authorizes
a root principal and issues children only after containment, current ancestry,
identity, lifetime, depth and quota checks. An immutable `IssuedDelegation` has a
private issuance seal and issuer-owned registration. Its serialized
`DelegationGrant` is an audit artifact, not current authority. JSON grants,
changed fields, another issuer, stale epoch/session/profile/policy, duplicate IDs,
ambiguous parent, self-delegation and cycles are refused. The trusted host process
and identity/maximum selection remain outside an untrusted agent's control.
Python objects cannot defend against malicious code inside that trusted process.

Revocation invalidates a grant, descendants and pending uses. A generation change
also invalidates older cached reviews; unrelated children need a fresh review.
Changed host configuration requires a fresh issuer or explicit host invalidation.
The clock refuses rollback and invalid timestamps. Failed issuance does not
change parent authority or reset history. Default quotas are 128 lifetime grant
IDs, 16 active children per parent, eight pending operations and 256 committed
actions per grant. Limits are host-owned and bounded; per-tool extensions are
not implemented. Old immutable audit records do not reflect later revocation;
current use must always consult the issuer.

`DelegatingAssuranceGate` wraps `AssuranceGate` and keeps one existing
`IntegrationSession` per child. It retains rejected proposals and preserves core
denials. Principal/role/intent text in arguments grants no rights. Current grants
are checked against complete derived operations, including authenticated
credential routes and exact v2 request arguments. Mandatory delegation-profile
rows receive a current host assessment followed by a fresh exact-action review.
Approval requirements, unsupported semantics and stale grants never become
automatic permits. Existing core/profile requirements cannot be weakened.

An executable result reserves a private use ticket. `commit_use(result, action)`
rechecks the exact action, review, history, policy, grant generation and ancestry
under the issuer lock, consumes the ticket once and updates quotas. It returns
whether the software binding was current; it does not execute, mint credentials
or atomically enforce kernel revocation. The external broker must forward the
bound bytes and enforce rights/revocation at execution. Children with inherited
host-level privileges can bypass software-only annotations.

Runtime collectors reuse exact session/source/contract checks. Initialize the
child host scope with the actual planned session digest, then bind a matching
collector and policy. JSON cannot become a backend observation; a sibling cannot
supply the child's completion. `ActionObservation` remains caller asserted.
Session reset revokes the child grant without resetting parent/sibling state.

`build_delegated_attack_path` composes independently scoped graphs only for a
current private issued relationship. Child inputs must be sealed
`DelegatedDecision` results, so a denied operation cannot appear authorized
because its underlying core review allowed it. Node IDs include host scope;
identical local IDs/tool names cannot merge different principals. An authenticated
`delegated_to` edge establishes relationship only. Cross-action source lineage
must reference a retained parent action and exact child-host byte use. It remains
a host declaration, not proof of persuasion or completed transfer. Distinct
session digests are preserved, and revoked/stale/foreign relationships refuse
current path construction.

Offline tests cover readonly source/test controls, `.env`/neighbor rejection,
MCP arguments/tool/version rights, GET/POST/path distinctions, verified exact
network intersection, depth/expiry/revocation, clock rollback, concurrent issuance
and reviews, quotas, duplicate/spoofed identities, fabricated/sibling observations,
pending-operation revocation, commit-time mutation and cross-agent graphs. These
are synthetic host fixtures: no command executes and no OS permission is issued.
