# Repository threat-model draft

Non-authoritative local static inventory.

Repository revision: `fixture-v1`; snapshot: `14127b7c34b13571643d9a77317dabc8b209f23801368f66accd2cbfdb1c3b5d`.
Inspection coverage: complete; 1 files.

## Inspected entrypoints, controls and sinks

- fact-1a0aa9b9f8bfcad0333fec18: entrypoint / mcp.handler_candidate, `server.py:10` (bytes `1eaf6a728f3d`)
- fact-f4b4b4737385a38a0ca01830: sink / network.egress, `server.py:11` (bytes `1eaf6a728f3d`)
- fact-ea5c4f4f1f43d3ec153619d0: control / module.load_stop_candidate, `server.py:14` (bytes `1eaf6a728f3d`)

## Actors and trust boundaries

- outside_attacker: possible actor; actual control remains unverified.
- malicious_dependency_or_mcp_server: possible actor; actual control remains unverified.
- compromised_sibling_agent: possible actor; actual control remains unverified.
- unauthorized_insider: possible actor; actual control remains unverified.
- external-input: outside_attacker -> application_handler; deployment enforcement unknown.
- tool-to-executor: malicious_dependency_or_mcp_server -> executor; deployment enforcement unknown.
- child-to-parent: compromised_sibling_agent -> parent_agent; deployment enforcement unknown.
- repository-to-ci: repository_data -> ci_runtime; deployment enforcement unknown.

## Route hypotheses and strongest counterevidence

- route-f4b4b4737385a38a0ca01830: malicious_dependency_or_mcp_server -> fact-1a0aa9b9f8bfcad0333fec18 -> transformations unknown -> controls uninspected -> fact-f4b4b4737385a38a0ca01830; hypothesis.
  - Proof gap: Static colocation does not prove data flow or reachability.
- Candidate counterevidence: fact-ea5c4f4f1f43d3ec153619d0; syntax does not prove this control stops the route.

## Proposed assets and invariants


## Assumptions

- The host supplied the repository revision and action-space mapping; no Git attestation is inferred.
- Static parsing establishes inspected syntax, not execution, authentication effectiveness or data flow.
- Deployment infrastructure, filesystem aliases and actual process privileges are uninspected.

## Open questions

- Which inputs are attacker controlled and which handlers are externally reachable?
- Which host enforces filesystem, network, tool and credential constraints?
- Are candidate authorization controls unavoidable on each relevant route?
- Which assets are production and where are credentials mounted?
- How are child identities, grants and approval workflows authenticated?

## Coverage gaps

- Which inputs are attacker controlled and which handlers are externally reachable?
- Which host enforces filesystem, network, tool and credential constraints?
- Are candidate authorization controls unavoidable on each relevant route?
- Which assets are production and where are credentials mounted?
- How are child identities, grants and approval workflows authenticated?

Hashes are correlation aids, not encryption. No raw source or secret values are included.
