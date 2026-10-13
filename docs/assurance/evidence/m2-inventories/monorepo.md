# Repository threat-model draft

Non-authoritative local static inventory.

Repository revision: `fixture-v1`; snapshot: `899346fbd837af974e04f3bad1536518af50b3b2e50a50c432853ed8dfe8340d`.
Inspection coverage: complete; 3 files.

## Inspected entrypoints, controls and sinks

- fact-c5250c43031fb3e151eaa66f: instruction_data / repository.instructions_untrusted, `README.md:1` (bytes `576411e0a841`)
- fact-1be46ff641abeb35d2b4113a: entrypoint / handler.declaration, `packages/production/app.py:7` (bytes `854e10f9d48f`)
- fact-b987827bfaa4ad920f4e8a7b: control / authorization.control_candidate, `packages/production/app.py:8` (bytes `854e10f9d48f`)
- fact-daf0f1761dfc8b990b7136c9: sink / subprocess.execute, `packages/production/app.py:9` (bytes `854e10f9d48f`)
- fact-016a886e4747803afcdee7ad: entrypoint / handler.declaration, `packages/test/app.py:6` (bytes `f3422b1013c0`)
- fact-962126264a7f692f21ec981c: sink / filesystem.write, `packages/test/app.py:7` (bytes `f3422b1013c0`)

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

- route-daf0f1761dfc8b990b7136c9: outside_attacker -> fact-1be46ff641abeb35d2b4113a -> transformations unknown -> controls fact-b987827bfaa4ad920f4e8a7b -> fact-daf0f1761dfc8b990b7136c9; hypothesis.
  - Proof gap: Static colocation does not prove data flow or reachability.
- route-962126264a7f692f21ec981c: outside_attacker -> fact-016a886e4747803afcdee7ad -> transformations unknown -> controls uninspected -> fact-962126264a7f692f21ec981c; hypothesis.
  - Proof gap: Static colocation does not prove data flow or reachability.
- Candidate counterevidence: fact-b987827bfaa4ad920f4e8a7b; syntax does not prove this control stops the route.

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
