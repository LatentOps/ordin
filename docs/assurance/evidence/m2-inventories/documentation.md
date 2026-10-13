# Repository threat-model draft

Non-authoritative local static inventory.

Repository revision: `fixture-v1`; snapshot: `0bf90389f98591f52841c5422f8aa75e79b673542c431de42fe18d3986b43c9a`.
Inspection coverage: complete; 1 files.

## Inspected entrypoints, controls and sinks

- fact-ff2fd0c86fbf1cf0fb15e7a7: instruction_data / repository.instructions_untrusted, `README.md:1` (bytes `c2276c21ec53`)

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
