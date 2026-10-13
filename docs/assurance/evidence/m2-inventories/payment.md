# Repository threat-model draft

Non-authoritative local static inventory.

Repository revision: `fixture-v1`; snapshot: `e7d1a78137d4bc99f501c213e3e3cbfaca2f712844c527db354c20b3eacacf0a`.
Inspection coverage: complete; 4 files.

## Inspected entrypoints, controls and sinks

- fact-8c33c8621628628889fc13c8: asset / approval.workflow, `.github/workflows/deploy.yml:1` (bytes `86edab3bf8df`)
- fact-c20b985375355182cd7f2e4a: instruction_data / repository.instructions_untrusted, `AGENTS.md:1` (bytes `e0c95dc3ca99`)
- fact-6155572a45b774cd0b1c938e: instruction_data / repository.instructions_untrusted, `README.md:1` (bytes `695201ef6bee`)
- fact-de00240330ed20c31678bb36: entrypoint / handler.declaration, `payments.py:12` (bytes `e23ccf2a95d9`)
- fact-11011c615ab8983caf0d836c: transformation / serialization.parse, `payments.py:13` (bytes `e23ccf2a95d9`)
- fact-3af7de68ae192e1fab43fe46: control / approval.guard_candidate, `payments.py:14` (bytes `e23ccf2a95d9`)
- fact-3b0963a29328d61808d5b5d7: control / authorization.control_candidate, `payments.py:14` (bytes `e23ccf2a95d9`)
- fact-cc1d4aa09d95f07b7d3e27d6: sink / subprocess.execute, `payments.py:16` (bytes `e23ccf2a95d9`)
- fact-cae7a0ec8d26e3c5d8b1a6c4: sink / network.egress, `payments.py:17` (bytes `e23ccf2a95d9`)
- fact-577b3dd9258ee5ddc02b1ba4: control / module.load_stop_candidate, `payments.py:20` (bytes `e23ccf2a95d9`)

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

- route-cc1d4aa09d95f07b7d3e27d6: outside_attacker -> fact-de00240330ed20c31678bb36 -> transformations fact-11011c615ab8983caf0d836c -> controls fact-3af7de68ae192e1fab43fe46, fact-3b0963a29328d61808d5b5d7 -> fact-cc1d4aa09d95f07b7d3e27d6; hypothesis.
  - Proof gap: Static colocation does not prove data flow or reachability.
- route-cae7a0ec8d26e3c5d8b1a6c4: outside_attacker -> fact-de00240330ed20c31678bb36 -> transformations fact-11011c615ab8983caf0d836c -> controls fact-3af7de68ae192e1fab43fe46, fact-3b0963a29328d61808d5b5d7 -> fact-cae7a0ec8d26e3c5d8b1a6c4; hypothesis.
  - Proof gap: Static colocation does not prove data flow or reachability.
- Candidate counterevidence: fact-3af7de68ae192e1fab43fe46; syntax does not prove this control stops the route.
- Candidate counterevidence: fact-3b0963a29328d61808d5b5d7; syntax does not prove this control stops the route.
- Candidate counterevidence: fact-577b3dd9258ee5ddc02b1ba4; syntax does not prove this control stops the route.

## Proposed assets and invariants

- config-3ec43173a7a9108d08742630: policy / `/fixture/payment/.github/workflows/deploy.yml`; operator selection required.
- protect-config-3ec43173a7a9108d08742630: protected_policy_mutation; suggestion only.

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
