# Finding validation and proposed fixes

Finding review and validation are separate from imported scanner claims.
`review_finding` checks exact source bytes and revisions selected by an
`AuthorizedRepository`. Its `FindingRubric` records the actor, controlled source,
allowed permissions, invariant and expected authority digest, source-to-sink
references, existing controls, preconditions, changes and unknowns. References
establish inspected bytes; they do not establish attacker control or causality.
Existing controls remain affirmative counterevidence candidates.

`validate_finding_static` always remains inconclusive about reproduction.
`load_replay_fixture` reads a bounded inert JSON proposal pinned by a
`SourceReference`. It imports no target module and executes no command.
`validate_finding_replay` runs an actual Assurance gate and independently checks
the derived capability contract against the selected expected boundary.
Its current vetted predicate is `gate_authority_subset`: whether this gate
permits a proposed contract exceeding that bound. Other vulnerability classes,
invalid/stale source, unknown mappings or unverified preconditions remain
inconclusive with an explicit gap. This proves the finite gate property rather
than target repository exploitability or backend execution.

`validate_finding_host_observation` accepts existing sealed review and runtime
evidence for the exact fixture, action, contract, session and policy. Generic
completion does not prove that all requested permissions were granted. Successful
grant closure requires `HostContractAuthorization` recorded by the protected
host only after actual backend verification of the entire granted contract.
The receipt binds the backend event and contract; it contains no issuing or
execution interface. Denied observations can refute the tested attempt, while
failures/unknown events remain inconclusive. This SDK channel authenticates the
host result and does not implement physical OS enforcement. Do not mint a grant
receipt from model text, an imported verdict or a requested contract alone.

`close_finding` binds the original candidate, source review and validation. It
rechecks source and fixture bytes, retains the exact validation digest and tested
scope, and clears unverified numeric confidence. An imported candidate is kept
separately under its original digest; its original status and reported claims
are unchanged. JSON decoding cannot recreate positive closure, source-review,
grant or validation handles. Duplicate grouping retains exact occurrence-record
digests rather than selecting the strongest verdict. Grouping is correlation,
not proof of a common root cause.

`propose_invariant_remediation` creates an inert draft requiring operator review
and exact authority/mapping selection. `propose_remediation` records explicitly
selected old/new detached `SimulationPolicy` configurations, protected profile
changes and conservative authority containment. Neither activates a policy.
`propose_source_patch` generates a bounded single-file unified diff in memory
from exact old bytes and an explicitly supplied replacement. It changes no
checkout. `private_patch()` and `private_policy_artifact()` are explicit private
review/export interfaces; they may contain sensitive source/configuration.
Routine `public_dict()` summaries contain hashes, scope and counts.

`verify_fix` first replays the preserved original failure, then the proposed
policy, benign counterparts, supplied alternative routes and affected policy
simulation. Original/candidate fixture hashes and actions must match: changing
or deleting a test cannot obtain green. Known permission widening, unsupported
containment, missing provenance, benign regressions and unresolved predicates
prevent `fixed-verified`. A surviving path or supplied alternative route yields
`still-vulnerable`. The verdict is limited to `policy_replay` and is never
publication/integration approval. Unprovided alternatives are outside coverage.
Latency samples are retained; they are not repeated matched performance gates.
Affected safety/unit/integration checks and full release validation remain
separate requirements.

Source-code patches remain inconclusive under policy replay because the changed
target code was not executed. A vetted minimal sandboxed test runner, broader
domain-specific reproduction predicates, independently exercised host setup and
the optional external Codex validate/patch/verify-fix report workflows still need
implementation or verification. No unsafe command or live exploit is a fixture.
Applying patches, creating PRs, integrating, publishing or deploying are separate
explicit operator actions.

After installing the core wheel, run the completely synthetic offline example:

```bash
python -I -m ordin.assurance.validation_demo
```

The example creates temporary synthetic fixture data, confirms a finite gate
configuration violation and verifies a narrower policy with a preserved benign
counterpart. It prints redacted summaries and applies no patch. It is not a
security or effectiveness benchmark for a real repository.
