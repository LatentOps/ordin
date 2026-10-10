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
target code was not executed. The separate vetted source-test path below supports
a finite synthetic predicate. Broader domain-specific predicates, independently
exercised host setup and external Codex validate/patch/verify-fix claim reports
still need implementation or verification. No unsafe command or live exploit is a fixture.
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

## Vetted synthetic source tests

`load_vetted_program` accepts only a bounded function `within_root(path, root)`
whose body is one return expression over its two string inputs. The closed AST
grammar permits equality, boolean combination, string addition, `startswith`
and `rstrip`. Imports, loops, decorators, arbitrary names/calls, dunder access,
annotations and embedded source literals beyond slash/empty string are refused.
Source comments are removed from the private worker payload. The exact original
file hash and normalized executable program digest remain bound separately.

`load_synthetic_suite` pins exact fixture bytes containing canonical paths only
under `/synthetic`. It requires both benign and boundary controls, unique case
IDs and distinct inputs. Expected behavior is computed independently from the
declared lexical property; fixture labels cannot hide a failure. Physical paths,
symlinks, relative/alias resolution and private assets are outside this domain.

`VettedSandboxRuntime` selects a native broker and fixed `_sandbox_worker.py`
outside target/enclosing Git roots. The complete argument list is the operator's
explicit command allowlist. Native/worker byte hashes and reviewed installation
digest, private home/working directory, deadline, output/CPU/memory/process
limits and target exclusions are bound into the setup action. Broker code must
actually enforce no egress, no credentials/private mounts, read-only installation
and target separation plus resource limits. A Windows Job or POSIX process group
provides lifetime cleanup; it does not implement those isolation guarantees.

`authorize_sandbox_test` requires actual protected approval and a satisfied
`validation_isolation` assessment for invariant `validation.sandbox`, matching
the exact source/profile/setup. Host code must verify the controls before issuing
this receipt. JSON consent or an operator-supplied digest alone is insufficient.
The worker receives only the vetted code, fixed synthetic inputs, resource
contract and correlation digests. No host issuance interface, raw history,
repository mount, ambient environment keys or agent-selected command reaches it.
Scopes are short-lived and single-use. Source/installation drift, expired scope,
timeouts, malformed/partial answers, output overflow and cancellation prevent
successful closure. Output contains measured booleans rather than a worker verdict.

`validate_finding_sandboxed` currently supports `synthetic_path_boundary` and
`PATH_PROPERTY_DIGEST`. It retains the actual `SandboxTestRun` digest in the
finding. `verify_source_fix` repeats the original failing code before executing
the exact proposed candidate bytes with unchanged test bytes, actor, profile and
runtime. It retains benign regressions and false allows. A known canonical fix
has a reviewed non-widening relation to the prefix bug across all supported
canonical lexical inputs; changed semantics beyond those templates remain unknown.
The result is `fixed-verified`, `still-vulnerable` or `inconclusive` within this
finite source/test domain, with no automatic application or integration.

Local process tests use a fake approved broker and constrained synthetic code.
They measure worker behavior and cleanup; they do not independently establish a
physical sandbox. Live broker verification, broader vulnerability predicates,
full affected safety/unit/integration suites and release acceptance remain open.
