# Bounded counterexample challengers

The initial challenger compares Ordin's actual full capability verifier with an
independent finite oracle for one filesystem property: an exact read of an
unambiguous ASCII POSIX path must be contained in the `/fixture` directory-prefix
read maximum. The synthetic fixture declares lexical scope and filesystem
guarantees for this calculation; no real host guarantee is established.

`challenge_authority_subset(seed=14, revision="fixture-v1", trials=16)` tests the
actual verifier. `variant="seeded_prefix_bug"` instead selects a fixed, deliberately
incorrect synthetic checker that treats `/fixture2` as inside `/fixture`.
The generator is standard-library only. It never loads an evaluator from a
target repository, executes fixture commands, reads fixture paths, or accesses
an endpoint. Seed/version/input-manifest digests bind the deterministic generated
order. Trial count is limited to 256, the time budget to 30 seconds, and each
minimization to 512 deletion attempts.

Malformed/ambiguous/encoded paths are outside this oracle's preconditions. They
remain unresolved rather than becoming proofs of containment. Timeout is also
partial. A discovered counterexample can prove a failure while the rest of a
run remains unresolved; the report records both counts.

The minimizer deletes path characters while preserving the exact same property,
fixed maximum, access rights, generator, variant, and expected/actual mismatch.
It cannot substitute a parse error or change a read into a delete. Both original
and minimized captures are concretely rechecked before a `CounterexampleRecord`
is emitted. Duplicate minimized failures are retained once. Independent replay
requires the same revision and checks both captures rather than trusting the
record's claimed outcome. JSON can describe a reproducer, never host enforcement
or a confirmed finding.

```console
ordin-assure challenge run --seed 14 --revision fixture-v1 --trials 16 --variant seeded_prefix_bug
ordin-assure challenge replay ./counterexample.json --revision fixture-v1
```

The seeded run returns exit 1 after finding four failing variants, shrinking
them to two distinct paths, and retaining four benign controls. Six cases stay
unresolved because they violate the oracle's path preconditions. Against the
actual verifier the same 16 cases have no disagreement in the ten supported
cases, and exit 2 for incomplete coverage. Exit 0 means all requested fixtures
were assessed without a mismatch; it does not prove all paths, invariants or domains. Replay exit 0 means reproduction
of the declared failure; it does not mean a secure policy. `--report` has the same
explicit-new-file behavior as policy simulation.

`ChallengeRun` and its source/package schema are closed, bounded and immutable.
Summary counts/status must agree; serialization cannot promote partial coverage
to passed or assert that a host boundary was exercised. Environment metadata
uses Python/system APIs, avoiding Windows' `platform` subprocess fallback.

The multi-property API also exercises actual core reviews, capability/request
verifiers, contract discovery, session/runtime correlation, trust import and
review-to-use bindings. It generates shell flag/quoting/nesting/compound variants,
URL authority and protocol changes, GraphQL alias/fragment/variable/batch
changes, RPC ID controls, tool schema/discovery drift, queue eviction/reset,
denied reformulation, and secret-read/upload temporal controls. Untrusted
instruction text remains data. No target evaluator or plugin can be selected.

```console
ordin-assure challenge run --seed 14 --revision fixture-v1 --suite --trials 32
ordin-assure challenge run --seed 14 --revision fixture-v1 --property tool_identity --trials 32
ordin-assure challenge run --seed 14 --revision fixture-v1 --suite --trials 32 --variant seeded_unsafe_checker
```

The suite preserves all ten required property names. At 32 trials per property,
it generates 320 fixtures when its declared time budget completes. With the
optional decision-model SDK installed, the actual suite assesses 308 without
a disagreement and retains 12 deliberately ambiguous path cases as unresolved.
Core-only runs assess 280 and retain 40 unresolved cases, including 28
model-dependent cases. No optional package is installed by the generator.
The result stays `inconclusive`. These are property fixtures, not the later
100-adversarial/100-benign effectiveness benchmark. A short run also retains
every missing declared scenario and cannot report complete coverage.

`ChallengeSuite` and `ChallengeRun` reject omitted required coverage, duplicate
sample IDs and contradictory summaries. Every sample retains action/authority
material digests, the input digest, relation, expected/actual property result and
scope. `accepted` refers to the particular verifier/property being challenged;
it does not authorize executing the action. Request and policy fixture material
is reconstructed from the closed generator and pinned source version. The
manifest binds ordered captures. Minimized multi-property captures retain the
same action material, maximum, scenario, assumptions and failure signature.
Decorative fields and irrelevant scalar material may shrink; a changed binding
or a different failure cannot replace the original one. Replay verifies both
captures and disregards the claimed status.

The core intentionally allows REST within a broader raw TCP transport maximum.
Assurance adds exact protocol separation for approved basic capability and
request-subset invariants. It first verifies all core constraints, including
credentials, files, tools, processes and complete request commitments, then adds
an internal protocol-only check. An explicit REST/GraphQL/MCP/JSON-RPC grant is
required for that protocol; raw TCP supplies raw TCP only in this layer. The
legacy APIs and their broader behavior remain intact. The differential fixture
records `tcp_to_rest` as `expected_policy_difference`, not a confirmed runtime
vulnerability. This additional restriction can cause expected approval friction.

The property inventory and remaining integration work are:

| Property | Preconditions and trusted inputs | Failure meaning / outstanding work |
| --- | --- | --- |
| Authority subset | Exact modeled rights, protected maximum, complete domain verification | Requested rights exceed the maximum; initial finite filesystem challenger implemented |
| Monotonicity | Same normalized action, history and protected configuration; additional valid restrictions/evidence | A final disposition becomes weaker; generated policy/shell/narrowing checks implemented |
| Exact request commitment | Same protocol, canonical body semantics, protected v2 commitment | A changed material request reuses authority; GraphQL/RPC/MCP generated checks implemented |
| Protocol separation | Distinct REST/GraphQL/MCP/JSON-RPC/TCP domains and exact authorities | One domain borrows another's grant; generated protocol/URL checks and stricter Assurance checks implemented |
| Tool identity | Protected registry, contract pin and complete discovery | A drifted identity inherits trusted semantics; schema/identity/discovery/semantics-digest checks implemented |
| History/observations | Retained non-denied action, exact session/epoch/event correlation | Unknown/stale/denied/cross-session evidence is accepted; generated queue/reset/source/temporal checks implemented |
| Delegation subset | Issued current parent/child grants, expiry/depth/revocation, all domains | A child gains broader current authority; generated all-domain containment checks and separate lifecycle/runtime tests implemented |
| Trust origin | Authenticated host records and protected profile handles | Imported/model/agent data becomes host or operator authority; generated import/text-claim checks implemented |
| Optional failure mode | Actual routing SDK with project-owned mock provider, pinned synthetic task/action, and core scanner/parser/consent APIs | Mandatory outage/malformed evidence/budget exhaustion/configuration drift improves permission; 22 generated offline scenarios with benign counterparts and independent replay |
| Review-to-use binding | Exact reviewed action/resource/arguments/policy/session commitment | A changed request reuses authorization; generated nested-argument/identity/history/policy/receipt checks implemented |

All these need faithful preconditions, concrete replay and benign counterparts.
The default suite uses no solver, live model or external scanner. Hypothesis,
safe promotion and the complete effectiveness corpus remain pending. The finite
seeded checker is a test of the assurance harness, not a discovered Ordin
vulnerability. M5 remains in progress.

The default optional property now uses generator `optional-failures-v1`.
It checks disabled and shadow parity, deterministic denial/approval preservation,
required-provider absence, timeout/transport/refusal/malformed/untrusted/version/
question errors, uncertainty, total-call and concurrency budgets, a real bounded
router timeout with its worker lease retained, and configuration drift. A fresh
healthy mock counterpart retains the same action and host context. Scanner
absence/pre-cancellation, malformed workflow claims and absent validation consent
exercise their actual refusal APIs over owned temporary files. No proposed
action, marker executable, scanner or target source is run.

`seeded_unsafe_checker` selects a closed, deliberately unsafe consumer that
discards refusal, mandatory attention or current-binding checks after the real
SDK has run. Thirty-two trials produce 24 failures and six benign controls,
minimized into 18 distinct records, when all work completes. These are defects
in that fixture consumer, not a claim of a production Ordin vulnerability.
Absent/incompatible SDKs or an unresolved benign counterpart remain unsupported;
neither can establish a verified failure. All existing trial, time and output
bounds remain unchanged.

The frozen `security-properties-v1` fixture and saved records retain their
original unavailable-only optional property. Its meaning is never reinterpreted:

```console
ordin-assure challenge run --seed 14 --revision fixture-v1 --property optional_failure_mode --trials 32
ordin-assure challenge run --seed 14 --revision fixture-v1 --property optional_failure_mode --trials 32 --variant seeded_unsafe_checker
ordin-assure challenge run --seed 14 --revision fixture-v1 --suite --trials 32 --legacy-optional-failures
```

The Python equivalent for the legacy property is
`challenge_property(property_id="optional_failure_mode", seed=14,
revision="fixture-v1", generator_version="security-properties-v1")`.
Replay binds generator version, property, scenario, variant, assumptions, action
and policy in both captures. A changed generation cannot replace the original
failure during shrinking or replay.

Explicit finite SMT challenges are available through the optional development
extra `.[assurance-dev]`, pinned to Z3 5.1.0.0. Ordinary imports and default
reviews never load Z3. Missing solver installations produce a validated
`unavailable`/`inconclusive` record. The implementation uses the
[official Z3 Python API](https://z3prover.github.io/api/html/z3py_8py_source.html).

```console
ordin-assure challenge solve --revision reviewed-sha --report /private/solver.json
ordin-assure challenge solve --revision reviewed-sha --encoding seeded_union_abstraction --report /private/union-candidate.json
ordin-assure challenge solver-replay /private/union-candidate.json --revision reviewed-sha
```

The fixed three-bit domain represents atomic read/write/delete rights on one
exact synthetic path. Parent, operator and task maxima are independently
specified by `--parent-mask`, `--operator-mask` and `--task-mask` (0–7). All other
domains remain empty. Faithful intersection cannot authorize rights outside the
intersection and returns UNSAT. This is only `no_counterexample_in_finite_model`,
with explicit proof gaps and no host enforcement claim.

The deliberately inaccurate union encoding can return SAT. Its assignment is
shrunk by removing rights while retaining the same property and maxima, then
both assignments are independently replayed through the real delegation
verifier. The actual verifier rejects the abstract excess, so the conclusion is
`candidate_not_reproduced` and the CLI returns 2. SAT is never promoted to a
confirmed vulnerability. Solver unknown/timeouts are also inconclusive. A
concretely reproduced verifier failure would return 1 and remain limited to this
finite declaration domain; it would still establish no physical exploit.

The immutable `SolverChallenge` contract includes the exact SMT input as bounded
lines, its SHA-256, solver version, seed, resource budget, original/minimized
rights, assumptions, concrete results and benign control. Decoding reconstructs
the fixed formula and concrete replay instead of executing supplied SMT. Changed
input/assumptions, inconsistent outcomes, false UNSAT labels and attempted host
trust promotion are rejected. Replay requires the pinned revision and works
without Z3. Each solve uses its own solver context, a timeout of at most ten
seconds and a fixed solver work limit. No target program, subprocess, filesystem
mutation outside owned fixtures, endpoint or model provider is exercised.

`tests/assurance/test_solver.py` compares all 4,096 exact three-bit
request/parent/operator/task combinations against concrete verification, and
tests actual SAT/UNSAT, missing/unknown solvers, hostile inputs and CLI replay.
The separate CI solver job exercises the optional extra; the ordinary wheel
smoke proves its absence remains explicit.
