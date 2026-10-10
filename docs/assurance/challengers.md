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
it generates 320 fixtures. The current actual run assesses 244 without a
disagreement; 76 remain unresolved, including deliberately ambiguous path cases,
delegation lifecycle and provider-failure integrations not yet implemented.
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
| Delegation subset | Issued current parent/child grants, expiry/depth/revocation, all domains | A child gains broader current authority; requires M7 verifier |
| Trust origin | Authenticated host records and protected profile handles | Imported/model/agent data becomes host or operator authority; generated import/text-claim checks implemented |
| Optional failure mode | Configured required provider/scanner and declared outage behavior | Failed optional validation improves permission; requires M8/M9 integrations |
| Review-to-use binding | Exact reviewed action/resource/arguments/policy/session commitment | A changed request reuses authorization; generated nested-argument/identity/history/policy/receipt checks implemented |

All these need faithful preconditions, concrete replay and benign counterparts.
Z3 and Hypothesis are not installed on this host; no installation was attempted.
Optional solver-backed integration, dependent delegation/provider checks, safe
promotion and the complete effectiveness corpus remain pending. The finite
seeded checker is a test of the assurance harness, not a discovered Ordin
vulnerability. M5 remains in progress.
