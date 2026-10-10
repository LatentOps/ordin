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

The broader property inventory and remaining work are:

| Property | Preconditions and trusted inputs | Failure meaning / outstanding work |
| --- | --- | --- |
| Authority subset | Exact modeled rights, protected maximum, complete domain verification | Requested rights exceed the maximum; initial finite filesystem challenger implemented |
| Monotonicity | Same normalized action, history and protected configuration; additional valid restrictions/evidence | A final disposition becomes weaker; gate tests exist, generated challenger pending |
| Exact request commitment | Same protocol, canonical body semantics, protected v2 commitment | A changed material request reuses authority; generated protocol challenger pending |
| Protocol separation | Distinct REST/GraphQL/MCP/JSON-RPC/TCP domains and exact authorities | One domain borrows another's grant; generated protocol challenger pending |
| Tool identity | Protected registry, contract pin and complete discovery | A drifted identity inherits trusted semantics; generated tool challenger pending |
| History/observations | Retained non-denied action, exact session/epoch/event correlation | Unknown/stale/denied/cross-session evidence is accepted; generated queue challenger pending |
| Delegation subset | Issued current parent/child grants, expiry/depth/revocation, all domains | A child gains broader current authority; requires M7 verifier |
| Trust origin | Authenticated host records and protected profile handles | Imported/model/agent data becomes host or operator authority; broader generated fixtures pending |
| Optional failure mode | Configured required provider/scanner and declared outage behavior | Failed optional validation improves permission; requires M8/M9 integrations |
| Review-to-use binding | Exact reviewed action/resource/arguments/policy/session commitment | A changed request reuses authorization; gate tests exist, generated runtime challenger pending |

All these need faithful preconditions, concrete replay and benign counterparts.
Optional Z3/Hypothesis integration, cross-domain differential generation, safe
promotion and the complete adversarial corpus remain unimplemented. The finite
seeded checker is a test of the assurance harness, not a discovered Ordin
vulnerability. M5 remains in progress.
