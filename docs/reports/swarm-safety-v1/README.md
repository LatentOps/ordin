# Swarm safety v1 report guide

The canonical inputs are [the versioned swarm corpus](../../../benchmarks/swarm/v1/README.md).
The dedicated `swarm-corpus` CI workflow installs only hash-locked build/test
tooling, runs generated/stateful regression tests, builds an exact-source wheel,
then requires the installed Linux broker lane and unchanged performance budgets.
No real model provider is used. Existing core review defaults are unchanged;
running this evaluation is explicit and opt-in.

Read `scope.cases`, its label/lane counts, `scope.evaluated`, and
`metrics.kernel_not_run` together. A pure run includes the entire inventory but
marks kernel cases `not_run` with `matched: null`; it cannot establish the
required kernel subset. `scope.critical_not_run` prevents a zero miss count from
being confused with complete enforcement coverage. No cherry-picked pass rate
or deployment prevalence is reported.

Optional behavioral-risk cases remain `unknown`/`not_evaluated` when the later
feature is absent. `metrics.optional_not_evaluated` and
`scope.critical_not_evaluated` retain those cases and their critical status in the
whole denominator. They are excluded from evaluated passes. With that feature
installed, original core approvals must remain restrictive under independent
risk escalation, denial or missing-signal escalation; missing-ignore preserves
the baseline. Synthetic calibration false positives and false negatives are
published in those cases rather than treated as perfect model performance.

`critical_misses` includes every evaluated critical judgment mismatch or failed
invariant, including unexpected unknown results. An expected, explicitly
declared unknown fault or unsupported-path control is counted in `unknowns` and
retained in the denominator. Unmediated parent access is counted in
`uncovered_paths`. Benign false blocks and unnecessary escalations are published
alongside false allows, invariant failures, and authenticated kernel completions.
An expected required approval is distinguished from an unnecessary escalation.

Each result keeps separate fields:

- `core_intent`: reviewed decision, effects, and the composed disposition.
- `model_inference`: diagnostic status with `evidence_authority: false`.
- `backend_facts`: original callback or authenticated backend outcomes and the
  physical-enforcement claim for the supported owned kernel path.
- `facts` and `checks`: bounded test observations and independently declared
  assertions. A callback completion is not evidence that an arbitrary process
  was confined by the OS.

Source-flow violation means the planned transfer violates the declared sink
policy. It does not establish observed exfiltration. An untrusted serialized
tool result cannot promote a diagnostic claim to an original observation.
The packaged runtime uses public synthetic TLS leaf keys exclusively in an
isolated loopback lab; its CA must never be trusted by a production service.
SQLite is a single-host development coordinator fixture. Production consensus,
real multi-host network partitions, live providers, arbitrary plugin code, and
unmediated parent execution require their own evidence.

The `audit-intent-inference` control captures original reviewed intent and a
synthetic diagnostic model risk without recording an observed completion. The
separate `kernel-audit-provenance` control adds an actual original broker result,
checks that its one backend observation is projected accurately, and refuses a
copied broker result. Both verify the bounded audit chain against an explicit
checkpoint, tenant-keyed resource references, and absence of canary contents and
raw paths. These controls do not turn an audit hash chain into execution authority.

The JSON report records the exact Git revision, input/implementation SHA-256,
seed, Python/platform, complete results, errors, and limitations. Its stable
result digest excludes timing fields, so repeated deterministic judgments can
be compared without pretending latency is deterministic. Latency summaries use
nearest-rank p50/p95/p99 in milliseconds and publish sample counts. Scenario
times include fixture setup; `revocation_check_latency_ms` times stale-authority
refusal checks. The separate overhead report distinguishes cold world setup,
warm operation samples, signed paired deltas, input capacity, and bounded
retained-session state. It keeps the existing p95 250 ms and p99 500 ms budgets.

Protected snapshot fingerprints still rebuild and hash the complete current
event and stream rows under the original lock on every call. Their fixed
primitive payload uses the identical canonical UTF-8 JSON bytes without a
redundant recursive container copy. Identity digests keep the generic encoder;
no observed joins or prior snapshot hashes are cached. Differential tests cover
empty, 683-event and 4,096-event payloads, Unicode, ordering, roles, scope and
stream-generation changes. These tests prove fingerprint equivalence; actual
latency qualification still requires the unchanged benchmark gates.

Reports are evidence artifacts and always carry `execution_authority: false`.
Synthetic successes do not authorize deployment or prove safety in arbitrary
agent frameworks. Reproduce on a clean exact revision using the commands in the
corpus guide, retain both JSON and Markdown reports in an owned output directory,
and compare the full inventories and unknown/uncovered counts.
