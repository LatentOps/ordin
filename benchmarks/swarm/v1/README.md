# Swarm corpus v1

This opt-in, offline evaluation uses synthetic tenants, actors, canaries, files,
and loopback mTLS workload identities. `manifest.json` declares the expected
judgment before the implementation runs. The loader freezes v1 labels, critical
status, lane, and judgments; a caller cannot hide a miss by relabeling a case.
No provider, model download, user command history, production credential, or
production target is required. Reports contain bounded diagnostic facts rather
than raw messages, command parameters, file contents, or certificates.

`capture-index.json` records **zero captured runtime cases**. Reconstructions
cite their public design issue and exact source revision. A
`synthetic_from_failure` case records an independently reproduced failure;
`control` identifies a constructed benign, adversarial, unknown, or bypass
control. None of these classifications means a synthetic case was independently
reviewed by a human. Private traces must remain outside this distribution.
Promotion requires operator review, collection provenance, irreversible
sanitization of paths/parameters/credentials, and a synthetic public equivalent.

Run from a clean checkout at an exact revision, using the hash-locked development
baseline in `requirements/dev-baseline.txt`:

```bash
python -m ordin.swarm.benchmark_cli corpus --revision <40-character-git-sha> --output pure.json
python -m ordin.swarm.benchmark_cli corpus --kernel --revision <40-character-git-sha> --output kernel.json
python -m ordin.swarm.benchmark_cli overhead --revision <40-character-git-sha> --samples 32 --long-actions 1024 --output overhead.json
python scripts/check_swarm_corpus_wheel.py --revision <40-character-git-sha> --workspace /owned/new-corpus-check
```

Output paths must be new files. The CLI validates the published report schema,
uses exclusive creation and owner-only permissions where supported, and exits
nonzero for a failed evaluation. `--markdown new-report.md` adds a readable
report. The wheel check creates a fresh environment outside the checkout,
verifies exact wheel/source bytes, and runs the pure lane, required Linux kernel
lane, and performance gate using the installed package. Its report SHA records
the exact manifest and implementation bytes in addition to the Git revision.

The deterministic scheduler explores topological operation orders for 2–10
actors. It publishes the seed, explored-order digest, schedule count, and
truncation. Small schedules are exhaustively checked; the 128-order corpus limit
does not claim exhaustive coverage of larger state spaces. Generated tests cover
monotonic restrictions and labels, tenant isolation, budget bounds, original
events, permit replay, and epoch fences. Fault controls include an owned process
that writes a synthetic partial effect and exits before a completion receipt,
persisted uncertain budget holds, retry/recovery, out-of-order collectors,
coordinator unavailability, and workload-service unavailability over real mTLS.
Availability injection is a deterministic partition control, not a test of a
production network or PostgreSQL consensus.

The pure lane measures reviewed intent, original host gateway decisions, and
owned callback effects. It provides no kernel enforcement claim. The separate
Linux lane uses original grants, broker authorizations, a real bounded file-read
backend, and authenticated backend observations. Copied/serialized results,
swapped action bytes, stale grants, replay, and an untrusted executor result do
not become trusted completion. Raw parent access is deliberately reported as
uncovered. Missing evidence and unsupported protocols remain unknown.

Performance limits are declared before measurement: warm p95 **250 ms**, p99
**500 ms**, using unchanged `SafetyThresholds` defaults. Reports separate world
setup from warm operations, use eight warmup operations, and measure core review,
swarm review, and an owned callback forwarding path for 2, 5, and 10 actors.
Signed paired review deltas preserve timer noise; their p95 differs from the
difference between the two review p95 values, and both are published. Input
shapes are 1,024, 16,384, and 32,768 ASCII bytes; a 65,536-character parameter
must be rejected by the existing 32,768-character contract. Long sessions run up
to 1,024 actions and report actual completed actions, retained history limits,
snapshot bytes, and safe refusal at the existing 4,096-event journal capacity.
The benchmark stops at that bound and does not claim the remaining requested
actions completed or discard missing journal evidence to continue.
Thresholds also apply to size checks and the last 32 long-session forwards.
Cold interpreter/import startup, arbitrary framework/provider latency, billing,
and deployment distributions are outside these measurements.

See [the report guide](../../../docs/reports/swarm-safety-v1/README.md) for how
to interpret denominators, misses, false blocks, unknowns, and backend facts.
