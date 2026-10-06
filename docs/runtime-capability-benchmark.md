# Runtime capability benchmark

The recorded [JSON report](reports/runtime-capability-benchmark.json) measures
local review with explicitly declared deployment context, review plus capability
derivation, and verification of the resulting intended capability boundary.
No reviewed action is executed, and backend/network/human-approval latency is
excluded.

Run from an installed development environment:

```sh
python scripts/run_runtime_capability_benchmark.py --repetitions 30 \
    --json-out runtime-capability-benchmark.json
```

The workload contains `git status --short`, a literal disabled-curlrc GET to the
GitHub rate-limit API, one scratch-file removal proposal, and an unknown command.
Each of four workloads has three warmup iterations and 30 measured iterations:
120 samples per stage. Boundaries retain unsupported results rather than treating
unknown semantics as successful verification (90 within, 30 unsupported).

| Stage | Median ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: |
| Review with declared context | 27.591 | 40.819 | 47.352 |
| Review with context + contract | 28.685 | 41.320 | 66.009 |
| Intended-boundary verification | 0.273 | 0.546 | 0.598 |

Measured with Python 3.12.3 on native Linux storage under WSL2 kernel
5.15.167.4, glibc 2.39, using a native Linux PATH. The JSON records the exact
source snapshot digest. These are local workload measurements, not a universal
performance or security guarantee. Review includes existing command-availability
and curated-data access; derivation and boundary verification perform no live
filesystem traversal, DNS lookup, subprocess execution, or network access.
