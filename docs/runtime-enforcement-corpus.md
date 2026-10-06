# Runtime enforcement adversarial corpus

The versioned [cases](../benchmarks/runtime_enforcement.json) exercise semantic
decisions, intended boundaries, compiler representability, proposal approval,
and runtime correlation. The [recorded report](reports/runtime-enforcement-corpus.json)
contains 13 passed cases with explicit decisions and evidence/reason codes.

```sh
python scripts/run_runtime_enforcement_corpus.py \
    --json-out runtime-enforcement-corpus.json
```

Cases cover predicted and denied secret-like reads before upload, unseen-host
writes, GET-to-DELETE expansion, repeated denial retries and alternate tools,
credential introduction, host wildcard expansion, REST-to-TCP fallback,
read-only-to-write and outside-repository scopes, changed action digests, and
cross-session observations. Wildcard host input is rejected by the contract
schema before it can reach a compiler. Every case checks both non-success or
approval/attention status and specific evidence; green counts alone are not a
runtime enforcement claim.

The corpus uses non-secret synthetic evidence and host-owned source objects.
It complements [actual runtime observations](openshell-runtime-demo.md), kernel
positive/negative controls, the compiler/prover adversaries, and existing Ordin
safety/trajectory corpora. It does not infer malicious intent or weaken existing
semantic danger when supplied observations disagree.
