# Search Quality Benchmark

CommandGraph keeps a deterministic search-quality fixture corpus in
`benchmarks/search_quality.jsonl`. The benchmark exists to make retrieval
changes measurable and to prevent silent regressions in the intent-to-command
experience.

## What It Measures

Each fixture contains:

- a natural-language intent query;
- one or more acceptable commands;
- a required match mode (`top1` or `top_k`);
- the evaluation cutoff;
- tags for category-level diagnostics.

The evaluator in `commandgraph.benchmark` reports:

- Top-1 accuracy;
- recall at each fixture's cutoff;
- mean reciprocal rank (MRR);
- per-fixture relevant-command rank;
- tag-level pass rate, Top-1 accuracy, and MRR.

The fixture corpus covers permissions, file operations, disk inspection,
network/DNS diagnostics, process management, package management, Git, Docker,
slot-filled queries, and paraphrased intents. Default-enabled command packs are
part of the normal search surface and therefore part of the benchmark.

## Running It

The benchmark runs with the normal test suite:

```bash
pytest -q tests/test_search_benchmark.py
```

or as part of the complete suite:

```bash
pytest -q
```

A regression failure prints the query, accepted commands, requirement, cutoff,
and the commands that were actually ranked. This is intended to make ranking
changes diagnosable without manually trying CLI queries.

## Adding Fixtures

Add a JSON object per line. Example:

```json
{"id":"permissions-runnable","query":"make file runnable","expected":["chmod"],"requirement":"top1","top_k":3,"tags":["permissions","paraphrase"]}
```

Use `top1` when the user intent has one clearly preferred command and the
ordering should remain stable. Use `top_k` when multiple valid Linux tools may
reasonably satisfy the intent or exact ordering should remain flexible.

Fixtures should describe user intent rather than embedding the expected command
name solely to make the benchmark easy to pass. Accept multiple commands when
the task genuinely has interchangeable tools.

## Relationship to Ranking Work

This benchmark is the baseline for later ranking work. Changes such as BM25,
availability/distro signals, or optional semantic reranking should report their
impact on this corpus rather than being tuned only against ad-hoc examples.

The benchmark itself is local, deterministic, and has no model or network
dependency.
