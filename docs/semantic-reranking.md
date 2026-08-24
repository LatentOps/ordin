# Optional Local Semantic Reranking

CommandGraph keeps deterministic BM25 retrieval as the default. Semantic reranking is an explicit opt-in layer applied only to a bounded BM25 candidate set.

## Default Behavior

A normal search does not import an ML framework, load a model, or change the deterministic ranker:

```python
from commandgraph.search import search

results = search("make file runnable")
```

Every result reports `semantic_reranked: false` and `semantic_score: null`.

## Local Sentence-Transformer Backend

Install the optional dependency only when needed:

```bash
pip install 'commandgraph[semantic]'
```

Then point CommandGraph at an **existing local model directory**:

```python
from commandgraph.search import search
from commandgraph.semantic import SentenceTransformerReranker

reranker = SentenceTransformerReranker.from_local_path("/models/all-MiniLM-L6-v2")
results = search(
    "make this script launchable",
    semantic_reranker=reranker,
)
```

The loader requires the supplied filesystem path to exist and requests local-only model loading. CommandGraph does not translate a model name into a remote Hub download.

## Reranking Boundary

Semantic mode does not search the whole command catalog independently. CommandGraph first runs normal BM25 retrieval and selects a bounded candidate pool:

```text
intent
  -> deterministic BM25 + explicit signals
  -> top bounded candidate pool
  -> local semantic similarity
  -> capped score adjustment
  -> final ordering
```

The semantic score is clamped to `[-1, 1]`. Its contribution is multiplied by a bounded semantic weight and fixed scale, preventing an optional backend from arbitrarily overwhelming exact command, intent, alias, or availability evidence.

The default semantic weight is `0.5`; callers may choose a value from `0.0` to `1.0`.

## Result Provenance

Search-result JSON includes:

- `semantic_reranked`: whether semantic scoring was used;
- `semantic_score`: the bounded similarity score when used.

The human-readable `why` explanation also includes the backend name and similarity value.

## Custom Local Backends

A backend only needs to implement the small `SemanticReranker` protocol:

```python
class MyReranker:
    name = "my-local-model"

    def score(self, query, documents):
        return [0.0 for _ in documents]
```

The backend must return exactly one numeric score per candidate document. CommandGraph validates the count and clamps the values before applying them.

This interface allows local research models without coupling the core package to one embedding framework.

## Benchmarking Quality and Cost

`commandgraph.benchmark.compare_search_quality()` evaluates a baseline and candidate ranker on the same fixture list and reports:

- Top-1 accuracy delta;
- Recall@K delta;
- MRR delta;
- baseline elapsed time;
- candidate elapsed time;
- latency ratio.

This lets a local semantic model quantify the quality/cost tradeoff on `benchmarks/search_quality.jsonl` before being adopted in a workflow.

The checked-in CI suite uses fake deterministic backends and never downloads or installs an embedding model.
