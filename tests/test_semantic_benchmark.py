import time

from ordin.benchmark import (
    SearchFixture,
    compare_search_quality,
)
from ordin.search import SearchResult


def _result(command: str, score: float) -> SearchResult:
    return SearchResult(
        command=command,
        summary="",
        score=score,
        why="",
        example=None,
        risk="low",
        matched_terms=[],
        suggested_commands=[],
    )


def test_ranker_comparison_quantifies_quality_and_latency_tradeoff():
    fixtures = [
        SearchFixture(
            id="semantic-paraphrase",
            query="make this script launchable",
            expected_commands=("chmod",),
            top_k=2,
            requirement="top1",
            tags=("paraphrase",),
        )
    ]

    def baseline(query: str, limit: int):
        del query
        return [_result("cat", 2.0), _result("chmod", 1.0)][:limit]

    def semantic(query: str, limit: int):
        del query
        time.sleep(0.001)
        return [_result("chmod", 3.0), _result("cat", 2.0)][:limit]

    report = compare_search_quality(
        fixtures,
        baseline_fn=baseline,
        candidate_fn=semantic,
    )
    payload = report.as_dict()

    assert report.baseline.top1_accuracy == 0.0
    assert report.candidate.top1_accuracy == 1.0
    assert payload["metric_delta"]["top1_accuracy"] == 1.0
    assert payload["metric_delta"]["mrr"] > 0
    assert payload["timing"]["candidate_seconds"] > 0
    assert payload["timing"]["latency_ratio"] is not None
