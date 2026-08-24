from pathlib import Path

from commandgraph.benchmark import (
    SearchFixture,
    evaluate_search_quality,
    load_search_fixtures,
)
from commandgraph.search import SearchResult


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "benchmarks" / "search_quality.jsonl"


def _fixtures():
    return load_search_fixtures(FIXTURE_PATH)


def test_search_quality_fixture_corpus_is_well_formed():
    fixtures = _fixtures()
    ids = [fixture.id for fixture in fixtures]

    assert len(fixtures) >= 25
    assert len(ids) == len(set(ids))
    assert all(fixture.tags for fixture in fixtures)
    assert {"permissions", "network", "disk", "files", "packages", "git", "docker"} <= {
        tag for fixture in fixtures for tag in fixture.tags
    }


def test_search_quality_fixture_requirements_hold():
    report = evaluate_search_quality(_fixtures())
    failures = "\n".join(case.diagnostic() for case in report.failures)

    assert not report.failures, failures


def test_search_quality_baseline_metrics_do_not_regress():
    report = evaluate_search_quality(_fixtures())

    assert report.recall_at_k >= 0.95, report.as_dict()
    assert report.top1_accuracy >= 0.60, report.as_dict()
    assert report.mean_reciprocal_rank >= 0.75, report.as_dict()


def test_benchmark_reports_rank_and_tag_metrics():
    fixtures = [
        SearchFixture(
            id="demo",
            query="demo query",
            expected_commands=("second",),
            top_k=3,
            tags=("demo",),
        )
    ]

    def fake_search(query: str, limit: int):
        del query
        results = [
            SearchResult(
                command="first",
                summary="",
                score=2.0,
                why="",
                example=None,
                risk="low",
                matched_terms=[],
                suggested_commands=[],
            ),
            SearchResult(
                command="second",
                summary="",
                score=1.0,
                why="",
                example=None,
                risk="low",
                matched_terms=[],
                suggested_commands=[],
            ),
        ]
        return results[:limit]

    report = evaluate_search_quality(fixtures, search_fn=fake_search)
    case = report.cases[0]

    assert case.first_relevant_rank == 2
    assert case.passed is True
    assert report.top1_accuracy == 0.0
    assert report.recall_at_k == 1.0
    assert report.mean_reciprocal_rank == 0.5
    assert report.tag_metrics()["demo"]["pass_rate"] == 1.0
