from pathlib import Path

from ordin.availability import EnvironmentInfo
from ordin.benchmark import evaluate_search_quality, load_search_fixtures
from ordin.search import search, search_legacy


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "benchmarks" / "search_quality.jsonl"
ENVIRONMENT = EnvironmentInfo(
    os="linux",
    distro_id="ubuntu",
    distro_like=("debian",),
)


def _which(command: str) -> str:
    return f"/usr/bin/{command}"


def _bm25(query: str, limit: int):
    return search(
        query,
        limit,
        environment=ENVIRONMENT,
        which=_which,
    )


def _legacy(query: str, limit: int):
    return search_legacy(
        query,
        limit,
        environment=ENVIRONMENT,
        which=_which,
    )


def test_bm25_meets_all_search_fixture_requirements():
    report = evaluate_search_quality(
        load_search_fixtures(FIXTURE_PATH),
        search_fn=_bm25,
    )
    failures = "\n".join(case.diagnostic() for case in report.failures)

    assert not report.failures, failures


def test_bm25_improves_or_preserves_legacy_benchmark_metrics():
    fixtures = load_search_fixtures(FIXTURE_PATH)
    bm25 = evaluate_search_quality(fixtures, search_fn=_bm25)
    legacy = evaluate_search_quality(fixtures, search_fn=_legacy)

    assert bm25.recall_at_k >= legacy.recall_at_k, {
        "bm25": bm25.as_dict(),
        "legacy": legacy.as_dict(),
    }
    assert bm25.top1_accuracy >= legacy.top1_accuracy, {
        "bm25": bm25.as_dict(),
        "legacy": legacy.as_dict(),
    }
    assert bm25.mean_reciprocal_rank >= legacy.mean_reciprocal_rank, {
        "bm25": bm25.as_dict(),
        "legacy": legacy.as_dict(),
    }


def test_bm25_explanation_surfaces_principal_ranking_signals():
    result = _bm25("make file runnable", 1)[0]

    assert result.command == "chmod"
    assert "bm25 lexical" in result.why
    assert "intent" in result.why
    assert "available locally" in result.why


def test_legacy_ranker_remains_available_for_comparison():
    results = _legacy("lookup dns for domain example.com", 3)

    assert results
    assert "legacy lexical" in results[0].why
