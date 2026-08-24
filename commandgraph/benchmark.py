from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .search import SearchResult, search


VALID_REQUIREMENTS = {"top1", "top_k"}


@dataclass(frozen=True)
class SearchFixture:
    id: str
    query: str
    expected_commands: tuple[str, ...]
    top_k: int = 3
    requirement: str = "top_k"
    tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, payload: dict) -> "SearchFixture":
        fixture_id = payload.get("id")
        query = payload.get("query")
        expected = payload.get("expected")
        top_k = payload.get("top_k", 3)
        requirement = payload.get("requirement", "top_k")
        tags = payload.get("tags", [])

        if not isinstance(fixture_id, str) or not fixture_id.strip():
            raise ValueError("search fixture requires a non-empty string id")
        if not isinstance(query, str) or not query.strip():
            raise ValueError(f"fixture {fixture_id!r} requires a non-empty query")
        if (
            not isinstance(expected, list)
            or not expected
            or any(not isinstance(item, str) or not item for item in expected)
        ):
            raise ValueError(
                f"fixture {fixture_id!r} requires a non-empty expected command list"
            )
        if not isinstance(top_k, int) or top_k < 1:
            raise ValueError(f"fixture {fixture_id!r} top_k must be >= 1")
        if requirement not in VALID_REQUIREMENTS:
            raise ValueError(
                f"fixture {fixture_id!r} requirement must be one of "
                f"{sorted(VALID_REQUIREMENTS)}"
            )
        if (
            not isinstance(tags, list)
            or any(not isinstance(tag, str) or not tag for tag in tags)
        ):
            raise ValueError(f"fixture {fixture_id!r} tags must be strings")

        return cls(
            id=fixture_id,
            query=query,
            expected_commands=tuple(expected),
            top_k=top_k,
            requirement=requirement,
            tags=tuple(tags),
        )


@dataclass(frozen=True)
class SearchCaseResult:
    fixture: SearchFixture
    ranked_commands: tuple[str, ...]
    first_relevant_rank: int | None
    passed: bool

    @property
    def top1_hit(self) -> bool:
        return self.first_relevant_rank == 1

    @property
    def recall_hit(self) -> bool:
        return (
            self.first_relevant_rank is not None
            and self.first_relevant_rank <= self.fixture.top_k
        )

    @property
    def reciprocal_rank(self) -> float:
        if self.first_relevant_rank is None:
            return 0.0
        return 1.0 / self.first_relevant_rank

    def diagnostic(self) -> str:
        expected = ", ".join(self.fixture.expected_commands)
        ranked = ", ".join(self.ranked_commands) or "<no results>"
        return (
            f"{self.fixture.id}: query={self.fixture.query!r}; "
            f"expected={expected}; requirement={self.fixture.requirement}; "
            f"top_k={self.fixture.top_k}; got={ranked}"
        )


@dataclass(frozen=True)
class SearchBenchmarkReport:
    cases: tuple[SearchCaseResult, ...]

    @property
    def case_count(self) -> int:
        return len(self.cases)

    @property
    def passed_count(self) -> int:
        return sum(case.passed for case in self.cases)

    @property
    def top1_accuracy(self) -> float:
        if not self.cases:
            return 0.0
        return sum(case.top1_hit for case in self.cases) / len(self.cases)

    @property
    def recall_at_k(self) -> float:
        if not self.cases:
            return 0.0
        return sum(case.recall_hit for case in self.cases) / len(self.cases)

    @property
    def mean_reciprocal_rank(self) -> float:
        if not self.cases:
            return 0.0
        return sum(case.reciprocal_rank for case in self.cases) / len(self.cases)

    @property
    def failures(self) -> tuple[SearchCaseResult, ...]:
        return tuple(case for case in self.cases if not case.passed)

    def tag_metrics(self) -> dict[str, dict[str, float | int]]:
        tags = sorted({tag for case in self.cases for tag in case.fixture.tags})
        metrics: dict[str, dict[str, float | int]] = {}
        for tag in tags:
            tagged = tuple(case for case in self.cases if tag in case.fixture.tags)
            if not tagged:
                continue
            metrics[tag] = {
                "cases": len(tagged),
                "pass_rate": sum(case.passed for case in tagged) / len(tagged),
                "top1_accuracy": sum(case.top1_hit for case in tagged) / len(tagged),
                "mrr": sum(case.reciprocal_rank for case in tagged) / len(tagged),
            }
        return metrics

    def as_dict(self) -> dict:
        return {
            "cases": self.case_count,
            "passed": self.passed_count,
            "top1_accuracy": round(self.top1_accuracy, 4),
            "recall_at_k": round(self.recall_at_k, 4),
            "mrr": round(self.mean_reciprocal_rank, 4),
            "tags": self.tag_metrics(),
            "failures": [case.diagnostic() for case in self.failures],
        }


def load_search_fixtures(path: Path) -> list[SearchFixture]:
    fixtures: list[SearchFixture] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON at {path}:{line_number}: {exc.msg}"
                ) from exc
            if not isinstance(payload, dict):
                raise ValueError(
                    f"fixture at {path}:{line_number} must be a JSON object"
                )
            fixtures.append(SearchFixture.from_dict(payload))
    return fixtures


def _first_relevant_rank(
    ranked_commands: Iterable[str],
    expected_commands: tuple[str, ...],
) -> int | None:
    expected = set(expected_commands)
    for rank, command in enumerate(ranked_commands, start=1):
        if command in expected:
            return rank
    return None


def evaluate_search_quality(
    fixtures: Iterable[SearchFixture],
    *,
    search_fn: Callable[[str, int], list[SearchResult]] = search,
) -> SearchBenchmarkReport:
    cases: list[SearchCaseResult] = []
    for fixture in fixtures:
        results = search_fn(fixture.query, fixture.top_k)
        ranked = tuple(result.command for result in results)
        rank = _first_relevant_rank(ranked, fixture.expected_commands)
        passed = rank == 1 if fixture.requirement == "top1" else (
            rank is not None and rank <= fixture.top_k
        )
        cases.append(
            SearchCaseResult(
                fixture=fixture,
                ranked_commands=ranked,
                first_relevant_rank=rank,
                passed=passed,
            )
        )
    return SearchBenchmarkReport(cases=tuple(cases))
