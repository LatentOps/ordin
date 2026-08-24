from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from math import log
from typing import Callable

from . import SEARCH_SCHEMA_VERSION
from .availability import EnvironmentInfo, command_availability, detect_environment
from .data import load_commands, load_synonyms
from .templates import suggest_commands


TOKEN_RE = re.compile(r"[a-zA-Z0-9_.+-]+")
STOPWORDS = {
    "a",
    "an",
    "and",
    "for",
    "how",
    "i",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "the",
    "this",
    "to",
    "what",
}
WEAK_MATCH_TERMS = {
    "command",
    "directory",
    "directories",
    "file",
    "files",
    "folder",
    "folders",
    "path",
    "paths",
}


@dataclass(frozen=True)
class SearchResult:
    command: str
    summary: str
    score: float
    why: str
    example: str | None
    risk: str
    matched_terms: list[str]
    suggested_commands: list[dict[str, str]]
    available: bool | None = None
    executable_path: str | None = None
    platform_compatible: bool | None = None
    availability_reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "schema_version": SEARCH_SCHEMA_VERSION,
            "command": self.command,
            "summary": self.summary,
            "score": round(self.score, 3),
            "why": self.why,
            "example": self.example,
            "risk": self.risk,
            "matched_terms": self.matched_terms,
            "suggested_commands": self.suggested_commands,
            "available": self.available,
            "executable_path": self.executable_path,
            "platform_compatible": self.platform_compatible,
            "availability_reason": self.availability_reason,
        }


def tokenize(text: str) -> list[str]:
    return [
        token.lower()
        for token in TOKEN_RE.findall(text)
        if token.lower() not in STOPWORDS
    ]


def expand_query(query: str, synonyms: dict[str, list[str]]) -> Counter[str]:
    tokens = tokenize(query)
    expanded: Counter[str] = Counter()
    for token in tokens:
        expanded[token] += 2.0
        for synonym in synonyms.get(token, []):
            expanded[synonym] += 0.8
    return expanded


def command_text(entry: dict) -> str:
    parts = [
        entry.get("command", ""),
        entry.get("summary", ""),
        " ".join(entry.get("intents", [])),
        " ".join(entry.get("aliases", [])),
        " ".join(entry.get("risk_tags", [])),
    ]
    for example in entry.get("examples", []):
        parts.append(example.get("command", ""))
        parts.append(example.get("explanation", ""))
    return " ".join(parts).lower()


def command_tokens(entry: dict) -> Counter[str]:
    return Counter(tokenize(command_text(entry)))


def phrase_match_score(query: str, entry: dict) -> tuple[float, str | None]:
    normalized_query = " ".join(tokenize(query))
    if not normalized_query:
        return 0.0, None

    best_score = 0.0
    best_reason: str | None = None
    for intent in entry.get("intents", []):
        normalized_intent = " ".join(tokenize(intent))
        if not normalized_intent:
            continue
        if normalized_query == normalized_intent:
            return 8.0, f'exact intent "{intent}"'
        if normalized_query in normalized_intent or normalized_intent in normalized_query:
            score = 4.0
            if score > best_score:
                best_score = score
                best_reason = f'near intent "{intent}"'

    for alias in entry.get("aliases", []):
        normalized_alias = " ".join(tokenize(alias))
        if normalized_alias and normalized_alias in normalized_query:
            score = 3.0
            if score > best_score:
                best_score = score
                best_reason = f'alias "{alias}"'

    return best_score, best_reason


def idf_by_term(commands: list[dict]) -> dict[str, float]:
    doc_count = len(commands)
    document_frequency: Counter[str] = Counter()
    for entry in commands:
        document_frequency.update(set(command_tokens(entry)))
    return {
        term: log((doc_count + 1) / (frequency + 0.5)) + 1.0
        for term, frequency in document_frequency.items()
    }


def search(
    query: str,
    limit: int = 5,
    *,
    environment: EnvironmentInfo | None = None,
    which: Callable[[str], str | None] | None = None,
) -> list[SearchResult]:
    synonyms = load_synonyms()
    expanded = expand_query(query, synonyms)
    commands = load_commands()
    idf = idf_by_term(commands)
    results: list[SearchResult] = []
    query_tokens = set(tokenize(query))
    environment = environment or detect_environment()

    for entry in commands:
        score = 0.0
        matched_terms: set[str] = set()
        strong_terms: set[str] = set()
        token_counts = command_tokens(entry)
        command_name = entry.get("command", "").lower()

        for term, weight in expanded.items():
            if not term:
                continue
            count = token_counts.get(term, 0)
            if count:
                matched_terms.add(term)
                if term not in WEAK_MATCH_TERMS:
                    strong_terms.add(term)
                score += weight * idf.get(term, 1.0) * min(count, 3)
            if term == command_name:
                matched_terms.add(term)
                strong_terms.add(term)
                score += 6.0

        phrase_score, phrase_reason = phrase_match_score(query, entry)
        score += phrase_score

        for intent in entry.get("intents", []):
            intent_tokens = set(tokenize(intent))
            overlap = intent_tokens & query_tokens
            if overlap:
                score += 2.5 * len(overlap)

        for alias in entry.get("aliases", []):
            alias_overlap = set(tokenize(alias)) & query_tokens
            if alias_overlap:
                score += 2.0 * len(alias_overlap)

        if command_name in query_tokens:
            score += 8.0

        if score <= 0 or (phrase_score <= 0 and not strong_terms):
            continue

        availability = command_availability(
            entry,
            environment=environment,
            which=which,
        )
        score += availability.score_adjustment

        examples = entry.get("examples", [])
        example = examples[0]["command"] if examples else None
        suggested_commands = suggest_commands(entry, query)
        matched = sorted(matched_terms)[:6]
        why_parts = []
        if phrase_reason:
            why_parts.append(phrase_reason)
        if matched:
            why_parts.append(f"matched {', '.join(matched)}")
        why_parts.append(availability.reason)
        why = "; ".join(why_parts) if why_parts else "matched command graph metadata"
        results.append(
            SearchResult(
                command=entry["command"],
                summary=entry["summary"],
                score=score,
                why=why,
                example=example,
                risk=entry.get("default_risk", "unknown"),
                matched_terms=matched,
                suggested_commands=suggested_commands,
                available=availability.installed,
                executable_path=availability.executable_path,
                platform_compatible=availability.platform_compatible,
                availability_reason=availability.reason,
            )
        )

    return sorted(results, key=lambda result: (-result.score, result.command))[:limit]
