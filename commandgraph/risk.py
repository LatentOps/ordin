from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from . import RISK_SCHEMA_VERSION
from .data import find_command, load_risk_rules
from .graph import effects_for_tokens
from .shell import (
    SHELL_EXECUTABLES,
    command_name_candidates,
    command_substitutions,
    executable_name_from_tokens,
    grouped_subshells_from_tokens,
    segment_text,
    shell_script_from_tokens,
    split_shell_segments,
)


RISK_ORDER = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
DECISION_ORDER = {
    "allow": 1,
    "ask": 2,
    "warn": 3,
    "block": 4,
}
RULE_EXECUTABLES = {
    "recursive_delete": {"rm"},
    "force_delete": {"rm"},
    "root_delete": {"rm"},
    "root_glob_delete": {"rm"},
    "chmod_recursive": {"chmod"},
    "chmod_777": {"chmod"},
    "process_kill": {"kill", "pkill", "killall"},
    "force_push": {"git"},
    "curl_shell": {"curl", "wget"},
    "sudo": {"sudo"},
    "chown_recursive": {"chown"},
    "package_install": {"npm", "pip", "python", "python3"},
    "docker_prune": {"docker"},
    "docker_rm_force": {"docker"},
    "read_private_key": {"cat", "less", "more", "tail", "head"},
    "read_env_file": {"cat", "less", "more", "tail", "head"},
}
SENSITIVE_REDIRECT_PREFIXES = (
    "/bin/",
    "/boot/",
    "/etc/",
    "/root/",
    "/sbin/",
    "/usr/",
    "~/.ssh/",
)


@dataclass(frozen=True)
class RiskReview:
    decision: str
    risk: str
    reasons: list[str]
    safer_next_step: str | None = None
    matched_rules: list[str] | None = None
    risk_categories: list[str] | None = None

    def as_dict(self) -> dict:
        return {
            "schema_version": RISK_SCHEMA_VERSION,
            "decision": self.decision,
            "risk": self.risk,
            "reasons": self.reasons,
            "safer_next_step": self.safer_next_step,
            "matched_rules": self.matched_rules or [],
            "risk_categories": self.risk_categories or [],
        }


def max_risk(current: str, candidate: str) -> str:
    return candidate if RISK_ORDER[candidate] > RISK_ORDER[current] else current


def decision_for_risk(risk: str) -> str:
    if risk == "critical":
        return "block"
    if risk in {"high", "medium"}:
        return "warn"
    if risk == "unknown":
        return "ask"
    return "allow"


def _append_unique(target: list[str], values: Iterable[str]) -> None:
    for value in values:
        if value not in target:
            target.append(value)


def _rule_applies(rule: dict, tokens: list[str]) -> bool:
    scope = RULE_EXECUTABLES.get(rule["id"])
    if not scope:
        return True
    return bool(command_name_candidates(tokens) & scope)


def _sensitive_redirection_target(tokens: list[str]) -> str | None:
    for index, token in enumerate(tokens[:-1]):
        if token not in {">", ">>", ">|", "&>", "&>>", "<>"}:
            continue
        target = tokens[index + 1]
        normalized = target.rstrip("/")
        if target in {
            "/etc",
            "/boot",
            "/usr",
            "/bin",
            "/sbin",
            "/root",
            "~/.ssh",
        }:
            return target
        if any(
            target.startswith(prefix)
            for prefix in SENSITIVE_REDIRECT_PREFIXES
        ):
            return target
        if normalized.endswith("/.ssh"):
            return target
    return None


def _apply_semantic_effects(
    tokens: list[str],
    risk: str,
    reasons: list[str],
    safer_next_steps: list[str],
    risk_categories: list[str],
) -> tuple[str, bool]:
    evidence = effects_for_tokens(tokens)
    for item in evidence:
        risk = max_risk(risk, item.risk)
        _append_unique(risk_categories, [item.category])
        reason = f"{item.reason} ({item.source})"
        _append_unique(reasons, [reason])
        if item.safer_next_step:
            _append_unique(
                safer_next_steps,
                [item.safer_next_step],
            )
    return risk, bool(evidence)


def _review_segment(
    tokens: list[str],
    rules: list[dict],
    depth: int,
) -> RiskReview:
    text = segment_text(tokens)
    risk = "unknown"
    reasons: list[str] = []
    safer_next_steps: list[str] = []
    matched_rules: list[str] = []
    risk_categories: list[str] = []

    for rule in rules:
        if rule["id"] == "curl_shell" or not _rule_applies(rule, tokens):
            continue
        if re.search(rule["pattern"], text, flags=re.IGNORECASE):
            risk = max_risk(risk, rule["risk"])
            _append_unique(reasons, [rule["reason"]])
            _append_unique(matched_rules, [rule["id"]])
            if rule.get("category"):
                _append_unique(
                    risk_categories,
                    [rule["category"]],
                )
            if rule.get("safer_next_step"):
                _append_unique(
                    safer_next_steps,
                    [rule["safer_next_step"]],
                )

    risk, has_semantic_effects = _apply_semantic_effects(
        tokens,
        risk,
        reasons,
        safer_next_steps,
        risk_categories,
    )

    redirect_target = _sensitive_redirection_target(tokens)
    if redirect_target:
        risk = max_risk(risk, "high")
        _append_unique(
            reasons,
            [
                (
                    "writes shell redirection to sensitive path "
                    f'"{redirect_target}"'
                )
            ],
        )
        _append_unique(
            matched_rules,
            ["sensitive_redirection"],
        )
        _append_unique(
            risk_categories,
            ["sensitive_file_write"],
        )
        _append_unique(
            safer_next_steps,
            [
                (
                    "Write to a non-system path first and inspect the "
                    "result before replacing sensitive files."
                )
            ],
        )

    nested_scripts = grouped_subshells_from_tokens(tokens)
    wrapped_script = shell_script_from_tokens(tokens)
    if wrapped_script is not None:
        nested_scripts.append(wrapped_script)

    for nested_script in nested_scripts:
        if depth >= 3:
            break
        nested = _check_command(
            nested_script,
            rules=rules,
            depth=depth + 1,
        )
        risk = max_risk(risk, nested.risk)
        _append_unique(reasons, nested.reasons)
        _append_unique(
            matched_rules,
            nested.matched_rules or [],
        )
        _append_unique(
            risk_categories,
            nested.risk_categories or [],
        )
        if nested.safer_next_step:
            _append_unique(
                safer_next_steps,
                [nested.safer_next_step],
            )

    pure_group = (
        bool(nested_scripts)
        and tokens[0] == "("
        and tokens[-1] == ")"
    )
    if wrapped_script is None and not pure_group:
        executable = executable_name_from_tokens(tokens)
        if executable:
            command = find_command(executable)
            if command is None:
                _append_unique(
                    reasons,
                    [
                        (
                            f'command "{executable}" is not classified '
                            "by the command graph"
                        )
                    ],
                )
                _append_unique(
                    risk_categories,
                    ["unclassified_command"],
                )
                _append_unique(
                    safer_next_steps,
                    [
                        (
                            "Review the command semantics before execution "
                            "or add a command card for it."
                        )
                    ],
                )
            elif not has_semantic_effects:
                default_risk = command.get(
                    "default_risk",
                    "unknown",
                )
                if default_risk not in RISK_ORDER:
                    default_risk = "unknown"
                risk = max_risk(risk, default_risk)
                if not matched_rules:
                    if default_risk == "unknown":
                        _append_unique(
                            reasons,
                            [
                                (
                                    f'command "{executable}" has no '
                                    "established default risk classification"
                                )
                            ],
                        )
                    else:
                        _append_unique(
                            reasons,
                            [
                                (
                                    "command graph default risk for "
                                    f'"{executable}" is {default_risk}'
                                )
                            ],
                        )
        else:
            _append_unique(
                reasons,
                ["could not identify the command executable"],
            )
            _append_unique(
                risk_categories,
                ["unclassified_command"],
            )

    if not reasons:
        reasons.append("command safety could not be classified")

    return RiskReview(
        decision=decision_for_risk(risk),
        risk=risk,
        reasons=reasons,
        safer_next_step=(
            safer_next_steps[0]
            if safer_next_steps
            else None
        ),
        matched_rules=matched_rules,
        risk_categories=sorted(set(risk_categories)),
    )


def _pipe_findings(
    segments: list[list[str]],
    operators: list[str],
) -> list[RiskReview]:
    findings: list[RiskReview] = []
    for index, operator in enumerate(operators):
        if (
            operator not in {"|", "|&"}
            or index + 1 >= len(segments)
        ):
            continue
        source = executable_name_from_tokens(
            segments[index]
        )
        sink = executable_name_from_tokens(
            segments[index + 1]
        )
        if (
            source in {"curl", "wget"}
            and sink in SHELL_EXECUTABLES
        ):
            findings.append(
                RiskReview(
                    decision="warn",
                    risk="high",
                    reasons=[
                        "downloads and executes remote code"
                    ],
                    safer_next_step=(
                        "Download the script, inspect it, then run "
                        "only if trusted."
                    ),
                    matched_rules=["curl_shell"],
                    risk_categories=[
                        "remote_code_execution"
                    ],
                )
            )
    return findings


def _merge_reviews(
    reviews: list[RiskReview],
) -> RiskReview:
    decision = "allow"
    known_risk = "low"
    has_unknown = False
    reasons: list[str] = []
    matched_rules: list[str] = []
    risk_categories: list[str] = []
    safer_next_step: str | None = None

    for review in reviews:
        if (
            DECISION_ORDER[review.decision]
            > DECISION_ORDER[decision]
        ):
            decision = review.decision
        if review.risk == "unknown":
            has_unknown = True
        else:
            known_risk = max_risk(
                known_risk,
                review.risk,
            )
        _append_unique(reasons, review.reasons)
        _append_unique(
            matched_rules,
            review.matched_rules or [],
        )
        _append_unique(
            risk_categories,
            review.risk_categories or [],
        )
        if (
            safer_next_step is None
            and review.safer_next_step
        ):
            safer_next_step = review.safer_next_step

    risk = (
        "unknown"
        if (
            decision == "ask"
            and has_unknown
            and known_risk == "low"
        )
        else known_risk
    )
    if decision == "block":
        risk = (
            "critical"
            if known_risk == "critical"
            else known_risk
        )

    return RiskReview(
        decision=decision,
        risk=risk,
        reasons=reasons,
        safer_next_step=safer_next_step,
        matched_rules=matched_rules,
        risk_categories=sorted(set(risk_categories)),
    )


def _check_command(
    command: str,
    rules: list[dict],
    depth: int,
) -> RiskReview:
    normalized = command.strip()
    if not normalized:
        return RiskReview(
            decision="block",
            risk="critical",
            reasons=[
                "empty command cannot be reviewed safely"
            ],
            safer_next_step=(
                "Provide the command text before review."
            ),
            matched_rules=["empty_command"],
            risk_categories=["invalid_input"],
        )

    try:
        segments, operators = split_shell_segments(
            normalized
        )
    except ValueError as exc:
        return RiskReview(
            decision="ask",
            risk="unknown",
            reasons=[
                (
                    "shell command could not be parsed safely: "
                    f"{exc}"
                )
            ],
            safer_next_step=(
                "Fix the shell quoting before review."
            ),
            matched_rules=["shell_parse_error"],
            risk_categories=["invalid_input"],
        )

    if not segments:
        return RiskReview(
            decision="ask",
            risk="unknown",
            reasons=[
                (
                    "no executable command segment could be "
                    "identified"
                )
            ],
            safer_next_step=(
                "Provide a complete shell command before review."
            ),
            matched_rules=["missing_executable"],
            risk_categories=["invalid_input"],
        )

    reviews = [
        _review_segment(
            segment,
            rules=rules,
            depth=depth,
        )
        for segment in segments
    ]
    reviews.extend(
        _pipe_findings(segments, operators)
    )
    if depth < 3:
        for nested_script in command_substitutions(
            normalized
        ):
            reviews.append(
                _check_command(
                    nested_script,
                    rules=rules,
                    depth=depth + 1,
                )
            )
    return _merge_reviews(reviews)


def check_command(command: str) -> RiskReview:
    return _check_command(
        command,
        rules=load_risk_rules(),
        depth=0,
    )
