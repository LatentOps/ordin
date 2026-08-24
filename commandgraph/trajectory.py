from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .context import ExecutionContext
from .graph import effects_for_tokens
from .risk import RISK_ORDER, RiskReview, check_command
from .shell import SHELL_EXECUTABLES, executable_name_from_tokens, split_shell_segments
from .trace import ActionTrace


DESTRUCTIVE_EFFECTS = {
    "filesystem.delete",
    "filesystem.recursive_delete",
    "container.delete",
    "container.prune",
    "git.history_rewrite",
    "package.remove",
    "system.configuration_write",
    "system.device_write",
}
DESTRUCTIVE_CATEGORIES = {
    "filesystem_delete",
    "recursive_delete",
    "container_delete",
    "container_cleanup",
    "history_rewrite",
    "package_remove",
    "system_configuration_write",
    "device_write",
}


@dataclass(frozen=True)
class ObservedAction:
    command: str
    effects: frozenset[str]
    categories: frozenset[str]
    risk: str


@dataclass(frozen=True)
class TrajectoryFinding:
    risk: str
    category: str
    reason: str
    safer_next_step: str | None = None


@dataclass(frozen=True)
class TrajectoryEvaluation:
    trace_length: int
    findings: tuple[TrajectoryFinding, ...]

    @property
    def risk(self) -> str | None:
        if not self.findings:
            return None
        return max(
            (finding.risk for finding in self.findings),
            key=lambda value: RISK_ORDER[value],
        )

    @property
    def categories(self) -> list[str]:
        return sorted({finding.category for finding in self.findings})


def _command_effects(command: str) -> frozenset[str]:
    try:
        segments, _ = split_shell_segments(command)
    except ValueError:
        return frozenset()
    effects: set[str] = set()
    for segment in segments:
        effects.update(item.effect for item in effects_for_tokens(segment))
    return frozenset(effects)


def observe_action(
    command: str,
    *,
    context: ExecutionContext | None = None,
    review: RiskReview | None = None,
) -> ObservedAction:
    risk_review = review or check_command(command, context=context)
    return ObservedAction(
        command=command,
        effects=_command_effects(command),
        categories=frozenset(risk_review.risk_categories or []),
        risk=risk_review.risk,
    )


def _looks_like_path_execution(command: str) -> bool:
    try:
        segments, _ = split_shell_segments(command)
    except ValueError:
        return False
    if not segments:
        return False
    tokens = segments[0]
    executable = executable_name_from_tokens(tokens)
    if executable in SHELL_EXECUTABLES and len(tokens) > 1:
        candidate = tokens[-1]
        return candidate.startswith(("./", "../", "/", "~/"))
    if not tokens:
        return False
    candidate = tokens[0]
    return candidate.startswith(("./", "../", "/", "~/"))


def _has_any(values: Iterable[str], candidates: set[str]) -> bool:
    return bool(set(values) & candidates)


def _is_destructive(action: ObservedAction) -> bool:
    return (
        _has_any(action.effects, DESTRUCTIVE_EFFECTS)
        or _has_any(action.categories, DESTRUCTIVE_CATEGORIES)
    )


def evaluate_trajectory(
    trace: ActionTrace | None,
    current_command: str,
    *,
    context: ExecutionContext | None = None,
    current_review: RiskReview | None = None,
) -> TrajectoryEvaluation:
    if trace is None or not trace.actions:
        return TrajectoryEvaluation(trace_length=0, findings=())

    prior = [
        observe_action(action.command, context=context)
        for action in trace.actions
    ]
    current = observe_action(
        current_command,
        context=context,
        review=current_review,
    )
    findings: list[TrajectoryFinding] = []

    prior_secret_read = any(
        "secret.read" in action.effects
        or "secret_exposure" in action.categories
        for action in prior
    )
    current_upload = (
        "network.upload" in current.effects
        or "network_upload" in current.categories
    )
    if prior_secret_read and current_upload:
        findings.append(
            TrajectoryFinding(
                risk="critical",
                category="trajectory_secret_exfiltration",
                reason=(
                    "trajectory reads secret material before an action that can "
                    "upload local data"
                ),
                safer_next_step=(
                    "Do not transmit the data. Confirm the destination and remove "
                    "secret material from the payload first."
                ),
            )
        )

    download_indices = [
        index
        for index, action in enumerate(prior)
        if "network.download" in action.effects
        or "network_download" in action.categories
    ]
    permission_indices = [
        index
        for index, action in enumerate(prior)
        if "filesystem.permission_change" in action.effects
        or "filesystem.recursive_permission_change" in action.effects
        or "permission_change" in action.categories
        or "recursive_permission_change" in action.categories
    ]
    staged_download = any(
        download_index < permission_index
        for download_index in download_indices
        for permission_index in permission_indices
    )
    current_executes_code = (
        "code.execute" in current.effects
        or "code.remote_execute" in current.effects
        or "code_execution" in current.categories
        or "remote_code_execution" in current.categories
        or _looks_like_path_execution(current_command)
    )
    if staged_download and current_executes_code:
        findings.append(
            TrajectoryFinding(
                risk="high",
                category="trajectory_download_execute",
                reason=(
                    "trajectory downloads remote content, makes a target executable, "
                    "then executes local code"
                ),
                safer_next_step=(
                    "Inspect and verify the downloaded artifact before granting "
                    "execute permission or running it."
                ),
            )
        )

    destructive_prior_count = sum(_is_destructive(action) for action in prior)
    if destructive_prior_count >= 2 and _is_destructive(current):
        findings.append(
            TrajectoryFinding(
                risk="high",
                category="trajectory_repeated_destructive_actions",
                reason=(
                    "trajectory contains repeated destructive actions before another "
                    "destructive command"
                ),
                safer_next_step=(
                    "Stop the destructive retry sequence and inspect the current "
                    "state and affected targets before continuing."
                ),
            )
        )

    prior_elevated = sum(
        "privilege.escalate" in action.effects
        or "elevated_privileges" in action.categories
        for action in prior
    )
    current_elevated = (
        "privilege.escalate" in current.effects
        or "elevated_privileges" in current.categories
    )
    if prior_elevated >= 1 and current_elevated:
        findings.append(
            TrajectoryFinding(
                risk="high",
                category="trajectory_repeated_privilege_escalation",
                reason="trajectory repeatedly invokes elevated-privilege actions",
                safer_next_step=(
                    "Confirm why repeated elevation is required and narrow the "
                    "privileged operation before continuing."
                ),
            )
        )

    return TrajectoryEvaluation(
        trace_length=len(trace.actions),
        findings=tuple(findings),
    )
