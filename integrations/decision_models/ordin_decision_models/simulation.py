"""Independent, read-only semantic-policy replay over owned synthetic fixtures.

The only provider selectable by this fixture driver is the project's offline
mock. JSON, fixture text and expected labels cannot choose a callable, executable,
checkpoint or endpoint. No fixture action is executed or runtime grant issued.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from time import perf_counter
from typing import Mapping, cast

from ordin import ActionEnvelope, ActionHistory, AgentDecision, AgentGate
from ordin.agent import AgentDisposition
from ordin.assurance import AssuranceGate, HostEvidenceSource, RepositoryScope
from ordin.assurance._json import digest, freeze
from ordin.assurance.gate import DISPOSITION_ORDER
from ordin.assurance.models import JsonRecord, LatencyDistribution, PolicySimulationReport
from ordin.assurance.origins import correlate_source_use, register_instruction_origin
from ordin.assurance.simulation import (
    FrozenCase,
    FrozenCorpus,
    SimulationPolicy,
    _latency,
    simulate_policy_change,
)
from ordin.execution import ActionObservation
from ordin.mcp_contracts import MCPContractCheck
from ordin.runtime_contract import derive_runtime_capability_contract
from ordin.session import IntegrationSession, SessionIdentity

from .fusion import SemanticDecision
from .mock import MockDecisionModel
from .privacy import SelectedSnippet, request_semantic_inspection, sanitize_decision_state
from .routing import RoutingPolicy, SemanticInspectionRouter


@dataclass(frozen=True)
class SemanticReplayPolicy:
    """Explicit local fixture configuration; tasks are synthetic context only."""

    deterministic: SimulationPolicy = field(default_factory=SimulationPolicy)
    routing: RoutingPolicy = field(default_factory=RoutingPolicy)
    tasks: Mapping[str, str] = field(default_factory=dict, repr=False)
    answers: Mapping[str, float] = field(default_factory=dict)
    provider_available: bool = True
    behavior: str = "normal"
    delay_ms: int = 0

    def __post_init__(self):
        if (
            type(self.deterministic) is not SimulationPolicy
            or type(self.routing) is not RoutingPolicy
            or type(self.provider_available) is not bool
        ):
            raise ValueError("semantic replay requires typed detached fixture policies")
        tasks = freeze(self.tasks)
        answers = freeze(self.answers)
        if not isinstance(tasks, Mapping) or any(
            not isinstance(task, str) or not 1 <= len(task) <= 2048 for task in tasks.values()
        ):
            raise ValueError("synthetic task selections must be bounded text")
        if not isinstance(answers, Mapping):
            raise ValueError("mock predictions must be a mapping")
        from .protocol import QUESTION_IDS
        from ordin.assurance.models import ModelAnswer

        if set(answers) - set(QUESTION_IDS):
            raise ValueError("unknown synthetic question selection")
        for key, value in answers.items():
            ModelAnswer(key, value)
        MockDecisionModel(answers, behavior=self.behavior, delay_ms=self.delay_ms)
        object.__setattr__(self, "tasks", tasks)
        object.__setattr__(self, "answers", answers)

    def as_dict(self):
        return {
            "deterministic_digest": self.deterministic.digest,
            "routing_digest": self.routing.digest,
            "task_selection_digest": digest("synthetic_replay_tasks", self.tasks),
            "mock_descriptor_digest": MockDecisionModel(
                self.answers, behavior=self.behavior, delay_ms=self.delay_ms
            ).descriptor.digest,
            "provider_available": self.provider_available,
        }

    @property
    def digest(self):
        return digest("semantic_replay_policy", self.as_dict())


@dataclass(frozen=True)
class SemanticPolicySimulationReport(JsonRecord):
    """Advisory data; decoding does not reconstruct protected runtime evidence."""

    SCHEMA = "assurance_semantic_simulation"
    NESTED = {
        "simulation": PolicySimulationReport,
        "baseline_model_latency": LatencyDistribution,
        "candidate_model_latency": LatencyDistribution,
    }
    simulation: PolicySimulationReport
    baseline_configuration_digest: str
    candidate_configuration_digest: str
    baseline_model_latency: LatencyDistribution
    candidate_model_latency: LatencyDistribution
    baseline_model_calls: int
    candidate_model_calls: int
    synthetic_only: bool = True
    model_locality: str = "mock"
    actions_executed: bool = False

    def __post_init__(self):
        super().__post_init__()
        if (
            self.baseline_configuration_digest != self.simulation.old_policy_digest
            or self.candidate_configuration_digest != self.simulation.new_policy_digest
            or self.baseline_model_latency.samples > self.baseline_model_calls
            or self.candidate_model_latency.samples > self.candidate_model_calls
        ):
            raise ValueError("semantic report configuration and inference counts are inconsistent")


def _model_latency(values):
    return _latency(values) if values else LatencyDistribution(0, 0, 0, 0)


@dataclass(frozen=True)
class _TimedCore(AgentGate):
    timings: list[float] = field(default_factory=list, compare=False)

    def evaluate_action(self, action, **kwargs):
        started = perf_counter()
        result = super().evaluate_action(action, **kwargs)
        self.timings.append((perf_counter() - started) * 1000)
        return result


@dataclass(frozen=True)
class _SessionGate(AgentGate):
    router: SemanticInspectionRouter | None = None
    selection: SemanticReplayPolicy | None = None
    source: HostEvidenceSource | None = None
    case: FrozenCase | None = None
    captured: list[SemanticDecision] = field(default_factory=list, compare=False)

    def evaluate_action(self, action, **kwargs):
        assert self.router is not None and self.source is not None and self.selection is not None
        policy = self.selection.deterministic
        host = self.source.context(
            capability_authorities=policy.capability_authorities,
            request_authorities=policy.request_authorities,
            history=kwargs.get("history"),
        )
        state = None
        task = self.selection.tasks.get(self.case.case_id) if self.case is not None else None
        # Required context remains missing for unsupported kinds and history seeds.
        if (
            task is not None
            and action.kind == "shell"
            and isinstance(action.parameters.get("command"), str)
            and self.router.policy.mode != "disabled"
        ):
            baseline = self.router.gate.evaluate_action(action, host_context=host, **kwargs)
            if not baseline.denied:
                command = action.parameters["command"]
                task_origin = register_instruction_origin(
                    self.source,
                    origin_id="synthetic-task",
                    kind="authorized_user",
                    classification="public",
                    content=task,
                )
                origin = register_instruction_origin(
                    self.source,
                    origin_id="synthetic-proposal",
                    kind="repository_file",
                    classification="public",
                    content=command,
                )
                use = correlate_source_use(
                    self.source,
                    origin,
                    action,
                    use_id="synthetic-use",
                    argument_path=("parameters", "command"),
                    usage="instruction_context",
                )
                state = sanitize_decision_state(
                    self.router.gate,
                    baseline,
                    host_context=host,
                    history=kwargs.get("history"),
                    task_origin=task_origin,
                    task_text=task,
                    snippets=(SelectedSnippet(origin, use, command),),
                    inspection=request_semantic_inspection(
                        self.source, action, reasons=("ambiguous_task_alignment",)
                    ),
                )
        result = self.router.evaluate_action(action, state=state, host_context=host, **kwargs)
        self.captured.append(result)
        return AgentDecision(cast(AgentDisposition, result.disposition), result.review)


def _arm(selection, corpus, revision):
    ordinary = selection.deterministic.build_gate()
    timed = _TimedCore(ordinary.ordin)
    gate = AssuranceGate(
        timed,
        ordinary.approved_profile,
        require_profile=ordinary.require_profile,
    )
    provider = (
        MockDecisionModel(
            selection.answers, behavior=selection.behavior, delay_ms=selection.delay_ms
        )
        if selection.provider_available
        else None
    )
    router = SemanticInspectionRouter(gate, policy=selection.routing, provider=provider)
    sessions = {}
    samples = []
    gaps = set()
    model_times: list[float] = []
    for case in corpus.cases:
        key = (case.session_id, case.principal, case.epoch)
        if key not in sessions:
            profile = selection.deterministic.approved_profile
            source = HostEvidenceSource(
                case.principal,
                profile.profile.repository
                if profile
                else RepositoryScope("fixture/semantic-replay", revision),
                digest("semantic_replay_session", key),
                case.epoch,
                profile.runtime_policy_digest if profile else selection.deterministic.digest,
                profile.selection_digest if profile else selection.digest,
            )
            proxy = _SessionGate(gate.ordin, router, selection, source)
            session = IntegrationSession(
                SessionIdentity("semantic-replay", digest("session", key)), proxy
            )
            sessions[key] = session, proxy
            packet = case.as_dict()
            if packet["initial_history"] is not None:
                for prior in ActionHistory.from_dict(packet["initial_history"]).actions:
                    session.evaluate(prior, approval_supported=False)
                model_times.extend(
                    result.model_evidence.latency_ms if result.model_evidence else 0
                    for result in proxy.captured
                    if result.model_invoked
                )
                proxy.captured.clear()
                timed.timings.clear()
        session, proxy = sessions[key]
        object.__setattr__(proxy, "case", case)
        packet = case.as_dict()
        started = perf_counter()
        session.evaluate(
            ActionEnvelope.from_dict(packet["action"]),
            contract_check=MCPContractCheck.from_dict(packet["contract_check"])
            if packet["contract_check"] is not None
            else None,
            approval_supported=False,
        )
        elapsed = (perf_counter() - started) * 1000
        result = proxy.captured.pop()
        samples.append((result, elapsed, sum(timed.timings)))
        timed.timings.clear()
        if result.model_invoked:
            model_times.append(result.model_evidence.latency_ms if result.model_evidence else 0)
        if result.mode != "disabled" and not result.denied:
            if (
                result.uncertain_question_ids
                or any(
                    reason in result.reason_codes
                    for reason in (
                        "semantic.provider_unavailable",
                        "semantic.required_context_missing",
                        "semantic.call_budget_exceeded",
                        "semantic.configuration_changed",
                    )
                )
                or (
                    result.model_evidence is not None
                    and result.model_evidence.supportedness != "supported"
                )
            ):
                gaps.add(case.case_id)
        if packet["observation"] is not None:
            if result.may_execute:
                session.observe(ActionObservation.from_dict(packet["observation"]))
            else:
                gaps.add(case.case_id)
    return samples, gaps, model_times, router.budget_snapshot()["calls"]


def simulate_semantic_policy_change(
    baseline: SemanticReplayPolicy,
    candidate: SemanticReplayPolicy,
    corpus: FrozenCorpus,
    *,
    baseline_revision: str,
    candidate_revision: str,
    expected_corpus_digest: str | None = None,
) -> SemanticPolicySimulationReport:
    """Replay real routing/fusion; preserve separate sessions, unknowns and budgets."""
    if type(baseline) is not SemanticReplayPolicy or type(candidate) is not SemanticReplayPolicy:
        raise ValueError("semantic replay requires typed fixture selections")
    if type(corpus) is not FrozenCorpus or corpus.source_permissions != "synthetic_fixture":
        raise ValueError("semantic replay only accepts explicitly owned synthetic fixtures")
    ids = {case.case_id for case in corpus.cases}
    if (set(baseline.tasks) | set(candidate.tasks)) - ids:
        raise ValueError("semantic task selection contains an absent case")
    report = simulate_policy_change(
        baseline.deterministic,
        candidate.deterministic,
        corpus,
        baseline_revision=baseline_revision,
        candidate_revision=candidate_revision,
        expected_corpus_digest=expected_corpus_digest,
    )
    old, old_gaps, old_times, old_calls = _arm(baseline, corpus, baseline_revision)
    new, new_gaps, new_times, new_calls = _arm(candidate, corpus, candidate_revision)
    delta = report.policy_authority_delta
    old_enforced = baseline.routing.mode == "enforced-escalation"
    new_enforced = candidate.routing.mode == "enforced-escalation"
    before_selection, after_selection = baseline.as_dict(), candidate.as_dict()
    before_selection.pop("deterministic_digest")
    after_selection.pop("deterministic_digest")
    semantic_delta = (
        "widened"
        if old_enforced and not new_enforced
        else "narrowed"
        if new_enforced and not old_enforced
        else "unknown"
        if old_enforced and before_selection != after_selection
        else "unchanged"
    )
    delta = next(
        (
            value
            for value in ("widened", "unsupported", "unknown", "narrowed")
            if value in {delta, semantic_delta}
        ),
        "unchanged",
    )
    gaps = set(report.unassessable) | old_gaps | new_gaps
    rows = []
    for row, before, after in zip(report.cases, old, new):
        old_result, old_ms, old_core = before
        new_result, new_ms, new_core = after
        change = (
            {"execute": "newly_executable", "escalate": "newly_escalated", "deny": "newly_denied"}[
                new_result.disposition
            ]
            if old_result.disposition != new_result.disposition
            else "unassessable"
            if row.case_id in gaps
            else "unchanged"
        )
        reasons = list(
            dict.fromkeys((*row.reason_codes, *old_result.reason_codes, *new_result.reason_codes))
        )
        if row.case_id in gaps:
            reasons.append("assurance.simulation_evidence_gap")
        if (
            row.critical
            and DISPOSITION_ORDER[new_result.disposition]
            < DISPOSITION_ORDER[old_result.disposition]
        ):
            reasons.append("assurance.simulation_critical_downgrade")
        if old_result.requires_approval and new_result.may_execute:
            reasons.append("assurance.simulation_approval_removed")
        rows.append(
            replace(
                row,
                baseline_core=old_result._baseline.baseline.disposition,
                candidate_core=new_result._baseline.baseline.disposition,
                baseline_final=old_result.disposition,
                candidate_final=new_result.disposition,
                change=change,
                reason_codes=tuple(dict.fromkeys(reasons)),
                authority_delta=delta,
                assessable=row.case_id not in gaps,
                baseline_ms=round(old_ms, 6),
                candidate_ms=round(new_ms, 6),
                baseline_core_ms=round(old_core, 6),
                candidate_core_ms=round(new_core, 6),
                baseline_wrapper_ms=round(max(0, old_ms - old_core), 6),
                candidate_wrapper_ms=round(max(0, new_ms - new_core), 6),
                baseline_effects=tuple(sorted(old_result.review.effects)),
                candidate_effects=tuple(sorted(new_result.review.effects)),
                baseline_temporal=tuple(sorted(old_result.review.trajectory_categories)),
                candidate_temporal=tuple(sorted(new_result.review.trajectory_categories)),
                baseline_capability_digest=derive_runtime_capability_contract(
                    old_result.review
                ).digest,
                candidate_capability_digest=derive_runtime_capability_contract(
                    new_result.review
                ).digest,
            )
        )
    complete = report.coverage == "complete" and not gaps
    misses = sum(
        row.critical and DISPOSITION_ORDER[row.candidate_final] < DISPOSITION_ORDER[row.expected]
        for row in rows
    )
    regressions = any(
        row.change == "newly_executable"
        or "assurance.simulation_critical_downgrade" in row.reason_codes
        for row in rows
    )
    limitations = tuple(
        value for value in report.limitations if "no optional scanner or model" not in value
    ) + (
        "Owned synthetic context and project mock predictions only; no real provider effectiveness or host authorization is claimed.",
        "Model latency is the mock's recorded inference duration; wrapper latency includes routing, sanitization and waits. Timeout evidence may have no inference duration.",
        "A changed enforced semantic configuration has unproved containment unless enforcement is only added; disabling enforcement widens the scrutiny boundary.",
    )
    report = replace(
        report,
        report_id="semantic-simulation:"
        + digest("semantic_simulation", [report.report_id, baseline.digest, candidate.digest])[:24],
        cases=tuple(rows),
        old_policy_digest=baseline.digest,
        new_policy_digest=candidate.digest,
        baseline_latency=_latency([value[1] for value in old]),
        candidate_latency=_latency([value[1] for value in new]),
        coverage="complete" if complete else "partial",
        activation_safe=complete
        and not misses
        and not regressions
        and delta in {"unchanged", "narrowed"},
        policy_authority_delta=delta,
        unassessable=tuple(row.case_id for row in rows if not row.assessable),
        newly_denied=tuple(row.case_id for row in rows if row.change == "newly_denied"),
        newly_escalated=tuple(row.case_id for row in rows if row.change == "newly_escalated"),
        newly_executable=tuple(row.case_id for row in rows if row.change == "newly_executable"),
        critical_misses=misses,
        critical_caught=sum(
            row.critical
            and row.assessable
            and DISPOSITION_ORDER[row.candidate_final] >= DISPOSITION_ORDER[row.expected]
            for row in rows
        ),
        benign_false_escalations=sum(
            row.label == "benign"
            and row.expected == "execute"
            and row.candidate_final == "escalate"
            for row in rows
        ),
        benign_false_denials=sum(
            row.label == "benign" and row.expected == "execute" and row.candidate_final == "deny"
            for row in rows
        ),
        coverage_by_kind=tuple(
            replace(
                kind,
                assessable=sum(
                    row.action_kind == kind.action_kind and row.assessable for row in rows
                ),
                unresolved=sum(
                    row.action_kind == kind.action_kind and not row.assessable for row in rows
                ),
            )
            for kind in report.coverage_by_kind
        ),
        limitations=limitations,
    )
    return SemanticPolicySimulationReport(
        report,
        baseline.digest,
        candidate.digest,
        _model_latency(old_times),
        _model_latency(new_times),
        old_calls,
        new_calls,
    )
