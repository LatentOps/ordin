"""Bounded, local policy replay. Simulation never installs policy or executes actions."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from functools import cached_property
from time import perf_counter
from typing import Any, Mapping, Sequence, cast

from ordin.action import ActionEnvelope, ActionHistory
from ordin.action_policy import ActionPolicySet
from ordin.agent import AgentDecision, AgentGate
from ordin.api import Ordin
from ordin.context import ExecutionContext
from ordin.execution import ActionObservation
from ordin.mcp_contracts import MCPContractCheck
from ordin.policy import ENFORCEMENT_ORDER, ReviewPolicy
from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.runtime_contract import (
    FilesystemCapability,
    RuntimeCapabilityContract,
    derive_runtime_capability_contract,
)
from ordin.runtime_requirements import RuntimeRequirementProfile
from ordin.session import IntegrationSession, SessionIdentity
from ordin.temporal import TemporalPolicySet
from ordin.tool_calls import ToolSemanticsRegistry
from ordin.trajectory_corpus import AgentTrajectory

from ._json import canonical_json, digest, freeze, thaw, validate
from ._environment import environment_label
from .gate import AssuranceDecision, AssuranceGate, DISPOSITION_ORDER
from .host import HostCapabilityAuthority, HostEvidenceSource, HostRequestAuthority
from .models import (
    ActionKindCoverage,
    ApprovedSecurityProfile,
    LatencyDistribution,
    PolicySimulationReport,
    SimulationCase,
)

POLICY_VERSION = "ordin.assurance_replay_policy.v1"
CORPUS_VERSION = "ordin.assurance_replay_corpus.v1"
CASE_VERSION = "ordin.assurance_replay_case.v1"
MAX_CASES = 256  # Also bounded by the report's one MiB JSON limit.


def _identifier(value: str) -> None:
    validate("assurance_authority_ref", {"authority_id": value, "boundary_digest": "0" * 64})


def _closed(payload: Mapping[str, Any], allowed: set[str]) -> None:
    if not isinstance(payload, Mapping) or set(payload) - allowed:
        raise ValueError("unknown or invalid replay configuration fields")


def _record(value: Any, attr: str) -> dict | None:
    value = getattr(value, attr, value)
    return value.as_dict() if value is not None else None


def _core_packet(core: Ordin) -> dict:
    if type(core) is not Ordin or core.audit is not None or core.trace is not None:
        raise ValueError("simulation requires ordinary Ordin without an audit sink or trace")
    return {
        "fail_on": core.policy.fail_on,
        "context": core.context.as_dict() if core.context else None,
        "action_policy": _record(core.action_policy, "policy"),
        "temporal_policy": _record(core.temporal_policy, "policy"),
        "tool_semantics": _record(core.tool_semantics, "registry"),
        "runtime_requirements": _record(core.runtime_requirements, "profile"),
    }


def _core_from_packet(packet: Mapping[str, Any]) -> Ordin:
    _closed(
        packet,
        {
            "fail_on",
            "context",
            "action_policy",
            "temporal_policy",
            "tool_semantics",
            "runtime_requirements",
        },
    )
    requirements = packet.get("runtime_requirements")
    if requirements is not None:
        _closed(
            requirements,
            {
                "profile_id",
                "filesystem",
                "executable_bindings",
                "spawn_children",
                "client_executables",
                "mcp_endpoints",
                "mcp_versions",
            },
        )
        requirements = RuntimeRequirementProfile(
            profile_id=requirements["profile_id"],
            filesystem=tuple(FilesystemCapability(**v) for v in requirements.get("filesystem", [])),
            executable_bindings=requirements.get("executable_bindings", {}),
            spawn_children=requirements.get("spawn_children"),
            client_executables=tuple(requirements.get("client_executables", [])),
            mcp_endpoints=requirements.get("mcp_endpoints", {}),
            mcp_versions=requirements.get("mcp_versions", {}),
        )
    return Ordin(
        policy=ReviewPolicy(packet.get("fail_on", "warn")),
        context=ExecutionContext.from_dict(packet.get("context")),
        action_policy=ActionPolicySet.from_dict(packet["action_policy"])
        if packet.get("action_policy") is not None
        else None,
        temporal_policy=TemporalPolicySet.from_dict(packet["temporal_policy"])
        if packet.get("temporal_policy") is not None
        else None,
        tool_semantics=ToolSemanticsRegistry.from_dict(packet["tool_semantics"])
        if packet.get("tool_semantics") is not None
        else None,
        runtime_requirements=requirements,
    )


@dataclass(frozen=True)
class SimulationPolicy:
    """Detached review configuration; JSON cannot select an approved profile.

    Boundaries are declared maxima for advisory comparison, not proof that any
    runtime enforces them. Host-only profile handles retain their original seal.
    """

    core: Ordin = field(default_factory=Ordin, repr=False, compare=False)
    approved_profile: ApprovedSecurityProfile | None = None
    require_profile: bool = False
    capability_authorities: tuple[HostCapabilityAuthority, ...] = ()
    request_authorities: tuple[HostRequestAuthority, ...] = ()
    _core: Mapping[str, Any] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.require_profile) is not bool:
            raise ValueError("simulation profile requirement must be boolean")
        if self.approved_profile is not None and not isinstance(
            self.approved_profile, ApprovedSecurityProfile
        ):
            raise ValueError("simulation cannot approve profile content")
        for name, model in (
            ("capability_authorities", HostCapabilityAuthority),
            ("request_authorities", HostRequestAuthority),
        ):
            items = getattr(self, name)
            if (
                not isinstance(items, (list, tuple))
                or len(items) > 128
                or any(type(item) is not model for item in items)
                or len({item.authority_id for item in items}) != len(items)
            ):
                raise ValueError("simulation requires bounded unique typed authority declarations")
            object.__setattr__(self, name, tuple(items))
        packet = freeze(_core_packet(self.core))
        # Store a detached ordinary instance as well as the immutable packet.
        object.__setattr__(self, "core", _core_from_packet(thaw(packet)))
        object.__setattr__(self, "_core", packet)
        canonical_json(self.as_dict())

    def build_gate(self) -> AssuranceGate:
        return AssuranceGate(
            AgentGate(_core_from_packet(thaw(self._core))),
            self.approved_profile,
            require_profile=self.require_profile,
        )

    def as_dict(self) -> dict:
        return {
            "schema_version": POLICY_VERSION,
            "core": thaw(self._core),
            "profile_digest": self.approved_profile.digest if self.approved_profile else None,
            "profile_selection_digest": self.approved_profile.selection_digest
            if self.approved_profile
            else None,
            "require_profile": self.require_profile,
            "capability_authorities": [
                {"authority_id": v.authority_id, "boundary": v.boundary.as_dict()}
                for v in self.capability_authorities
            ],
            "request_authorities": [
                {"authority_id": v.authority_id, "boundary": v.boundary.as_dict()}
                for v in self.request_authorities
            ],
        }

    @cached_property
    def digest(self) -> str:
        return digest("replay_policy", self.as_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SimulationPolicy:
        from ordin.runtime_requests_v2 import RuntimeRequestBoundaryV2

        _closed(
            payload,
            {
                "schema_version",
                "core",
                "profile_digest",
                "profile_selection_digest",
                "require_profile",
                "capability_authorities",
                "request_authorities",
            },
        )
        if payload.get("schema_version") != POLICY_VERSION:
            raise ValueError("unsupported replay policy version")
        if (
            payload.get("profile_digest") is not None
            or payload.get("profile_selection_digest") is not None
        ):
            raise ValueError("JSON cannot activate an approved security profile; use the host API")
        capabilities = payload.get("capability_authorities", [])
        requests = payload.get("request_authorities", [])
        if not isinstance(capabilities, list) or not isinstance(requests, list):
            raise ValueError("authority declarations must be arrays")
        for item in (*capabilities, *requests):
            _closed(item, {"authority_id", "boundary"})
        return cls(
            _core_from_packet(payload.get("core", {})),
            require_profile=payload.get("require_profile", False),
            capability_authorities=tuple(
                HostCapabilityAuthority(
                    v["authority_id"], RuntimeCapabilityBoundary.from_dict(v["boundary"])
                )
                for v in capabilities
            ),
            request_authorities=tuple(
                HostRequestAuthority(
                    v["authority_id"], RuntimeRequestBoundaryV2.from_dict(v["boundary"])
                )
                for v in requests
            ),
        )


@dataclass(frozen=True)
class FrozenCase:
    """One immutable proposal; actions/observations are returned as fresh copies."""

    case_id: str
    action: ActionEnvelope = field(repr=False, compare=False)
    session_id: str = "fixture"
    principal: str = "fixture-agent"
    epoch: int = 0
    expected: str = "escalate"
    label: str = "unknown"
    critical: bool = False
    observation: ActionObservation | None = field(default=None, repr=False, compare=False)
    contract_check: MCPContractCheck | None = field(default=None, repr=False, compare=False)
    initial_history: ActionHistory | None = field(default=None, repr=False, compare=False)
    proof_gaps: tuple[str, ...] = ()
    family: str = "unspecified"
    _packet: Mapping[str, Any] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        for value in (self.case_id, self.session_id, self.principal):
            _identifier(value)
        _identifier(self.family)
        if (
            not isinstance(self.proof_gaps, (list, tuple))
            or len(self.proof_gaps) > 32
            or any(not isinstance(v, str) or not v for v in self.proof_gaps)
        ):
            raise ValueError("invalid fixture proof gaps")
        object.__setattr__(self, "proof_gaps", tuple(self.proof_gaps))
        if type(self.epoch) is not int or not 0 <= self.epoch <= 1_000_000_000:
            raise ValueError("invalid replay epoch")
        if self.expected not in DISPOSITION_ORDER or self.label not in {
            "benign",
            "adversarial",
            "unknown",
        }:
            raise ValueError("invalid replay expectation or label")
        if type(self.critical) is not bool or not isinstance(self.action, ActionEnvelope):
            raise ValueError("replay requires a typed action and boolean critical label")
        if self.initial_history is not None and not isinstance(self.initial_history, ActionHistory):
            raise ValueError("replay history must be typed")
        if self.observation is not None and (
            not isinstance(self.observation, ActionObservation)
            or self.observation.action_id != self.action.action_id
        ):
            raise ValueError("replay observation must match its exact action")
        if self.contract_check is not None and not isinstance(
            self.contract_check, MCPContractCheck
        ):
            raise ValueError("replay contract check must be typed")
        action = self.action.as_dict()
        if not action.get("action_id"):
            action["action_id"] = self.case_id
        packet = freeze(
            {
                "schema_version": CASE_VERSION,
                "case_id": self.case_id,
                "action": action,
                "session_id": self.session_id,
                "principal": self.principal,
                "epoch": self.epoch,
                "expected": self.expected,
                "label": self.label,
                "critical": self.critical,
                "observation": self.observation.as_dict() if self.observation else None,
                "contract_check": self.contract_check.as_dict() if self.contract_check else None,
                "initial_history": self.initial_history.as_dict() if self.initial_history else None,
                "proof_gaps": list(self.proof_gaps),
                "family": self.family,
            }
        )
        object.__setattr__(self, "_packet", packet)
        object.__setattr__(self, "action", ActionEnvelope.from_dict(thaw(packet["action"])))

    def as_dict(self) -> dict:
        return thaw(self._packet)

    @cached_property
    def digest(self) -> str:
        return digest("replay_case", self._packet)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FrozenCase:
        _closed(
            payload,
            {
                "schema_version",
                "case_id",
                "action",
                "session_id",
                "principal",
                "epoch",
                "expected",
                "label",
                "critical",
                "observation",
                "contract_check",
                "initial_history",
                "proof_gaps",
                "family",
            },
        )
        if payload.get("schema_version") != CASE_VERSION:
            raise ValueError("unsupported replay case version")
        return cls(
            case_id=payload["case_id"],
            action=ActionEnvelope.from_dict(payload["action"]),
            session_id=payload.get("session_id", "fixture"),
            principal=payload.get("principal", "fixture-agent"),
            epoch=payload.get("epoch", 0),
            expected=payload.get("expected", "escalate"),
            label=payload.get("label", "unknown"),
            critical=payload.get("critical", False),
            observation=ActionObservation.from_dict(payload["observation"])
            if payload.get("observation") is not None
            else None,
            contract_check=MCPContractCheck.from_dict(payload["contract_check"])
            if payload.get("contract_check") is not None
            else None,
            initial_history=ActionHistory.from_dict(payload["initial_history"])
            if payload.get("initial_history") is not None
            else None,
            proof_gaps=payload.get("proof_gaps", ()),
            family=payload.get("family", "unspecified"),
        )


@dataclass(frozen=True)
class FrozenCorpus:
    cases: tuple[FrozenCase, ...]
    required_case_digests: Mapping[str, str] = field(default_factory=dict)
    source_permissions: str = "unknown"
    declared_complete: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.cases, (list, tuple))
            or not 1 <= len(self.cases) <= MAX_CASES
            or any(not isinstance(v, FrozenCase) for v in self.cases)
        ):
            raise ValueError("corpus requires one to 256 typed cases")
        cases = tuple(self.cases)
        if len({v.case_id for v in cases}) != len(cases):
            raise ValueError("duplicate replay case ID")
        if self.source_permissions not in {
            "synthetic_fixture",
            "authorized_sanitized_replay",
            "unknown",
        }:
            raise ValueError("invalid corpus permission metadata")
        if type(self.declared_complete) is not bool:
            raise ValueError("invalid corpus completeness")
        manifest = freeze(self.required_case_digests)
        if not isinstance(manifest, Mapping) or len(manifest) > MAX_CASES:
            raise ValueError("invalid corpus manifest")
        for key, value in manifest.items():
            validate("assurance_authority_ref", {"authority_id": key, "boundary_digest": value})
        by_id = {v.case_id: v for v in cases}
        if any(key in by_id and by_id[key].digest != value for key, value in manifest.items()):
            raise ValueError("mandatory replay fixture content/version digest mismatch")
        # Reject ambiguous order, repeated proposals, stale epochs and history reseeding.
        seen: dict[tuple[str, str, int], set[str]] = {}
        epochs: dict[tuple[str, str], int] = {}
        for case in cases:
            key = (case.session_id, case.principal, case.epoch)
            identity = key[:2]
            if case.epoch < epochs.get(identity, case.epoch):
                raise ValueError("replay crosses a stale session epoch")
            epochs[identity] = case.epoch
            packet = case.as_dict()
            if key in seen and packet["initial_history"] is not None:
                raise ValueError("initial history may only seed a fresh replay session")
            prior = seen.setdefault(key, set())
            if packet["initial_history"] is not None:
                ids = [v.get("action_id") for v in packet["initial_history"]["actions"]]
                if None in ids or len(set(ids)) != len(ids):
                    raise ValueError("initial replay proposals require unique action IDs")
                prior.update(ids)
            action_id = packet["action"]["action_id"]
            if action_id in prior:
                raise ValueError("duplicate replay proposal ID within a session")
            prior.add(action_id)
        object.__setattr__(self, "cases", cases)
        object.__setattr__(self, "required_case_digests", manifest)
        if len(canonical_json(self.as_dict()).encode("utf-8")) > 1_048_576:
            raise ValueError("corpus byte limit exceeded")

    def as_dict(self) -> dict:
        return {
            "schema_version": CORPUS_VERSION,
            "cases": [v.as_dict() for v in self.cases],
            "required_case_digests": thaw(self.required_case_digests),
            "source_permissions": self.source_permissions,
            "declared_complete": self.declared_complete,
        }

    @cached_property
    def digest(self) -> str:
        return digest("replay_corpus", self.as_dict())

    @classmethod
    def synthetic(cls, cases: Sequence[FrozenCase]) -> FrozenCorpus:
        return cls(tuple(cases), {v.case_id: v.digest for v in cases}, "synthetic_fixture", True)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FrozenCorpus:
        _closed(
            payload,
            {
                "schema_version",
                "cases",
                "required_case_digests",
                "source_permissions",
                "declared_complete",
            },
        )
        if payload.get("schema_version") != CORPUS_VERSION or not isinstance(
            payload.get("cases"), list
        ):
            raise ValueError("unsupported replay corpus version or cases")
        return cls(
            tuple(FrozenCase.from_dict(v) for v in payload["cases"]),
            payload.get("required_case_digests", {}),
            payload.get("source_permissions", "unknown"),
            payload.get("declared_complete", False),
        )


def freeze_trajectory(
    trajectory: AgentTrajectory,
    *,
    label: str = "unknown",
    critical: bool = False,
    principal: str = "fixture-agent",
) -> tuple[FrozenCase, ...]:
    """Adapt existing trajectories without promoting their observations or semantics."""
    if not isinstance(trajectory, AgentTrajectory):
        raise ValueError("trajectory adapter requires an existing parsed trajectory")
    return tuple(
        FrozenCase(
            f"{trajectory.id}:{index}",
            step.action,
            session_id=trajectory.id,
            principal=principal,
            expected={"allow": "execute", "ask": "escalate", "warn": "escalate", "block": "deny"}[
                step.expected
            ],
            label=label,
            critical=critical,
            observation=step.observation,
            contract_check=step.contract_check,
        )
        for index, step in enumerate(trajectory.steps)
    )


def freeze_trace_candidate(
    payload: Mapping[str, Any], *, label: str = "unknown"
) -> tuple[FrozenCase, ...]:
    """Use the existing sanitized trace validator; reconstructed evidence stays synthetic."""
    from ordin.trace_replay import validate_candidate

    return freeze_trajectory(validate_candidate(thaw(freeze(payload))).trajectory, label=label)


def _boundary_contract(boundary: RuntimeCapabilityBoundary) -> RuntimeCapabilityContract:
    return RuntimeCapabilityContract(
        "comparison",
        "0" * 64,
        "allow",
        "low",
        filesystem=boundary.filesystem,
        network=boundary.network,
        tools=boundary.tools,
        process=boundary.process,
        privilege=boundary.privilege,
        credentials=boundary.credentials,
        source={
            "kind": "comparison",
            "operation": "subset",
            "adapter": None,
            "effects": [],
            "provenance_digest": None,
        },
    )


def compare_capability_boundaries(
    old: RuntimeCapabilityBoundary, new: RuntimeCapabilityBoundary
) -> str:
    """Conservative full-domain comparison using the existing subset verifier."""
    if not isinstance(old, RuntimeCapabilityBoundary) or not isinstance(
        new, RuntimeCapabilityBoundary
    ):
        raise ValueError("boundary comparison requires typed maxima")
    if old.as_dict() == new.as_dict():
        return "unchanged"
    if new.allow_any_executable and not old.allow_any_executable:
        return "widened"
    if (old.filesystem_semantics, old.runtime_filesystem_guarantees) != (
        new.filesystem_semantics,
        new.runtime_filesystem_guarantees,
    ) or new.allow_any_executable:
        return "unsupported"
    forward = verify_runtime_capability(_boundary_contract(new), old)
    reverse = verify_runtime_capability(_boundary_contract(old), new)
    if forward.result in {"unsupported", "inconclusive"}:
        return "unsupported"
    if not forward.ok:
        return "widened"
    if old.allow_any_executable and not new.allow_any_executable:
        return "narrowed"
    return "unchanged" if reverse.ok else "narrowed"


def policy_authority_delta(old: SimulationPolicy, new: SimulationPolicy) -> str:
    """Unknown policy algebra is explicit; sampled permits never prove containment."""
    if old.digest == new.digest:
        return "unchanged"
    deltas: list[str] = []
    before = old.as_dict()
    after = new.as_dict()
    old_core, new_core = dict(before["core"]), dict(after["core"])
    old_threshold, new_threshold = old_core.pop("fail_on"), new_core.pop("fail_on")
    if old_core != new_core:
        deltas.append("unknown")
    if old_threshold != new_threshold:
        deltas.append(
            "widened"
            if ENFORCEMENT_ORDER[new_threshold] > ENFORCEMENT_ORDER[old_threshold]
            else "narrowed"
        )
    if before["profile_digest"] != after["profile_digest"]:
        deltas.append("unknown")
    if before["profile_selection_digest"] != after["profile_selection_digest"]:
        deltas.append("unknown")
    if old.require_profile and not new.require_profile:
        deltas.append("widened")
    elif new.require_profile and not old.require_profile:
        deltas.append("narrowed")
    for field_name in ("capability_authorities", "request_authorities"):
        a = {v.authority_id: v for v in getattr(old, field_name)}
        b = {v.authority_id: v for v in getattr(new, field_name)}
        if set(b) - set(a):
            deltas.append("widened")
        if set(a) - set(b):
            deltas.append("narrowed")
        for key in set(a) & set(b):
            if field_name == "capability_authorities":
                deltas.append(compare_capability_boundaries(a[key].boundary, b[key].boundary))
            else:
                # Exact protocol requests and grants are never reduced to transport rights.
                old_request, new_request = a[key].boundary, b[key].boundary
                deltas.append(
                    compare_capability_boundaries(old_request.boundary, new_request.boundary)
                )
                for name in ("requests", "network_grants"):
                    old_items = {canonical_json(v.as_dict()) for v in getattr(old_request, name)}
                    new_items = {canonical_json(v.as_dict()) for v in getattr(new_request, name)}
                    deltas.append(
                        "widened"
                        if new_items - old_items
                        else "narrowed"
                        if old_items - new_items
                        else "unchanged"
                    )
    return next(
        (v for v in ("widened", "unsupported", "unknown", "narrowed") if v in deltas), "unchanged"
    )


@dataclass(frozen=True)
class _TimedGate(AgentGate):
    timings: list[float] = field(default_factory=list, compare=False)

    def evaluate_action(self, action, **kwargs) -> AgentDecision:
        started = perf_counter()
        result = super().evaluate_action(action, **kwargs)
        self.timings.append((perf_counter() - started) * 1000)
        return result


@dataclass(frozen=True)
class _SessionGate(AgentGate):
    assurance: AssuranceGate = field(default_factory=AssuranceGate)
    policy: SimulationPolicy = field(default_factory=SimulationPolicy)
    case: FrozenCase | None = None
    captured: list[AssuranceDecision] = field(default_factory=list, compare=False)

    def evaluate_action(self, action, **kwargs) -> AgentDecision:
        host = None
        profile = self.policy.approved_profile
        if profile is not None:
            assert self.case is not None
            if profile.runtime_policy_digest is None:
                raise ValueError("simulation profile lacks a bound runtime policy")
            source = HostEvidenceSource(
                self.case.principal,
                profile.profile.repository,
                digest(
                    "replay_session", [self.case.session_id, self.case.principal, self.case.epoch]
                ),
                self.case.epoch,
                profile.runtime_policy_digest,
                profile.selection_digest,
            )
            host = source.context(
                capability_authorities=self.policy.capability_authorities,
                request_authorities=self.policy.request_authorities,
                history=kwargs.get("history"),
            )
        result = self.assurance.evaluate_action(action, host_context=host, **kwargs)
        self.captured.append(result)
        return AgentDecision(result.disposition, result.review)


def _run_arm(
    policy: SimulationPolicy, corpus: FrozenCorpus
) -> tuple[list[tuple[AssuranceDecision, float, float]], set[str]]:
    sessions: dict[tuple[str, str, int], IntegrationSession] = {}
    outcomes: list[tuple[AssuranceDecision, float, float]] = []
    gaps: set[str] = set()
    for case in corpus.cases:
        packet = case.as_dict()
        key = (case.session_id, case.principal, case.epoch)
        if key not in sessions:
            ordinary = policy.build_gate()
            assurance = AssuranceGate(
                _TimedGate(ordinary.ordin),
                policy.approved_profile,
                require_profile=policy.require_profile,
            )
            proxy = _SessionGate(assurance.ordin, assurance, policy, case)
            sessions[key] = IntegrationSession(
                SessionIdentity("assurance-replay", canonical_json(key)), proxy
            )
            if packet["initial_history"] is not None:
                # Replay prior proposals too; retaining rejected proposals is core session behavior.
                history = ActionHistory.from_dict(packet["initial_history"])
                for prior in history.actions:
                    sessions[key].evaluate(prior, approval_supported=False)
                proxy.captured.clear()
                timed_gate = assurance.baseline_gate
                assert isinstance(timed_gate, _TimedGate)
                timed_gate.timings.clear()
        session = sessions[key]
        proxy = cast(_SessionGate, session.gate)
        assert isinstance(proxy, _SessionGate)
        object.__setattr__(proxy, "case", case)
        started = perf_counter()
        session.evaluate(
            ActionEnvelope.from_dict(packet["action"]),
            contract_check=MCPContractCheck.from_dict(packet["contract_check"])
            if packet["contract_check"] is not None
            else None,
            approval_supported=False,
        )
        elapsed = (perf_counter() - started) * 1000
        decision = proxy.captured.pop()
        if case.proof_gaps:
            gaps.add(case.case_id)
        assert isinstance(proxy.assurance.baseline_gate, _TimedGate)
        core_ms = proxy.assurance.baseline_gate.timings.pop()
        outcomes.append((decision, elapsed, core_ms))
        if packet["observation"] is not None:
            if decision.may_execute:
                session.observe(ActionObservation.from_dict(packet["observation"]))
            else:
                gaps.add(case.case_id)
        if any(
            v.status in {"inconclusive", "unsupported"} for v in decision.invariant_evaluations
        ) or any(
            v in decision.reason_codes
            for v in (
                "assurance.required_profile_missing",
                "assurance.host_context_untrusted",
                "assurance.required_profile_changed",
            )
        ):
            gaps.add(case.case_id)
        if not decision.denied and (
            decision.review.risk == "unknown" or decision.review.adapter is None
        ):
            gaps.add(case.case_id)
    return outcomes, gaps


def _latency(values: Sequence[float]) -> LatencyDistribution:
    ordered = sorted(values)

    def percentile(p: float) -> float:
        return round(ordered[max(0, math.ceil(len(ordered) * p) - 1)], 6)

    return LatencyDistribution(percentile(0.50), percentile(0.95), percentile(0.99), len(values))


def simulate_policy_change(
    old_policy: SimulationPolicy,
    proposed_policy: SimulationPolicy,
    frozen_cases: FrozenCorpus,
    *,
    baseline_revision: str,
    candidate_revision: str,
    expected_corpus_digest: str | None = None,
    environment: str | None = None,
) -> PolicySimulationReport:
    """Read-only independent replay; activation_safe is an advisory guard result.

    Corpus permissions and expectations are caller claims. No approvals, causal
    assessments, runtime observations, credentials or grants are minted by replay.
    """
    if (
        not isinstance(old_policy, SimulationPolicy)
        or not isinstance(proposed_policy, SimulationPolicy)
        or not isinstance(frozen_cases, FrozenCorpus)
    ):
        raise ValueError("simulation requires frozen typed policies and corpus")
    if expected_corpus_digest is not None and frozen_cases.digest != expected_corpus_digest:
        raise ValueError("frozen corpus digest mismatch")
    for revision in (baseline_revision, candidate_revision):
        _identifier(revision)
    baseline, old_gaps = _run_arm(old_policy, frozen_cases)
    candidate, new_gaps = _run_arm(proposed_policy, frozen_cases)
    delta = policy_authority_delta(old_policy, proposed_policy)
    rows: list[SimulationCase] = []
    for case, (old, old_ms, old_core_ms), (new, new_ms, new_core_ms) in zip(
        frozen_cases.cases, baseline, candidate
    ):
        assessable = case.case_id not in old_gaps | new_gaps and case.label != "unknown"
        change = "unchanged"
        if new.disposition != old.disposition:
            change = {
                "execute": "newly_executable",
                "escalate": "newly_escalated",
                "deny": "newly_denied",
            }[new.disposition]
        elif not assessable:
            change = "unassessable"
        old_contract = derive_runtime_capability_contract(old.review)
        new_contract = derive_runtime_capability_contract(new.review)
        reasons = list(dict.fromkeys((*old.reason_codes, *new.reason_codes)))
        if not assessable:
            reasons.append("assurance.simulation_evidence_gap")
        if (
            case.critical
            and DISPOSITION_ORDER[new.disposition] < DISPOSITION_ORDER[old.disposition]
        ):
            reasons.append("assurance.simulation_critical_downgrade")
        if old.disposition == "escalate" and new.disposition == "execute":
            reasons.append("assurance.simulation_approval_removed")
        rows.append(
            SimulationCase(
                case.case_id,
                digest("replay_action", case.as_dict()["action"]),
                old.baseline.disposition,
                new.baseline.disposition,
                old.disposition,
                new.disposition,
                change,
                reason_codes=tuple(reasons),
                authority_delta=delta,
                label=case.label,
                baseline_ms=round(old_ms, 6),
                candidate_ms=round(new_ms, 6),
                baseline_core_ms=round(old_core_ms, 6),
                candidate_core_ms=round(new_core_ms, 6),
                baseline_wrapper_ms=round(max(0, old_ms - old_core_ms), 6),
                candidate_wrapper_ms=round(max(0, new_ms - new_core_ms), 6),
                expected=case.expected,
                critical=case.critical,
                action_kind=case.as_dict()["action"]["kind"],
                assessable=assessable,
                baseline_effects=tuple(sorted(old.review.effects)),
                candidate_effects=tuple(sorted(new.review.effects)),
                baseline_temporal=tuple(sorted(old.review.trajectory_categories)),
                candidate_temporal=tuple(sorted(new.review.trajectory_categories)),
                baseline_capability_digest=old_contract.digest,
                candidate_capability_digest=new_contract.digest,
            )
        )
    ids = {v.case_id for v in frozen_cases.cases}
    missing = tuple(sorted(set(frozen_cases.required_case_digests) - ids))
    gaps = tuple(v.case_id for v in rows if not v.assessable or v.label == "unknown")
    complete = (
        frozen_cases.declared_complete
        and bool(frozen_cases.required_case_digests)
        and not missing
        and not gaps
        and frozen_cases.source_permissions != "unknown"
        and baseline_revision not in {"unspecified", "unknown"}
        and candidate_revision not in {"unspecified", "unknown"}
    )
    misses = sum(
        v.critical and DISPOSITION_ORDER[v.candidate_final] < DISPOSITION_ORDER[v.expected]
        for v in rows
    )
    regressions = any(
        v.change == "newly_executable"
        or "assurance.simulation_critical_downgrade" in v.reason_codes
        for v in rows
    )
    safe = complete and not misses and not regressions and delta in {"unchanged", "narrowed"}
    limitations = [
        "Advisory fixture replay only; no policy installation, runtime enforcement or action execution.",
        "Imported observations remain caller-asserted; replay authenticates no human approval or backend evidence.",
        "Latency covers local replay only; no optional scanner or model was invoked.",
    ]
    if delta in {"unknown", "unsupported"}:
        limitations.append(
            "Changed policy authority cannot be proven contained by supported comparison."
        )
    if old_gaps | new_gaps:
        limitations.append(
            "Some fixtures require unavailable evidence or an observation after a refused proposal."
        )
    if baseline_revision in {"unspecified", "unknown"} or candidate_revision in {
        "unspecified",
        "unknown",
    }:
        limitations.append("Source revision was not supplied for one or both replay arms.")
    kinds = sorted({v.action_kind for v in rows})
    coverage_by_kind = tuple(
        ActionKindCoverage(
            kind,
            sum(v.action_kind == kind for v in rows),
            sum(v.action_kind == kind and v.assessable for v in rows),
            sum(v.action_kind == kind and not v.assessable for v in rows),
        )
        for kind in kinds
    )
    return PolicySimulationReport(
        "simulation:"
        + digest(
            "simulation_identity",
            [
                old_policy.digest,
                proposed_policy.digest,
                frozen_cases.digest,
                baseline_revision,
                candidate_revision,
            ],
        )[:24],
        frozen_cases.digest,
        baseline_revision,
        candidate_revision,
        old_policy.digest,
        proposed_policy.digest,
        _latency([v[1] for v in baseline]),
        _latency([v[1] for v in candidate]),
        environment or environment_label(),
        cases=tuple(rows),
        critical_misses=misses,
        benign_false_escalations=sum(
            v.label == "benign" and v.expected == "execute" and v.candidate_final == "escalate"
            for v in rows
        ),
        benign_false_denials=sum(
            v.label == "benign" and v.expected == "execute" and v.candidate_final == "deny"
            for v in rows
        ),
        coverage="complete" if complete else "partial",
        activation_safe=safe,
        limitations=tuple(limitations),
        newly_denied=tuple(v.case_id for v in rows if v.change == "newly_denied"),
        newly_escalated=tuple(v.case_id for v in rows if v.change == "newly_escalated"),
        newly_executable=tuple(v.case_id for v in rows if v.change == "newly_executable"),
        unassessable=gaps,
        missing_required_cases=missing,
        policy_authority_delta=delta,
        source_permissions=frozen_cases.source_permissions,
        old_profile_digest=old_policy.approved_profile.digest
        if old_policy.approved_profile
        else None,
        new_profile_digest=proposed_policy.approved_profile.digest
        if proposed_policy.approved_profile
        else None,
        old_profile_selection_digest=old_policy.approved_profile.selection_digest
        if old_policy.approved_profile
        else None,
        new_profile_selection_digest=proposed_policy.approved_profile.selection_digest
        if proposed_policy.approved_profile
        else None,
        critical_caught=sum(
            v.critical
            and v.assessable
            and DISPOSITION_ORDER[v.candidate_final] >= DISPOSITION_ORDER[v.expected]
            for v in rows
        ),
        coverage_by_kind=coverage_by_kind,
    )
