"""Immutable Assurance records. Ordinary decoding never activates authority.

These artifacts describe evidence and proposals. Host-only trust/approval
constructors are separate from JSON parsing, as in RuntimeEvidenceSource.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from functools import cached_property
from typing import Any, ClassVar, Mapping, TypeVar

from ._json import digest, freeze, loads, thaw, validate
from ._schemas import SCHEMAS

T = TypeVar("T", bound="JsonRecord")


@dataclass(frozen=True)
class JsonRecord:
    SCHEMA: ClassVar[str]
    NESTED: ClassVar[dict[str, type[JsonRecord]]] = {}
    MANY: ClassVar[dict[str, type[JsonRecord]]] = {}

    def __post_init__(self) -> None:
        for member in fields(self):
            name = member.name
            if name.startswith("_"):
                continue
            value = getattr(self, name)
            if name in self.NESTED:
                if value is not None and not isinstance(value, self.NESTED[name]):
                    raise ValueError(f"{self.SCHEMA} requires typed nested records")
            elif name in self.MANY:
                if (
                    not isinstance(value, (tuple, list))
                    or len(value) > 4096
                    or any(not isinstance(child, self.MANY[name]) for child in value)
                ):
                    raise ValueError(f"{self.SCHEMA} requires typed record collections")
                object.__setattr__(self, name, tuple(value))
            else:
                object.__setattr__(self, name, freeze(value))
        validate(self.SCHEMA, self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        def plain(value: Any) -> Any:
            if isinstance(value, JsonRecord):
                return value.as_dict()
            if isinstance(value, tuple):
                return [plain(child) for child in value]
            return thaw(value)

        payload = {
            member.name: plain(getattr(self, member.name))
            for member in fields(self)
            if not member.name.startswith("_")
        }
        if self.SCHEMA in SCHEMAS:
            payload = {"schema_version": f"ordin.{self.SCHEMA}.v1", **payload}
        return payload

    @classmethod
    def from_dict(cls: type[T], payload: Mapping[str, Any]) -> T:
        validate(cls.SCHEMA, payload)
        arguments = dict(payload)
        arguments.pop("schema_version", None)
        for name, model in cls.NESTED.items():
            if arguments[name] is not None:
                arguments[name] = model.from_dict(arguments[name])
        for name, model in cls.MANY.items():
            arguments[name] = tuple(model.from_dict(child) for child in arguments[name])
        return cls(**arguments)

    @classmethod
    def from_json(cls: type[T], data: str | bytes) -> T:
        return cls.from_dict(loads(data))

    @cached_property
    def digest(self) -> str:
        return digest(self.SCHEMA, self.as_dict())


@dataclass(frozen=True)
class RepositoryScope(JsonRecord):
    SCHEMA = "repository_scope"
    id: str
    revision: str


@dataclass(frozen=True)
class SourceReference(JsonRecord):
    SCHEMA = "source_reference"
    path: str
    line: int
    revision: str
    content_digest: str
    symbol: str | None = None


@dataclass(frozen=True)
class ProtectedAsset(JsonRecord):
    SCHEMA = "protected_asset"
    id: str
    kind: str
    value: str
    match: str = "exact"

    def __post_init__(self) -> None:
        super().__post_init__()
        from ordin.runtime_contract import _safe_path
        from ordin.runtime_requests import request_endpoint

        if self.kind in {"path", "policy"} and not _safe_path(self.value):
            raise ValueError("protected path must have supported absolute lexical syntax")
        if self.kind == "endpoint" and request_endpoint(self.value) is None:
            raise ValueError("protected endpoint must have supported request syntax")
        if self.match == "prefix" and self.kind not in {"path", "policy"}:
            raise ValueError("protected prefix matching supports paths only")
        if self.kind in {"tool", "credential"}:
            validate("repository_scope", {"id": self.value, "revision": "opaque-reference"})


@dataclass(frozen=True)
class TrustBoundary(JsonRecord):
    SCHEMA = "trust_boundary"
    id: str
    source: str
    sink: str


_STRONG_ORIGINS = {
    "deterministically_derived",
    "policy_verified",
    "runtime_backend_observed",
    "host_authenticated_source",
}


@dataclass(frozen=True)
class _EvidenceAuthority:
    payload_digest: str


@dataclass(frozen=True)
class EvidenceLink(JsonRecord):
    SCHEMA = "evidence_link"
    NESTED = {"source": SourceReference}
    evidence_id: str
    origin: str
    source: SourceReference | None = None
    action_digest: str | None = None
    contract_id: str | None = None
    session_digest: str | None = None
    proof_gaps: tuple[str, ...] = ()
    _authority: _EvidenceAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.origin in _STRONG_ORIGINS and (
            not isinstance(self._authority, _EvidenceAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("assurance evidence requires an authenticated host source")


@dataclass(frozen=True)
class InvariantSelectors(JsonRecord):
    SCHEMA = "invariant_selectors"
    kinds: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()
    resource_ref: str | None = None
    principal: str | None = None


@dataclass(frozen=True)
class SecurityInvariant(JsonRecord):
    SCHEMA = "assurance_invariant"
    NESTED = {"selectors": InvariantSelectors}
    MANY = {"provenance": EvidenceLink}
    invariant_id: str
    kind: str
    selectors: InvariantSelectors
    on_violation: str = "escalate"
    severity: str = "high"
    mandatory: bool = True
    authority_ref: str | None = None
    provenance: tuple[EvidenceLink, ...] = ()


def _unique(records: tuple[Any, ...], key: str) -> None:
    values = [getattr(record, key) for record in records]
    if len(set(values)) != len(values):
        raise ValueError("assurance records require unique identifiers")


@dataclass(frozen=True)
class SecurityProfile(JsonRecord):
    """Validated profile content; this object is never activation authority."""

    SCHEMA = "assurance_security_profile"
    NESTED = {"repository": RepositoryScope}
    MANY = {
        "protected_assets": ProtectedAsset,
        "trust_boundaries": TrustBoundary,
        "invariants": SecurityInvariant,
    }
    profile_id: str
    version: str
    repository: RepositoryScope
    protected_assets: tuple[ProtectedAsset, ...] = ()
    trust_boundaries: tuple[TrustBoundary, ...] = ()
    invariants: tuple[SecurityInvariant, ...] = ()
    support_flags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        _unique(self.protected_assets, "id")
        _unique(self.trust_boundaries, "id")
        _unique(self.invariants, "invariant_id")
        assets = {asset.id for asset in self.protected_assets}
        if any(
            rule.selectors.resource_ref is not None and rule.selectors.resource_ref not in assets
            for rule in self.invariants
        ):
            raise ValueError("assurance invariant references an undefined asset")


@dataclass(frozen=True)
class SecurityProfileDraft(JsonRecord):
    SCHEMA = "assurance_security_profile_draft"
    NESTED = {"repository": RepositoryScope}
    MANY = {
        "protected_assets": ProtectedAsset,
        "trust_boundaries": TrustBoundary,
        "entry_points": SourceReference,
        "source_evidence": SourceReference,
        "invariant_suggestions": SecurityInvariant,
    }
    draft_id: str
    repository: RepositoryScope
    generator: str
    protected_assets: tuple[ProtectedAsset, ...] = ()
    trust_boundaries: tuple[TrustBoundary, ...] = ()
    entry_points: tuple[SourceReference, ...] = ()
    risk_hypotheses: tuple[str, ...] = ()
    source_evidence: tuple[SourceReference, ...] = ()
    unresolved_facts: tuple[str, ...] = ()
    invariant_suggestions: tuple[SecurityInvariant, ...] = ()
    scan_digest: str | None = None
    completeness: str = "unknown"
    authoritative: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        _unique(self.protected_assets, "id")
        _unique(self.trust_boundaries, "id")
        _unique(self.invariant_suggestions, "invariant_id")


@dataclass(frozen=True)
class ApprovedSecurityProfile:
    """Host-selected immutable profile handle, unavailable through JSON import.

    The protected loader is implemented by the profiles module. A JSON
    profile's validated shape or digest alone cannot create this handle.
    """

    profile: SecurityProfile
    operator_identity: str
    selection_digest: str
    _authority: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.profile, SecurityProfile) or not isinstance(
            self._authority, _ProfileAuthority
        ):
            raise ValueError("approved profile requires a protected host selection")
        validate("repository_scope", self.profile.repository.as_dict())
        if (
            self._authority.profile_digest != self.profile.digest
            or (self._authority.selection_digest != self.selection_digest)
            or self._authority.operator_identity != self.operator_identity
        ):
            raise ValueError("approved profile host selection mismatch")

    @property
    def digest(self) -> str:
        return self.profile.digest

    @property
    def runtime_policy_digest(self) -> str | None:
        assert isinstance(self._authority, _ProfileAuthority)
        return self._authority.runtime_policy_digest

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ApprovedSecurityProfile:
        raise ValueError("JSON cannot activate an approved profile")


@dataclass(frozen=True)
class _ProfileAuthority:
    profile_digest: str
    selection_digest: str
    operator_identity: str
    runtime_policy_digest: str | None = None


@dataclass(frozen=True)
class InvariantEvaluation(JsonRecord):
    SCHEMA = "assurance_invariant_evaluation"
    invariant_id: str
    status: str
    reason_code: str
    policy_digest: str
    action_digest: str
    matched_facts: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    contract_id: str | None = None


@dataclass(frozen=True)
class AttackNode(JsonRecord):
    SCHEMA = "attack_node"
    node_id: str
    kind: str
    category: str
    value_digest: str | None = None


@dataclass(frozen=True)
class AttackEdge(JsonRecord):
    SCHEMA = "attack_edge"
    NESTED = {"evidence": EvidenceLink}
    edge_id: str
    source_id: str
    target_id: str
    kind: str
    evidence: EvidenceLink
    confidence: float | None = None
    evidence_kind: str | None = None
    correlation_id: str | None = None
    proof_gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, EvidenceLink):
            raise ValueError("attack edge requires typed evidence")
        expected = {
            "runtime_backend_observed": "host_observed",
            "host_authenticated_source": "host_observed",
            "deterministically_derived": "deterministic_inference",
            "policy_verified": "deterministic_inference",
            "static_evidence": "deterministic_inference",
            "model_hypothesis": "model_hypothesis",
            "imported_claim": "imported_claim",
            "caller_asserted": "caller_asserted",
        }[self.evidence.origin]
        if self.evidence_kind is None:
            object.__setattr__(self, "evidence_kind", expected)
        elif self.evidence_kind != expected:
            raise ValueError("edge confidence/kind cannot promote evidence origin")
        super().__post_init__()


@dataclass(frozen=True)
class AttackPathEvidence(JsonRecord):
    SCHEMA = "assurance_attack_path"
    NESTED = {"repository": RepositoryScope}
    MANY = {
        "nodes": AttackNode,
        "edges": AttackEdge,
        "supporting_evidence": EvidenceLink,
        "counterevidence": EvidenceLink,
    }
    path_id: str
    repository: RepositoryScope
    session_digest: str | None = None
    nodes: tuple[AttackNode, ...] = ()
    edges: tuple[AttackEdge, ...] = ()
    supporting_evidence: tuple[EvidenceLink, ...] = ()
    counterevidence: tuple[EvidenceLink, ...] = ()
    proof_gaps: tuple[str, ...] = ()
    exposure: str = "unknown"
    reachability: str = "unknown"
    possible_impact: tuple[str, ...] = ()
    permissions: str = "unknown"
    root_cause_digest: str | None = None
    boundary_digest: str | None = None
    occurrence_ids: tuple[str, ...] = ()
    max_depth: int = 64

    def __post_init__(self) -> None:
        super().__post_init__()
        _unique(self.nodes, "node_id")
        _unique(self.edges, "edge_id")
        nodes = {node.node_id for node in self.nodes}
        if any(edge.source_id not in nodes or edge.target_id not in nodes for edge in self.edges):
            raise ValueError("assurance graph references an undefined node")
        if any(
            edge.evidence.session_digest not in {None, self.session_digest} for edge in self.edges
        ):
            raise ValueError("assurance graph session mismatch")
        # A bounded topological walk rejects cycles and excess depth without
        # recursion. JSON diagrams cannot introduce unbounded causal chains.
        incoming = dict.fromkeys(nodes, 0)
        outgoing: dict[str, list[str]] = {key: [] for key in nodes}
        for edge in self.edges:
            incoming[edge.target_id] += 1
            outgoing[edge.source_id].append(edge.target_id)
        pending = sorted(key for key, count in incoming.items() if count == 0)
        depths = dict.fromkeys(nodes, 1)
        visited = 0
        for key in pending:
            visited += 1
            for target in outgoing[key]:
                depths[target] = max(depths[target], depths[key] + 1)
                if depths[target] > self.max_depth:
                    raise ValueError("assurance graph depth limit exceeded")
                incoming[target] -= 1
                if incoming[target] == 0:
                    pending.append(target)
        if visited != len(nodes):
            raise ValueError("assurance graph contains a cycle")


@dataclass(frozen=True)
class _FindingAuthority:
    payload_digest: str


@dataclass(frozen=True)
class SecurityFinding(JsonRecord):
    SCHEMA = "assurance_finding"
    NESTED = {"repository": RepositoryScope}
    MANY = {
        "affected_sources": SourceReference,
        "evidence": EvidenceLink,
        "counterevidence": EvidenceLink,
    }
    finding_id: str
    issue_class: str
    repository: RepositoryScope
    dedupe_key: str
    affected_sources: tuple[SourceReference, ...] = ()
    affected_operations: tuple[str, ...] = ()
    attacker_control: tuple[str, ...] = ()
    invariant_id: str | None = None
    requested_privilege: tuple[str, ...] = ()
    actual_privilege: tuple[str, ...] = ()
    evidence: tuple[EvidenceLink, ...] = ()
    counterevidence: tuple[EvidenceLink, ...] = ()
    preconditions: tuple[str, ...] = ()
    confidence: float | None = None
    status: str = "hypothesis"
    verification_method: str = "none"
    proof_gaps: tuple[str, ...] = ()
    safe_reproducer_ref: str | None = None
    occurrence_ids: tuple[str, ...] = ()
    origin: str = "caller_asserted"
    _authority: _FindingAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.origin == "imported_claim" and self.status in {"confirmed", "refuted"}:
            raise ValueError("imported claims cannot establish finding closure")
        if self.status in {"confirmed", "refuted"} and (
            not isinstance(self._authority, _FindingAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("finding closure requires verified host validation")
        if self.status == "confirmed" and (
            self.verification_method not in {"replay", "sandboxed_test", "host_observation"}
            or not self.evidence
            or self.proof_gaps
        ):
            raise ValueError("confirmed finding requires reproduction evidence without proof gaps")


@dataclass(frozen=True)
class SimulationCase(JsonRecord):
    SCHEMA = "simulation_case"
    case_id: str
    action_digest: str
    baseline_core: str
    candidate_core: str
    baseline_final: str
    candidate_final: str
    change: str
    reason_codes: tuple[str, ...] = ()
    authority_delta: str = "unknown"
    label: str = "unknown"
    baseline_ms: float = 0
    candidate_ms: float = 0
    baseline_core_ms: float = 0
    candidate_core_ms: float = 0
    baseline_wrapper_ms: float = 0
    candidate_wrapper_ms: float = 0
    expected: str = "escalate"
    critical: bool = False
    action_kind: str = "tool"
    assessable: bool = True
    baseline_effects: tuple[str, ...] = ()
    candidate_effects: tuple[str, ...] = ()
    baseline_temporal: tuple[str, ...] = ()
    candidate_temporal: tuple[str, ...] = ()
    baseline_capability_digest: str | None = None
    candidate_capability_digest: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        order = {"execute": 0, "escalate": 1, "deny": 2}
        if (
            order[self.baseline_final] < order[self.baseline_core]
            or order[self.candidate_final] < order[self.candidate_core]
        ):
            raise ValueError("simulation final decisions cannot weaken their core decisions")
        expected_change = "unchanged" if self.assessable else "unassessable"
        if self.baseline_final != self.candidate_final:
            expected_change = {
                "execute": "newly_executable",
                "escalate": "newly_escalated",
                "deny": "newly_denied",
            }[self.candidate_final]
        if self.change != expected_change:
            raise ValueError("simulation change does not match its decisions and coverage")


@dataclass(frozen=True)
class LatencyDistribution(JsonRecord):
    SCHEMA = "latency_distribution"
    p50_ms: float
    p95_ms: float
    p99_ms: float
    samples: int

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.p50_ms <= self.p95_ms <= self.p99_ms:
            raise ValueError("assurance latency percentiles must be ordered")


@dataclass(frozen=True)
class ActionKindCoverage(JsonRecord):
    SCHEMA = "action_kind_coverage"
    action_kind: str
    total: int
    assessable: int
    unresolved: int

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.assessable + self.unresolved != self.total:
            raise ValueError("action kind coverage counts must account for every case")


@dataclass(frozen=True)
class PolicySimulationReport(JsonRecord):
    SCHEMA = "assurance_simulation"
    NESTED = {"baseline_latency": LatencyDistribution, "candidate_latency": LatencyDistribution}
    MANY = {"cases": SimulationCase, "coverage_by_kind": ActionKindCoverage}
    report_id: str
    corpus_digest: str
    baseline_revision: str
    candidate_revision: str
    old_policy_digest: str
    new_policy_digest: str
    baseline_latency: LatencyDistribution
    candidate_latency: LatencyDistribution
    environment: str
    cases: tuple[SimulationCase, ...] = ()
    critical_misses: int = 0
    benign_false_escalations: int = 0
    benign_false_denials: int = 0
    coverage: str = "unknown"
    activation_safe: bool = False
    limitations: tuple[str, ...] = ()
    newly_denied: tuple[str, ...] = ()
    newly_escalated: tuple[str, ...] = ()
    newly_executable: tuple[str, ...] = ()
    unassessable: tuple[str, ...] = ()
    missing_required_cases: tuple[str, ...] = ()
    policy_authority_delta: str = "unknown"
    source_permissions: str = "unknown"
    old_profile_digest: str | None = None
    new_profile_digest: str | None = None
    old_profile_selection_digest: str | None = None
    new_profile_selection_digest: str | None = None
    critical_caught: int = 0
    coverage_by_kind: tuple[ActionKindCoverage, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        _unique(self.cases, "case_id")
        _unique(self.coverage_by_kind, "action_kind")
        if self.activation_safe:
            order = {"execute": 0, "escalate": 1, "deny": 2}
            if (
                self.baseline_revision in {"unspecified", "unknown"}
                or self.candidate_revision in {"unspecified", "unknown"}
                or self.baseline_latency.samples != len(self.cases)
                or self.candidate_latency.samples != len(self.cases)
                or any(v.unresolved or v.assessable != v.total for v in self.coverage_by_kind)
                or any(
                    v.critical
                    and order[v.candidate_final] < max(order[v.expected], order[v.baseline_final])
                    for v in self.cases
                )
                or self.newly_denied
                != tuple(v.case_id for v in self.cases if v.change == "newly_denied")
                or self.newly_escalated
                != tuple(v.case_id for v in self.cases if v.change == "newly_escalated")
                or self.newly_executable
                != tuple(v.case_id for v in self.cases if v.change == "newly_executable")
                or self.benign_false_escalations
                != sum(
                    v.label == "benign"
                    and v.expected == "execute"
                    and v.candidate_final == "escalate"
                    for v in self.cases
                )
                or self.benign_false_denials
                != sum(
                    v.label == "benign" and v.expected == "execute" and v.candidate_final == "deny"
                    for v in self.cases
                )
                or self.critical_caught
                != sum(
                    v.critical and v.assessable and order[v.candidate_final] >= order[v.expected]
                    for v in self.cases
                )
                or {v.action_kind: v.total for v in self.coverage_by_kind}
                != {
                    kind: sum(v.action_kind == kind for v in self.cases)
                    for kind in {v.action_kind for v in self.cases}
                }
            ):
                raise ValueError(
                    "incomplete passing simulation summary must match complete replay cases"
                )
        if self.activation_safe and (
            not self.cases
            or self.coverage != "complete"
            or self.critical_misses
            or self.unassessable
            or self.missing_required_cases
            or self.policy_authority_delta in {"widened", "unsupported", "unknown"}
            or self.source_permissions == "unknown"
            or any(
                case.change in {"newly_executable", "unassessable"}
                or not case.assessable
                or case.label == "unknown"
                or "assurance.simulation_critical_downgrade" in case.reason_codes
                or case.authority_delta in {"widened", "unsupported", "unknown"}
                for case in self.cases
            )
        ):
            raise ValueError("incomplete or widening simulations cannot declare activation safe")


@dataclass(frozen=True)
class CounterexampleRecord(JsonRecord):
    SCHEMA = "assurance_counterexample"
    record_id: str
    claimed_property: str
    seed: int
    generator_version: str
    mutation: str
    initial_input: str
    minimized_input: str
    initial_digest: str
    minimized_digest: str
    baseline_result: str
    candidate_result: str
    replay_outcome: str
    revision: str
    environment: str
    provenance_kind: str = "synthetic_fixture"
    safe_fixture_only: bool = True
    proof_gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.initial_digest != digest("counterexample_input", self.initial_input) or (
            self.minimized_digest != digest("counterexample_input", self.minimized_input)
        ):
            raise ValueError("counterexample input digest mismatch")


@dataclass(frozen=True)
class DelegationGrant(JsonRecord):
    """Grant artifact only. Host issuance and current lifecycle must be verified."""

    SCHEMA = "assurance_delegation"
    grant_id: str
    parent_principal: str
    child_principal: str
    issuer_identity: str
    authorization_channel: str
    session_digest: str
    epoch: int
    issued_at: int
    expires_at: int
    parent_policy_digest: str
    profile_digest: str
    contract_digest: str
    parent_grant_id: str | None = None
    revoked_at: int | None = None
    capability_refs: tuple[str, ...] = ()
    maximum_delegation_depth: int = 0
    depth: int = 0
    status: str = "proposal"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.parent_principal == self.child_principal or self.expires_at <= self.issued_at:
            raise ValueError("invalid delegation identities or lifetime")
        if self.depth > self.maximum_delegation_depth or self.parent_grant_id == self.grant_id:
            raise ValueError("invalid delegation depth or parent")
        if self.revoked_at is not None and self.revoked_at < self.issued_at:
            raise ValueError("invalid delegation revocation time")


@dataclass(frozen=True)
class ModelAnswer(JsonRecord):
    SCHEMA = "model_answer"
    question_id: str
    p_yes: float


@dataclass(frozen=True)
class ModelRiskEvidence(JsonRecord):
    SCHEMA = "assurance_model_evidence"
    MANY = {"answers": ModelAnswer}
    evidence_id: str
    provider: str
    model_version: str
    question_set_id: str
    question_set_digest: str
    redaction_policy_id: str
    input_digest: str
    answers: tuple[ModelAnswer, ...] = ()
    supportedness: str = "inconclusive"
    latency_ms: float = 0
    error_class: str = "none"
    calibration_ref: str | None = None
    consent_ref: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        _unique(self.answers, "question_id")
        if self.error_class != "none" and self.supportedness == "supported":
            raise ValueError("failed model evaluation cannot be supported")
        if self.supportedness == "supported" and not self.answers:
            raise ValueError("supported model evaluation requires answers")
