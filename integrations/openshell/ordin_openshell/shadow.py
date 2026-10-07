"""Pure local shadow evaluation. This module never applies policy or runs actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ordin._runtime_json import digest, freeze, thaw, validate
from ordin.enforcement_backend import EnforcementPlan
from ordin.runtime_boundary import (
    RuntimeCapabilityBoundary,
    CapabilityVerificationResult,
    verify_runtime_capability,
)
from ordin.runtime_contract import RuntimeCapabilityContract
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation
from ordin.runtime_requests import (
    RuntimeRequestBoundary,
    RequestVerificationResult,
    verify_runtime_request_capability,
)

from .compiler import OpenShellBackend
from ordin.runtime_requests_v2 import RuntimeRequestContractV2, verify_request_contract
from .model import READ_METHODS

SHADOW_SCHEMA_VERSION = "ordin.runtime_shadow_report.v1"
METRIC_NAMES = (
    "actions_reviewed",
    "contracts_generated",
    "contracts_fully_representable",
    "contracts_unsupported",
    "runtime_events_correlated",
    "correlation_mismatches",
    "observed_but_unpredicted_capabilities",
    "predicted_but_unused_capabilities",
    "would_deny_events",
    "compiler_widening_failures",
)


@dataclass(frozen=True)
class ShadowCase:
    contract: RuntimeCapabilityContract
    boundary: RuntimeCapabilityBoundary
    observations: tuple[RuntimeObservation, ...] = ()
    source: RuntimeEvidenceSource | None = None
    backend: OpenShellBackend = field(default_factory=lambda: OpenShellBackend(mode="shadow"))
    request_boundary: RuntimeRequestBoundary | None = None


@dataclass(frozen=True)
class ShadowReport:
    metrics: Mapping[str, int]
    boundary_outcomes: Mapping[str, int]
    actions: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "metrics", freeze(self.metrics))
        object.__setattr__(self, "boundary_outcomes", freeze(self.boundary_outcomes))
        object.__setattr__(self, "actions", freeze(self.actions))
        validate("runtime_shadow_report", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SHADOW_SCHEMA_VERSION,
            "backend": "openshell",
            "mode": "shadow",
            "metrics": thaw(self.metrics),
            "boundary_outcomes": thaw(self.boundary_outcomes),
            "actions": thaw(self.actions),
        }

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ShadowReport:
        validate("runtime_shadow_report", data)
        if data["backend"] != "openshell":
            raise ValueError("openshell_shadow_backend_mismatch")
        return cls(data["metrics"], data["boundary_outcomes"], tuple(data["actions"]))


def _network_prediction(
    contract: RuntimeCapabilityContract, observation: RuntimeObservation
) -> str:
    fields = observation.metadata
    uncertain = False
    for capability in contract.network:
        if capability.host not in {None, fields.get("host")} or capability.port not in {
            None,
            fields.get("port"),
        }:
            continue
        if capability.host is None or capability.port is None:
            uncertain = True
            continue
        if observation.operation == "network.connect":
            return "predicted"  # L4 attempt only; no request permission is inferred.
        if capability.protocol != "rest" or not fields.get("method") or not fields.get("path"):
            uncertain = True
            continue
        if (
            fields["method"] in capability.methods
            and fields["path"] in capability.paths
            and (capability.access == "write" or fields["method"] in READ_METHODS)
        ):
            return "predicted"
    return "inconclusive" if uncertain else "unpredicted"


def prediction_match(contract: RuntimeCapabilityContract, observation: RuntimeObservation) -> str:
    if observation.enforcement_point == "network":
        return _network_prediction(contract, observation)
    if observation.enforcement_point == "process":
        if contract.process.execution is False:
            return "unpredicted"
        binary = observation.metadata.get("binary")
        if contract.process.execution is None or not binary or not contract.process.executables:
            return "inconclusive"
        return "predicted" if binary in contract.process.executables else "unpredicted"
    if observation.enforcement_point == "filesystem":
        effects = set(observation.effects)
        accesses = {
            "filesystem.read": "read",
            "filesystem.metadata_read": "metadata",
            "filesystem.write": "write",
            "filesystem.delete": "delete",
            "filesystem.recursive_delete": "delete",
        }
        requested = {accesses[e] for e in effects if e in accesses}
        paths = {r.value for r in observation.resources if r.type in {"path", "file"}}
        if not requested or not paths:
            return "inconclusive"
        for path in paths:
            for access in requested:
                if not any(
                    (f.access == access or (f.access == "read" and access == "metadata"))
                    and f.path is not None
                    and (
                        path == f.path
                        or (f.scope == "prefix" and path.startswith(f.path.rstrip("/") + "/"))
                    )
                    for f in contract.filesystem
                ):
                    return "unpredicted"
        return "predicted"
    return "inconclusive"  # Binding/tool identities are not present in these event fields.


def policy_request_match(plan: EnforcementPlan, observation: RuntimeObservation) -> str:
    """Compare modeled request/binary fields; no claim about DNS, secrets, or execution."""
    if observation.enforcement_point != "network":
        return "inconclusive"
    fields = observation.metadata
    host, port = fields.get("host"), fields.get("port")
    if host is None or port is None:
        return "inconclusive"
    if any(
        endpoint["host"] == host
        and endpoint["port"] == port
        and endpoint["protocol"] != "rest"
        and "request_integrity" not in endpoint
        and endpoint.get("path") == fields.get("path")
        for rule in plan.policy["network_policies"].values()
        for endpoint in rule["endpoints"]
    ):
        # HTTP metadata does not establish GraphQL operations or MCP methods/tools.
        return "inconclusive"
    uncertain = False
    for rule in plan.policy["network_policies"].values():
        for endpoint in rule["endpoints"]:
            if endpoint["host"] != host or endpoint["port"] != port:
                continue
            integrity = endpoint.get("request_integrity")
            if integrity is not None:
                if any(
                    fields.get(key) is None
                    for key in (
                        "protocol",
                        "request_commitment",
                        "request_commitment_algorithm",
                        "method",
                        "path",
                        "binary",
                    )
                ):
                    uncertain = True
                    continue
                if (
                    fields["protocol"] == endpoint["protocol"]
                    and fields["method"] == "POST"
                    and fields["path"] == endpoint["path"]
                    and fields["request_commitment_algorithm"] == integrity["algorithm"]
                    and fields["request_commitment"] in integrity["commitments"]
                    and any(b["path"] == fields["binary"] for b in rule["binaries"])
                ):
                    return "within_policy"
                continue
            if endpoint["protocol"] != "rest":
                uncertain = True
                continue
            method, path = fields.get("method"), fields.get("path")
            if method is None or path is None:
                uncertain = True
                continue
            if not any(
                r["allow"]["method"] == method and r["allow"]["path"] == path
                for r in endpoint["rules"]
            ):
                continue
            binary = fields.get("binary")
            if binary is None:
                uncertain = True
            elif any(b["path"] == binary for b in rule["binaries"]):
                return "within_policy"
    return "inconclusive" if uncertain else "outside_policy"


def _unused_capabilities(
    contract: RuntimeCapabilityContract, observations: Sequence[RuntimeObservation]
) -> int:
    # Count declared resource capabilities, not raw predicted command strings.
    # A denial still observes an attempt at a requirement; it is not completion.
    from dataclasses import replace

    unused = 0
    for name in ("filesystem", "network", "tools", "credentials"):
        for capability in getattr(contract, name):
            changes: dict[str, Any] = {"contract_id": "", name: (capability,)}
            narrowed = replace(contract, **changes)
            point = {
                "filesystem": "filesystem",
                "network": "network",
                "tools": "tool",
                "credentials": "credential",
            }[name]
            if not any(
                o.enforcement_point == point and prediction_match(narrowed, o) == "predicted"
                for o in observations
            ):
                unused += 1
    if contract.process.execution is True and not any(
        o.enforcement_point == "process" and prediction_match(contract, o) == "predicted"
        for o in observations
    ):
        unused += 1
    if contract.privilege.escalation is True:
        unused += 1  # Upstream fixtures do not establish privilege use.
    return unused


def build_shadow_report(cases: Sequence[ShadowCase]) -> ShadowReport:
    """Evaluate already-reviewed contracts against boundaries and trusted observations.

    Attribution is rechecked; invalid events contribute only digest/reason records.
    This is a bounded diagnostic projection, not backend enforcement verification.
    """
    if len(cases) > 128 or sum(len(c.observations) for c in cases) > 128:
        raise ValueError("openshell_shadow_capacity")
    if len({c.contract.contract_id for c in cases}) != len(cases):
        raise ValueError("openshell_shadow_duplicate_contract")
    metrics = {name: 0 for name in METRIC_NAMES}
    outcomes = {
        name: 0 for name in ("within_boundary", "exceeds_boundary", "unsupported", "inconclusive")
    }
    rows = []
    seen_observations: set[str] = set()
    for case in cases:
        contract = case.contract
        metrics["actions_reviewed"] += 1
        metrics["contracts_generated"] += 1
        compiled = case.backend.compile(contract)
        verification: CapabilityVerificationResult | RequestVerificationResult
        if (
            case.backend.request_contract is not None
            and case.request_boundary is not None
            and case.backend.request_contract.capability == contract
        ):
            verification = verify_request_contract(
                case.backend.request_contract, case.request_boundary
            )
        else:
            verification = verify_runtime_capability(contract, case.boundary)
        outcomes[verification.result] += 1
        categories: set[str] = set()
        plan = compiled.plan
        effective_status = compiled.status
        if compiled.status == "success" and plan is not None:
            if plan.contract != contract or not case.backend.validate(plan).ok:
                categories.add("compiler_widening_detected")
                metrics["compiler_widening_failures"] += 1
                metrics["contracts_unsupported"] += 1
                effective_status = "unsupported"
                plan = None
            else:
                metrics["contracts_fully_representable"] += 1
        else:
            metrics["contracts_unsupported"] += 1
            categories.add("unrepresentable_capability")
            if any("would_widen" in f for f in compiled.unsupported_fields):
                categories.add("compiler_widening_detected")
                metrics["compiler_widening_failures"] += 1
        events, accepted = [], []
        for observation in case.observations:
            mismatch_code = None
            if observation.observation_id in seen_observations:
                mismatch_code = "runtime_observation_duplicate"
            elif observation.action_id != contract.action_id or (
                observation.action_digest != contract.action_digest
            ):
                mismatch_code = "runtime_observation_action_mismatch"
            elif observation.contract_id != contract.contract_id:
                mismatch_code = "runtime_observation_contract_mismatch"
            elif (
                case.source is None
                or observation.source_key != case.source.key
                or observation.trust == "caller_asserted"
            ):
                mismatch_code = "runtime_observation_source_mismatch"
            seen_observations.add(observation.observation_id)
            if mismatch_code:
                metrics["correlation_mismatches"] += 1
                categories.add("action_correlation_mismatch")
                events.append(
                    {
                        "observation_digest": observation.digest,
                        "event_digest": observation.metadata.get("event_digest"),
                        "outcome": observation.outcome,
                        "prediction": "inconclusive",
                        "policy_match": "inconclusive",
                        "reason_code": mismatch_code,
                    }
                )
                continue
            metrics["runtime_events_correlated"] += 1
            accepted.append(observation)
            predicted = prediction_match(contract, observation)
            if case.backend.request_contract is not None and observation.metadata.get(
                "request_commitment"
            ):
                authority = case.backend.request_contract
                if isinstance(authority, RuntimeRequestContractV2):
                    fields = observation.metadata
                    predicted = (
                        "predicted"
                        if any(
                            (r.protocol, r.host, r.port, r.path, r.commitment, r.algorithm)
                            == tuple(
                                fields.get(key)
                                for key in (
                                    "protocol",
                                    "host",
                                    "port",
                                    "path",
                                    "request_commitment",
                                    "request_commitment_algorithm",
                                )
                            )
                            for r in authority.requests
                        )
                        else "unpredicted"
                    )
            policy_match = policy_request_match(plan, observation) if plan else "inconclusive"
            if predicted == "unpredicted":
                metrics["observed_but_unpredicted_capabilities"] += 1
                categories.add("observed_but_not_predicted")
            if policy_match == "outside_policy":
                metrics["would_deny_events"] += 1
            if observation.outcome == "denied":
                if policy_match == "outside_policy":
                    categories.add("runtime_denial_expected")
                elif policy_match == "within_policy":
                    categories.add("runtime_denial_unexpected")
            if predicted == "inconclusive" or policy_match == "inconclusive":
                categories.add("runtime_event_inconclusive")
            events.append(
                {
                    "observation_digest": observation.digest,
                    "event_digest": observation.metadata.get("event_digest"),
                    "outcome": observation.outcome,
                    "prediction": predicted,
                    "policy_match": policy_match,
                    "reason_code": observation.reason_code,
                }
            )
        unused = _unused_capabilities(contract, accepted)
        metrics["predicted_but_unused_capabilities"] += unused
        if unused:
            categories.add("predicted_but_not_observed")
        rows.append(
            {
                "action_digest": contract.action_digest,
                "contract_id": contract.contract_id,
                "contract_digest": contract.digest,
                "review_decision": contract.decision,
                "risk": contract.risk,
                "policy_digest": plan.policy_digest if plan else None,
                "compilation_status": effective_status,
                "unsupported_fields": list(compiled.unsupported_fields),
                "boundary_result": verification.result,
                "boundary_digest": verification.boundary_digest,
                "boundary_coverage": {
                    d: verification.coverage[d]
                    and (verification.coverage.get("requests", True) if d == "network" else True)
                    for d in (
                        "filesystem",
                        "network",
                        "tools",
                        "process",
                        "privilege",
                        "credentials",
                    )
                },
                "mismatches": sorted(categories),
                "events": events,
            }
        )
    return ShadowReport(metrics, outcomes, tuple(rows))
