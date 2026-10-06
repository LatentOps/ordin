"""Bounded runtime evidence with an explicit trusted-adapter construction path.

Strong labels describe a host-owned reporting boundary, not remote attestation.
Normal JSON loading and direct construction accept caller assertions only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from ._runtime_json import digest, freeze, model_tuple, text_tuple, thaw, validate
from .action import ActionEnvelope, ActionHistory
from .execution import ObservedResource
from .runtime_contract import RuntimeCapabilityContract

RUNTIME_OBSERVATION_SCHEMA_VERSION = "ordin.runtime_observation.v1"
RUNTIME_OBSERVATION_HISTORY_SCHEMA_VERSION = "ordin.runtime_observation_history.v1"


class RuntimeCorrelationError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class _EvidenceAuthority:
    source_key: str
    record_digest: str


@dataclass(frozen=True)
class RuntimeReviewBinding:
    """Explicit host session context, retained in review provenance for replay defense."""

    session_digest: str
    sequence: int
    epoch: int

    def __post_init__(self) -> None:
        validate("runtime_review_binding", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_digest": self.session_digest,
            "sequence": self.sequence,
            "epoch": self.epoch,
        }


def _safe_resources(resources: tuple[ObservedResource, ...], metadata: Mapping[str, Any]) -> None:
    for resource in resources:
        value = resource.value
        if resource.type in {"url", "endpoint"}:
            try:
                url = urlsplit(value)
                if (
                    url.scheme not in {"https", "http"}
                    or not url.hostname
                    or url.username is not None
                    or url.password is not None
                    or url.query
                    or url.fragment
                ):
                    raise ValueError("runtime observation rejects sensitive or ambiguous URLs")
                if url.port is not None and not 1 <= url.port <= 65535:
                    raise ValueError("runtime observation rejects sensitive or ambiguous URLs")
            except ValueError:
                raise ValueError(
                    "runtime observation rejects sensitive or ambiguous URLs"
                ) from None
    # These fields identify request boundaries, not headers, bodies, or queries.
    path = metadata.get("path")
    if path is not None and (not path.startswith("/") or "?" in path or "#" in path):
        raise ValueError("runtime observation path must not contain query or fragment data")


@dataclass(frozen=True)
class RuntimeObservation:
    observation_id: str
    action_id: str
    action_digest: str | None = None
    contract_id: str | None = None
    backend: str = "caller"
    trust: str = "caller_asserted"
    enforcement_point: str = "unknown"
    outcome: str = "unknown"
    operation: str = "unknown"
    effects: tuple[str, ...] = ()
    resources: tuple[ObservedResource, ...] = ()
    reason_code: str = "unknown"
    metadata: Mapping[str, Any] = field(default_factory=dict)
    session_digest: str | None = None
    sandbox_id: str | None = None
    policy_digest: str | None = None
    _authority: _EvidenceAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "effects", text_tuple(self.effects))
        object.__setattr__(self, "resources", model_tuple(self.resources, ObservedResource))
        if not isinstance(self.metadata, Mapping):
            raise ValueError("runtime observation metadata requires an object")
        object.__setattr__(self, "metadata", freeze(self.metadata))
        validate("runtime_observation", self.as_dict())
        _safe_resources(self.resources, self.metadata)
        if self.trust != "caller_asserted":
            if not all(
                (
                    self.action_digest,
                    self.contract_id,
                    self.session_digest,
                    self.sandbox_id,
                    self.policy_digest,
                )
            ):
                raise RuntimeCorrelationError("runtime_observation_missing_binding")
            if not isinstance(self._authority, _EvidenceAuthority) or (
                self._authority.source_key != self.source_key
                or self._authority.record_digest != self.digest
            ):
                raise RuntimeCorrelationError("runtime_observation_untrusted_source")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUNTIME_OBSERVATION_SCHEMA_VERSION,
            "observation_id": self.observation_id,
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "contract_id": self.contract_id,
            "backend": self.backend,
            "trust": self.trust,
            "enforcement_point": self.enforcement_point,
            "outcome": self.outcome,
            "operation": self.operation,
            "effects": list(self.effects),
            "resources": [r.as_dict() for r in self.resources],
            "reason_code": self.reason_code,
            "metadata": thaw(self.metadata),
            "session_digest": self.session_digest,
            "sandbox_id": self.sandbox_id,
            "policy_digest": self.policy_digest,
        }

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    @property
    def source_key(self) -> str:
        return digest(
            {
                "backend": self.backend,
                "session_digest": self.session_digest,
                "sandbox_id": self.sandbox_id,
                "policy_digest": self.policy_digest,
            }
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RuntimeObservation:
        validate("runtime_observation", payload)
        if payload["trust"] != "caller_asserted":
            raise RuntimeCorrelationError("runtime_observation_untrusted_source")
        return cls(**_observation_arguments(payload))


def _observation_arguments(payload: Mapping[str, Any]) -> dict[str, Any]:
    arguments = {k: v for k, v in payload.items() if k != "schema_version"}
    arguments["resources"] = tuple(ObservedResource(**r) for r in payload["resources"])
    return arguments


@dataclass(frozen=True)
class RuntimeEvidenceSource:
    """Host-owned adapter authorization. Never construct from agent JSON.

    Host code owns this object and the backend event collection/correlation path.
    Python code inside that same trusted process can construct it; this is an
    API boundary, not protection against an in-process attacker or forged files.
    """

    backend: str
    session_digest: str
    sandbox_id: str
    policy_digest: str

    def __post_init__(self) -> None:
        validate("runtime_source_context", self.as_dict())

    def as_dict(self) -> dict[str, str]:
        return {
            "backend": self.backend,
            "session_digest": self.session_digest,
            "sandbox_id": self.sandbox_id,
            "policy_digest": self.policy_digest,
        }

    @property
    def key(self) -> str:
        return digest(self.as_dict())

    def restore_trusted(self, payload: Mapping[str, Any]) -> RuntimeObservation:
        """Restore protected, operator-owned evidence for this exact source scope.

        This is deliberately separate from ordinary JSON loading. Calling code
        must authenticate/own the event input or private persistence path.
        """
        validate("runtime_observation", payload)
        if any(payload[k] != v for k, v in self.as_dict().items()):
            raise RuntimeCorrelationError("runtime_observation_source_mismatch")
        if payload["trust"] not in {"backend_observed", "backend_enforced"}:
            raise RuntimeCorrelationError("runtime_observation_untrusted_source")
        return RuntimeObservation(
            **_observation_arguments(payload),
            _authority=_EvidenceAuthority(self.key, digest(payload)),
        )

    def observe(
        self,
        contract: RuntimeCapabilityContract,
        *,
        observation_id: str,
        trust: str,
        enforcement_point: str,
        outcome: str,
        operation: str,
        effects: tuple[str, ...] = (),
        resources: tuple[ObservedResource, ...] = (),
        reason_code: str = "unknown",
        metadata: Mapping[str, Any] | None = None,
    ) -> RuntimeObservation:
        if not isinstance(contract, RuntimeCapabilityContract) or contract.action_id is None:
            raise RuntimeCorrelationError("runtime_observation_action_mismatch")
        packet = {
            "schema_version": RUNTIME_OBSERVATION_SCHEMA_VERSION,
            "observation_id": observation_id,
            "action_id": contract.action_id,
            "action_digest": contract.action_digest,
            "contract_id": contract.contract_id,
            **self.as_dict(),
            "trust": trust,
            "enforcement_point": enforcement_point,
            "outcome": outcome,
            "operation": operation,
            "effects": list(effects),
            "resources": [r.as_dict() for r in resources],
            "reason_code": reason_code,
            "metadata": thaw(metadata or {}),
        }
        return self.restore_trusted(packet)


@dataclass(frozen=True)
class RuntimeObservationHistory:
    observations: tuple[RuntimeObservation, ...] = ()
    contracts: tuple[RuntimeCapabilityContract, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "observations", model_tuple(self.observations, RuntimeObservation))
        object.__setattr__(
            self, "contracts", model_tuple(self.contracts, RuntimeCapabilityContract)
        )
        if len({o.observation_id for o in self.observations}) != len(self.observations):
            raise RuntimeCorrelationError("runtime_observation_duplicate")
        ids = [c.action_id for c in self.contracts]
        if None in ids or len(set(ids)) != len(ids):
            raise RuntimeCorrelationError("runtime_observation_contract_mismatch")
        validate("runtime_observation_history", self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUNTIME_OBSERVATION_HISTORY_SCHEMA_VERSION,
            "observations": [o.as_dict() for o in self.observations],
            "contracts": [c.as_dict() for c in self.contracts],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RuntimeObservationHistory:
        validate("runtime_observation_history", payload)
        return cls(
            tuple(RuntimeObservation.from_dict(o) for o in payload["observations"]),
            tuple(RuntimeCapabilityContract.from_dict(c) for c in payload["contracts"]),
        )

    @classmethod
    def restore_trusted(
        cls, payload: Mapping[str, Any], *, sources: Sequence[RuntimeEvidenceSource]
    ) -> RuntimeObservationHistory:
        validate("runtime_observation_history", payload)
        contexts = {s.key: s for s in sources}
        observations = []
        for item in payload["observations"]:
            if item["trust"] == "caller_asserted":
                observations.append(RuntimeObservation.from_dict(item))
            else:
                key = digest(
                    {
                        k: item[k]
                        for k in ("backend", "session_digest", "sandbox_id", "policy_digest")
                    }
                )
                source = contexts.get(key)
                if source is None:
                    raise RuntimeCorrelationError("runtime_observation_untrusted_source")
                observations.append(source.restore_trusted(item))
        return cls(
            tuple(observations),
            tuple(RuntimeCapabilityContract.from_dict(c) for c in payload["contracts"]),
        )

    def correlate(
        self,
        history: ActionHistory | None,
        *,
        session_digest: str | None = None,
        allowed_sources: Sequence[RuntimeEvidenceSource] | None = None,
    ) -> dict[str, tuple[RuntimeObservation, ...]]:
        if not self.observations:
            return {}
        if history is None:
            raise RuntimeCorrelationError("runtime_observation_action_mismatch")
        actions: dict[str, ActionEnvelope] = {}
        for action in history.actions:
            if action.action_id is not None:
                if action.action_id in actions:
                    raise RuntimeCorrelationError("runtime_observation_action_mismatch")
                actions[action.action_id] = action
        contracts = {c.action_id: c for c in self.contracts}
        permitted = {s.key for s in allowed_sources} if allowed_sources is not None else None
        result: dict[str, list[RuntimeObservation]] = {}
        for observation in self.observations:
            matched_action = actions.get(observation.action_id)
            if matched_action is None:
                raise RuntimeCorrelationError("runtime_observation_action_mismatch")
            canonical = digest(matched_action.as_dict())
            if observation.action_digest is not None and observation.action_digest != canonical:
                raise RuntimeCorrelationError("runtime_observation_action_mismatch")
            contract = contracts.get(observation.action_id)
            if observation.contract_id is not None and (
                contract is None
                or contract.action_digest != canonical
                or contract.contract_id != observation.contract_id
            ):
                raise RuntimeCorrelationError("runtime_observation_contract_mismatch")
            if (
                contract is not None
                and contract.decision == "block"
                and observation.outcome != "denied"
            ):
                raise RuntimeCorrelationError("runtime_observation_denied_action")
            if session_digest is not None and observation.session_digest != session_digest:
                raise RuntimeCorrelationError("runtime_observation_session_mismatch")
            if (
                permitted is not None
                and observation.trust != "caller_asserted"
                and (observation.source_key not in permitted)
            ):
                raise RuntimeCorrelationError("runtime_observation_source_mismatch")
            result.setdefault(observation.action_id, []).append(observation)
        return {key: tuple(values) for key, values in result.items()}


def runtime_observation_signals(observation: RuntimeObservation) -> frozenset[str]:
    """Normalize additive signals; a denial describes attempted, not completed, effects."""
    signals = {
        f"signal:runtime-enforcement-point:{observation.enforcement_point}",
        f"signal:runtime-reason:{observation.reason_code}",
        f"signal:runtime-{observation.outcome}",
    }
    if observation.trust == "backend_enforced":
        signals.add("signal:runtime-enforced")
    elif observation.trust == "backend_observed":
        signals.add("signal:runtime-observed")
    if observation.outcome == "completed":
        for effect in observation.effects:
            signals.update((f"effect:{effect}", f"signal:observed-effect:{effect}"))
        signals.add("signal:observed-success")
    elif observation.outcome == "allowed":
        signals.update(f"signal:runtime-allowed-effect:{effect}" for effect in observation.effects)
    elif observation.outcome == "failed":
        signals.add("signal:observed-failure")
    elif observation.outcome == "denied":
        signals.add("signal:observed-failure")
        for effect in observation.effects:
            signals.add(f"signal:runtime-denied-effect:{effect}")
        secret_resource = any(
            r.type == "secret"
            or (
                r.type in {"path", "file"}
                and re.search(
                    r"(?:^|/)(?:\.env(?:\.[^/]*)?|id_rsa|credentials(?:\.[^/]*)?|secrets?(?:\.[^/]*)?)(?:/|$)",
                    r.value,
                    re.IGNORECASE,
                )
            )
            for r in observation.resources
        )
        if observation.trust != "caller_asserted" and (
            "secret.read" in observation.effects or secret_resource
        ):
            signals.add("signal:runtime-denied-secret-access")
    return frozenset(signals)
