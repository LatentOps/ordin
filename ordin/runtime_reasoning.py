"""Add runtime evidence to existing temporal reasoning without replacing predictions."""

from __future__ import annotations

from dataclasses import replace
from typing import Mapping
from urllib.parse import urlsplit

from ._runtime_json import digest
from .action import ActionHistory, ActionReview
from .provenance import ProvenanceRecord, ProvenanceResource
from .runtime_observation import RuntimeObservation


def with_runtime_provenance(
    review: ActionReview,
    history: ActionHistory | None,
    observations: Mapping[str, tuple[RuntimeObservation, ...]],
) -> ActionReview:
    if history is None or review.provenance is None:
        return review
    records = []
    for index, action in enumerate(history.actions):
        for observation in observations.get(action.action_id or "", ()):
            metadata = {
                "history_index": index,
                "observation_digest": observation.digest,
                "observation_id_sha256": digest(observation.observation_id),
                "action_digest": observation.action_digest,
                "contract_id": observation.contract_id,
                "backend": observation.backend,
                "trust": observation.trust,
                "enforcement_point": observation.enforcement_point,
                "outcome": observation.outcome,
                "reason_code": observation.reason_code,
                "policy_digest": observation.policy_digest,
                "session_digest": observation.session_digest,
                "sandbox_id_sha256": digest(observation.sandbox_id)
                if observation.sandbox_id
                else None,
                "event_digest": observation.metadata.get("event_digest"),
            }
            records.append(
                ProvenanceRecord(
                    source="observation",
                    kind="observation",
                    code="runtime.observation.accepted",
                    action_id=observation.action_id,
                    metadata=metadata,
                )
            )
            for effect in observation.effects:
                records.append(
                    ProvenanceRecord(
                        source="observation",
                        kind="effect",
                        code=f"runtime.observation.{observation.outcome}-effect",
                        effect=effect,
                        action_id=observation.action_id,
                        metadata={"history_index": index, "trust": observation.trust},
                    )
                )
            for resource in observation.resources:
                records.append(
                    ProvenanceRecord(
                        source="observation",
                        kind="resource",
                        code="runtime.observation.resource",
                        resource=ProvenanceResource(resource.type, resource.value),
                        action_id=observation.action_id,
                        metadata={"history_index": index},
                    )
                )
    # The existing provenance model enforces its 512-record bound. Excessive
    # evidence fails validation rather than silently dropping records.
    return replace(review, provenance=review.provenance.append(*records))


def _request_key(host, port, path) -> tuple[str, ...] | None:
    if (
        not isinstance(host, str)
        or not host
        or type(port) is not int
        or not 1 <= port <= 65535
        or not isinstance(path, str)
        or not path.startswith("/")
        or any(c in path for c in "%?#")
        or "//" in path
        or any(part in {".", ".."} for part in path.split("/"))
    ):
        return None
    return ("request", host.lower(), str(port), path)


def _resource_keys(resources) -> set[tuple[str, ...]]:
    keys: set[tuple[str, ...]] = {(r.type, r.value) for r in resources}
    for resource in resources:
        if resource.type not in {"url", "endpoint"}:
            continue
        try:
            url = urlsplit(resource.value)
            if (
                url.scheme not in {"https", "http"}
                or url.username is not None
                or url.password is not None
                or url.query
                or url.fragment
                or any(ord(c) < 32 for c in resource.value)
            ):
                continue
            port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
            key = _request_key(url.hostname, port, url.path or "/")
            if key is not None:
                keys.add(key)
        except ValueError:
            pass
    return keys


def _observed_keys(observation: RuntimeObservation) -> set[tuple[str, ...]]:
    keys = _resource_keys(observation.resources)
    if observation.enforcement_point == "network" and observation.operation == "http.request":
        key = _request_key(
            observation.metadata.get("host"),
            observation.metadata.get("port"),
            observation.metadata.get("path"),
        )
        if key is not None:
            previous = {k for k in keys if k[0] == "request"}
            if previous and key not in previous:
                return set()  # Contradictory targets cannot establish a retry.
            keys.add(key)
    return keys


def current_runtime_signals(
    review: ActionReview,
    observations: Mapping[str, tuple[RuntimeObservation, ...]],
) -> frozenset[str]:
    targets = _resource_keys(review.resources)
    matches = [
        o
        for group in observations.values()
        for o in group
        if o.trust == "backend_enforced"
        and o.outcome == "denied"
        and bool(_observed_keys(o).intersection(targets))
    ]
    signals = set()
    denied_counts: dict[tuple[str, ...], int] = {}
    for observation in matches:
        if observation.reason_code == "policy_denied":
            for key in _observed_keys(observation).intersection(targets):
                denied_counts[key] = denied_counts.get(key, 0) + 1
    if any(count >= 2 for count in denied_counts.values()):
        signals.add("signal:runtime-boundary-retry")
    mutation = any(
        e.startswith("privilege.")
        or e
        in {
            "filesystem.write",
            "filesystem.delete",
            "filesystem.permission_change",
            "system.configuration_write",
            "system.device_write",
        }
        for e in review.effects
    )
    if mutation and len(targets) == 1 and any("privilege.escalate" in o.effects for o in matches):
        signals.add("signal:runtime-privilege-alternative")
    return frozenset(signals)
