"""OCSF 1.8.0/OpenShell 0.1.2 event ingestion through a host-owned collector.

Only sanitized structured fields survive parsing. The metadata product label is
compatibility information, never authentication. Raw events must come from a
protected backend channel and attribution must be registered explicitly.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from ordin._runtime_json import MAX_RUNTIME_BYTES, digest, freeze, thaw
from ordin._runtime_url import has_unsafe_authority_characters
from ordin.execution import ObservedResource
from ordin.runtime_contract import RuntimeCapabilityContract, _safe_path
from ordin.runtime_observation import (
    RuntimeCorrelationError,
    RuntimeEvidenceSource,
    RuntimeObservation,
)

from .correlation import CorrelationStore
from .model import HTTP_METHODS, READ_METHODS

OCSF_VERSION = "1.8.0"
PRODUCT_VERSION = "0.1.2"


class OpenShellEventError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ParsedOpenShellEvent:
    event_digest: str
    event_id_digest: str
    sandbox_id: str
    time_ms: int
    class_uid: int
    trust: str
    outcome: str
    enforcement_point: str
    operation: str
    reason_code: str
    effects: tuple[str, ...] = ()
    resources: tuple[ObservedResource, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", freeze(self.metadata))

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_digest": self.event_digest,
            "event_id_digest": self.event_id_digest,
            "source_schema_version": OCSF_VERSION,
            "sandbox_id": self.sandbox_id,
            "time_ms": self.time_ms,
            "class_uid": self.class_uid,
            "trust": self.trust,
            "outcome": self.outcome,
            "enforcement_point": self.enforcement_point,
            "operation": self.operation,
            "reason_code": self.reason_code,
            "effects": list(self.effects),
            "resources": [r.as_dict() for r in self.resources],
            "metadata": thaw(self.metadata),
        }


@dataclass(frozen=True)
class EventIngestionResult:
    status: str
    reason_code: str
    event: ParsedOpenShellEvent | None = None
    observation: RuntimeObservation | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "event": self.event.as_dict() if self.event else None,
            "observation": self.observation.as_dict() if self.observation else None,
        }


def _object(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OpenShellEventError("openshell_event_malformed")
    return value


def _text(value: Any, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise OpenShellEventError("openshell_event_malformed")
    return value


def _host(value: Any) -> str:
    value = _text(value, maximum=253)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", value):
        raise OpenShellEventError("openshell_event_endpoint_invalid")
    return value.lower()


def _port(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise OpenShellEventError("openshell_event_endpoint_invalid")
    return value


def parse_openshell_event(event: str | Mapping[str, Any]) -> ParsedOpenShellEvent:
    """Parse known structured classes without parsing message/status_detail prose."""
    try:
        if isinstance(event, str):
            if len(event.encode()) > MAX_RUNTIME_BYTES:
                raise OpenShellEventError("openshell_event_size")

            def unique(pairs):
                packet = {}
                for key, value in pairs:
                    if key in packet:
                        raise OpenShellEventError("openshell_event_duplicate_key")
                    packet[key] = value
                return packet

            event = json.loads(event, object_pairs_hook=unique)
        event = _object(event)
        freeze(event)
        if len(json.dumps(thaw(event), allow_nan=False).encode()) > MAX_RUNTIME_BYTES:
            raise OpenShellEventError("openshell_event_size")
        metadata = _object(event.get("metadata"))
        product = _object(metadata.get("product"))
        if (
            metadata.get("version") != OCSF_VERSION
            or product.get("name") != "OpenShell Sandbox Supervisor"
            or product.get("vendor_name") != "OpenShell"
            or product.get("version") != PRODUCT_VERSION
        ):
            raise OpenShellEventError("openshell_event_compatibility")
        uid = _text(metadata.get("uid"), maximum=128)
        container = _object(event.get("container"))
        sandbox = _text(container.get("uid"), maximum=128)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]*", sandbox):
            raise OpenShellEventError("openshell_event_sandbox_invalid")
        time_ms = event.get("time")
        class_uid, activity_id = event.get("class_uid"), event.get("activity_id")
        if (
            type(time_ms) is not int
            or time_ms < 0
            or type(class_uid) is not int
            or type(activity_id) is not int
            or not 0 <= activity_id <= 99
            or type(event.get("type_uid")) is not int
            or event["type_uid"] != class_uid * 100 + activity_id
        ):
            raise OpenShellEventError("openshell_event_malformed")
        if class_uid not in {4001, 4002, 1007}:
            raise OpenShellEventError("openshell_event_class_unsupported")
        action = event.get("action_id")  # OCSF enum; never an Ordin action identifier.
        disposition = event.get("disposition_id")
        if type(action) is not int:
            raise OpenShellEventError("openshell_event_malformed")
        if action not in {1, 2, 3}:
            raise OpenShellEventError("openshell_event_outcome_unsupported")
        labels = {1: "Allowed", 2: "Denied", 3: "Observed"}
        if "action" in event and event["action"] != labels[action]:
            raise OpenShellEventError("openshell_event_outcome_conflict")
        if disposition is not None and (
            type(disposition) is not int
            or (action == 2 and disposition != 2)
            or (action == 1 and disposition != 1)
            or (action == 3 and disposition not in {16, 17})
        ):
            raise OpenShellEventError("openshell_event_outcome_conflict")
        # Upstream serializes both audit and enforce allows as Allowed/Allowed.
        # Without an authenticated mode field, claiming enforcement would overstate trust.
        trust = "backend_enforced" if action == 2 else "backend_observed"
        outcome = {1: "allowed", 2: "denied", 3: "unknown"}[action]
        fields: dict[str, Any] = {
            "event_digest": digest(event),
            "source_schema_version": OCSF_VERSION,
        }
        resources: tuple[ObservedResource, ...] = ()
        effects: tuple[str, ...] = ()
        rule = _object(event.get("firewall_rule", {}))
        reason = (
            "policy_denied"
            if action == 2 and rule.get("type") in {"l7", "rest", "opa", "mechanistic"}
            else ("openshell_runtime_denied" if action == 2 else "openshell_runtime_observed")
        )
        point, operation = "network", "network.connect"
        if class_uid in {4001, 4002}:
            endpoint = _object(event.get("dst_endpoint", {}))
            if class_uid == 4002:
                request = _object(event.get("http_request"))
                method = request.get("http_method")
                if not isinstance(method, str) or method not in HTTP_METHODS:
                    raise OpenShellEventError("openshell_event_method_invalid")
                fields["method"] = method
                url = _object(request.get("url", {}))
                host = _host(url.get("hostname", endpoint.get("domain", endpoint.get("ip"))))
                port = _port(url.get("port", endpoint.get("port")))
                if endpoint and (
                    _host(endpoint.get("domain", endpoint.get("ip"))) != host
                    or _port(endpoint.get("port")) != port
                ):
                    raise OpenShellEventError("openshell_event_endpoint_conflict")
                operation = "http.request"
                effects = ("network.download" if method in READ_METHODS else "network.upload",)
                if url.get("path") is not None:
                    raw_path = _text(url["path"])
                    if has_unsafe_authority_characters(raw_path):
                        raise OpenShellEventError("openshell_event_path_invalid")
                    # Remove query/fragment before retaining any request target.
                    parsed = urlsplit(raw_path)
                    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
                        raise OpenShellEventError("openshell_event_path_invalid")
                    fields["path"] = parsed.path
                if rule.get("type") == "credential-binding":
                    point, reason = "credential", "credential_binding_denied"
            else:
                host = _host(endpoint.get("domain", endpoint.get("ip")))
                port = _port(endpoint.get("port"))
                effects = ("network.connect",)
            fields.update(host=host, port=port)
            # Host identity alone does not establish an HTTPS URL or REST path.
            resources = (ObservedResource("host", host),)
        elif class_uid == 1007:
            if activity_id != 1:
                raise OpenShellEventError("openshell_event_process_activity_unsupported")
            point, operation, effects = "process", "process.start", ("process.execute",)
        actor = event.get("actor")
        process_value = (
            event.get("process")
            if class_uid == 1007
            else (_object(actor).get("process") if actor is not None else None)
        )
        if class_uid == 1007 and process_value is None:
            raise OpenShellEventError("openshell_event_process_invalid")
        if process_value is not None:
            process = _object(process_value)
            pid = process.get("pid")
            if type(pid) is not int or pid < 0:
                raise OpenShellEventError("openshell_event_process_invalid")
            fields["process_id"] = pid
            name = _text(process.get("name"))
            # Upstream may supply a basename. Never invent an absolute binary path.
            if _safe_path(name):
                fields["binary"] = name
        return ParsedOpenShellEvent(
            digest(event),
            digest({"uid": uid}),
            sandbox,
            time_ms,
            class_uid,
            trust,
            outcome,
            point,
            operation,
            reason,
            effects,
            resources,
            fields,
        )
    except OpenShellEventError:
        raise
    except (ValueError, TypeError, KeyError, RecursionError):
        raise OpenShellEventError("openshell_event_malformed") from None


def ingest_openshell_event(
    event: str | Mapping[str, Any],
    *,
    contract: RuntimeCapabilityContract | None = None,
    source: RuntimeEvidenceSource | None = None,
    store: CorrelationStore | None = None,
    now_ms: int | None = None,
) -> EventIngestionResult:
    """Accept evidence only with an exact private event/action/source binding."""
    try:
        parsed = parse_openshell_event(event)
    except OpenShellEventError as exc:
        state = "unsupported" if exc.reason_code.endswith("unsupported") else "rejected"
        return EventIngestionResult(state, exc.reason_code)
    if contract is None or source is None or store is None or now_ms is None:
        return EventIngestionResult("uncorrelated", "openshell_event_uncorrelated", parsed)
    try:
        if source.backend != "openshell" or parsed.sandbox_id != source.sandbox_id:
            raise RuntimeCorrelationError("runtime_observation_source_mismatch")
        binding = store.lookup(parsed.event_id_digest)
        if binding is None:
            return EventIngestionResult("uncorrelated", "openshell_event_uncorrelated", parsed)
        binding.require_match(
            contract,
            source,
            event_digest=parsed.event_digest,
            event_time_ms=parsed.time_ms,
            now_ms=now_ms,
        )
        if contract.decision == "block" and parsed.outcome != "denied":
            raise RuntimeCorrelationError("runtime_observation_denied_action")
        observation = source.observe(
            contract,
            observation_id="os:" + parsed.event_id_digest,
            trust=parsed.trust,
            enforcement_point=parsed.enforcement_point,
            outcome=parsed.outcome,
            operation=parsed.operation,
            effects=parsed.effects,
            resources=parsed.resources,
            reason_code=parsed.reason_code,
            metadata=parsed.metadata,
        )
        store.consume(binding)
        return EventIngestionResult("accepted", "runtime.observation.accepted", parsed, observation)
    except RuntimeCorrelationError as exc:
        return EventIngestionResult("rejected", exc.reason_code, parsed)
    except (ValueError, OSError, TypeError):
        return EventIngestionResult("rejected", "openshell_correlation_unavailable", parsed)
