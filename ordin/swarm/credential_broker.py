"""Private credential use only through exact destination-bound online delegation."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from threading import RLock
from typing import Any, Callable
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest
from ordin.runtime_contract import (
    CredentialBinding,
    NetworkCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_requests_v2 import derive_runtime_request_contract_v2
from ordin.assurance.rest import derive_rest_request_contract

from .delegation import DelegationDispatch, RemoteReview, SwarmDelegationService, _checked
from .models import identifier
from .workload_auth import AuthorityChannel


@dataclass(frozen=True, eq=False, slots=True)
class CredentialRoute:
    route_id: str


@dataclass(frozen=True, slots=True)
class PrivateCredentialRequest:
    """Only a protected transport receives this object; never serialize it."""

    action: ActionEnvelope
    binding: CredentialBinding
    credential: bytes = field(repr=False)


@dataclass
class _Route:
    binding: CredentialBinding
    destination: NetworkCapability
    request_digest: str
    secret: bytes = field(repr=False)
    forward: Callable[[PrivateCredentialRequest], Any] = field(repr=False)
    revoked: bool = False


@dataclass(frozen=True)
class _PreparedCredential:
    route: CredentialRoute
    action: ActionEnvelope
    caller_digest: str


class SwarmCredentialBroker:
    """Host-owned credential vault and destination-pinned forwarding boundary.

    It does not give secrets to workloads or return transport bodies. The host
    adapter owns TLS, redirects (which must be refused), actual header/credential
    placement and runtime restrictions. Broad network rights do not imply
    credential rights; an authenticated HostCredentialUse is included in the
    exact core delegation review before any credential can reach the transport.
    """

    def __init__(
        self, service: SwarmDelegationService, *, operator: object, max_routes: int = 128
    ) -> None:
        if (
            type(service) is not SwarmDelegationService
            or operator is not service._operator
            or type(max_routes) is not int
            or not 1 <= max_routes <= 1024
        ):
            raise ValueError(
                "protected delegation service and bounded credential configuration required"
            )
        self._service, self._operator, self._limit = service, operator, max_routes
        self._routes: dict[CredentialRoute, _Route] = {}
        self._prepared: dict[str, _PreparedCredential] = {}
        self._audit: list[dict] = []
        self._lock = RLock()

    @staticmethod
    def _material(action: ActionEnvelope) -> str:
        value = action.as_dict()
        value["action_id"] = None
        return digest(value)

    def _destination(self, action: ActionEnvelope) -> NetworkCapability:
        review = self._service.assurance.ordin.review_action(action)
        capability = derive_runtime_capability_contract(review)
        request = derive_runtime_request_contract_v2(review)
        if review.adapter == "network.rest":
            # Preserve the exact REST packet instead of dropping the required
            # headers/body/scheme commitment from the capability projection.
            derive_rest_request_contract(review)
        unsupported = tuple(
            u
            for u in capability.unknowns
            if not (
                review.adapter == "network.rest"
                and u.reason_code == "runtime_rest_request_commitment_required"
                and u.domain == "network"
            )
        )
        if (
            unsupported
            or len(capability.network) != 1
            or capability.network[0].protocol not in {"rest", "graphql", "mcp", "json-rpc"}
            or capability.network[0].host is None
            or capability.network[0].port is None
        ):
            raise ValueError(
                "credential route requires one completely represented request destination"
            )
        network = capability.network[0]
        if network.protocol in {"graphql", "mcp", "json-rpc"} and not request.requests:
            raise ValueError("credential route requires exact protocol request semantics")
        return network

    @staticmethod
    def _private_action(
        action: ActionEnvelope, binding: CredentialBinding, credential: bytes
    ) -> None:
        # Run before core review/audit as well as before transport dispatch.
        headers = action.parameters.get("headers", {})
        if not isinstance(headers, dict) and hasattr(headers, "items"):
            headers = dict(headers)
        if isinstance(headers, dict) and any(
            str(k).lower() in {"authorization", "proxy-authorization", "cookie", "x-api-key"}
            for k in headers
        ):
            raise ValueError("credential values must remain outside action parameters")
        pending: list[Any] = [action.as_dict(), binding.as_dict()]
        while pending:
            value = pending.pop()
            try:
                if isinstance(value, str) and credential in value.encode("utf-8"):
                    raise ValueError("credential value appears in the proposed action or context")
            except UnicodeError:
                raise ValueError("invalid credential route text encoding") from None
            if isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())
            elif isinstance(value, (tuple, list)):
                pending.extend(value)

    def register(
        self,
        *,
        binding: CredentialBinding,
        action: ActionEnvelope,
        credential: bytes,
        forward: Callable[[PrivateCredentialRequest], Any],
        operator: object,
    ) -> CredentialRoute:
        if (
            operator is not self._operator
            or type(binding) is not CredentialBinding
            or type(action) is not ActionEnvelope
            or type(credential) is not bytes
            or not 1 <= len(credential) <= 16384
            or not callable(forward)
        ):
            raise ValueError(
                "protected credential route, private bytes and exact action template required"
            )
        with self._lock:
            if len(self._routes) >= self._limit:
                raise ValueError("credential route capacity reached")
            self._private_action(action, binding, credential)
            destination = self._destination(action)
            if (binding.host, binding.port) != (destination.host, destination.port):
                raise ValueError("credential binding differs from the exact request destination")
            handle = CredentialRoute(uuid4().hex)
            self._routes[handle] = _Route(
                binding, destination, self._material(action), credential, forward
            )
            return handle

    def _route(self, route: CredentialRoute, action: ActionEnvelope) -> _Route:
        if type(route) is not CredentialRoute or route not in self._routes:
            raise ValueError("unknown original credential route")
        row = self._routes[route]
        if (
            row.revoked
            or type(action) is not ActionEnvelope
            or self._material(action) != row.request_digest
        ):
            raise ValueError("credential route is revoked or the exact request changed")
        self._private_action(action, row.binding, row.secret)
        if self._destination(action) != row.destination:
            raise ValueError("credential route destination changed")
        return row

    def prepare(
        self,
        channel: AuthorityChannel,
        grant_ref: str,
        route: CredentialRoute,
        action: ActionEnvelope,
    ) -> RemoteReview:
        if type(action) is not ActionEnvelope:
            raise ValueError("typed exact credential action required")
        with self._lock, self._service._lock, self._service.issuer._lock:
            caller_packet = action.as_dict()
            # Host IDs avoid a secret-matching oracle on caller correlation text.
            captured = replace(ActionEnvelope.from_dict(caller_packet), action_id=uuid4().hex)
            row = self._route(route, captured)
            _, subject = self._service._grant(channel, grant_ref)
            if subject.source is None:
                raise ValueError("protected credential subject unavailable")
            receipt = subject.source.record_credential_use(
                captured,
                self._service.issuer.profile,
                receipt_id="credential-route-" + uuid4().hex,
                binding=row.binding,
            )
            review = self._service.review(channel, grant_ref, captured, credential_uses=(receipt,))
            if review.admission_id is not None:
                if len(self._prepared) >= self._service._limit:
                    self._service.cancel(channel, review.admission_id)
                    raise ValueError("credential admission capacity reached")
                self._prepared[review.admission_id] = _PreparedCredential(
                    route, captured, digest(caller_packet)
                )
            return review

    def dispatch(
        self, broker_channel: AuthorityChannel, admission_id: str, action: ActionEnvelope
    ) -> DelegationDispatch:
        with self._lock:
            prepared = self._prepared.pop(admission_id, None)
            if prepared is None:
                raise ValueError("unknown or consumed credential admission")
            try:
                if (
                    type(action) is not ActionEnvelope
                    or digest(action.as_dict()) != prepared.caller_digest
                ):
                    raise ValueError("credential caller action changed after preparation")
                row = self._route(prepared.route, prepared.action)
            except ValueError:
                with self._service._lock, self._service.issuer._lock:
                    pending = self._service._admissions.get(admission_id)
                    if pending is not None:
                        self._service._cancel(pending, "credential_route_refused")
                raise

            def forward(captured: ActionEnvelope) -> None:
                self._route(prepared.route, captured)
                # Ignore the transport result. A server that echoes a credential
                # cannot make it part of a public result, prompt or audit record.
                row.forward(PrivateCredentialRequest(captured, row.binding, row.secret))

            result = self._service.guarded_dispatch(
                broker_channel, admission_id, prepared.action, forward
            )
            if len(self._audit) < self._service._limit:
                self._audit.append(
                    _checked(
                        "swarm_credential_audit",
                        {
                            "schema_version": "ordin.swarm_credential_audit.v1",
                            "execution_authority": False,
                            "route_digest": digest(prepared.route.route_id),
                            "binding_digest": digest(row.binding.as_dict()),
                            "admission_digest": result.admission_digest,
                            "action_digest": result.action_digest,
                            "status": result.status,
                        },
                    )
                )
            return result

    def revoke(self, route: CredentialRoute, *, operator: object) -> None:
        if operator is not self._operator:
            raise ValueError("protected credential operator capability required")
        with self._lock, self._service._lock, self._service.issuer._lock:
            if type(route) is not CredentialRoute or route not in self._routes:
                raise ValueError("unknown original credential route")
            self._routes[route].revoked = True
            for reference, selected in tuple(self._prepared.items()):
                if selected.route is route:
                    self._prepared.pop(reference, None)
                    pending = self._service._admissions.get(reference)
                    if pending is not None:
                        self._service._cancel(pending, "credential_route_revoked")

    def audit(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(dict(v) for v in self._audit)
