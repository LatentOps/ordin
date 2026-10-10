"""Exact REST request data beside unchanged runtime request v1/v2 contracts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from functools import cached_property
from urllib.parse import urlsplit

from ordin._rest_semantics import RestSemantics, prepare_rest, READ_METHODS
from ordin._request_commitment import REQUEST_COMMITMENT_ALGORITHM
from ordin.runtime_contract import (
    RuntimeCapabilityContract,
    NetworkCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.runtime_requests import RequestVerificationResult

from ._json import digest, validate
from .models import JsonRecord

EXACT_REQUIREMENT = "runtime_rest_request_commitment_required"


@dataclass(frozen=True)
class RestRequestAuthority(JsonRecord):
    SCHEMA = "assurance_rest_authority"
    scheme: str
    host: str
    port: int
    path: str
    method: str
    access: str
    body_present: bool
    commitment: str
    algorithm: str = REQUEST_COMMITMENT_ALGORITHM

    def __post_init__(self):
        super().__post_init__()
        from ordin.runtime_requests import request_endpoint

        address = f"[{self.host}]" if ":" in self.host else self.host
        if request_endpoint(f"{self.scheme}://{address}:{self.port}{self.path}") != (
            self.host,
            self.port,
            self.path,
        ):
            raise ValueError("REST authority endpoint is unsupported")
        expected = "read" if self.method in READ_METHODS and not self.body_present else "write"
        if self.access != expected:
            raise ValueError("REST authority access differs from exact request shape")

    @classmethod
    def from_parameters(cls, parameters):
        endpoint, method, commitment, reading = prepare_rest(parameters)
        return cls(
            scheme=urlsplit(parameters["url"]).scheme,
            host=endpoint[0],
            port=endpoint[1],
            path=endpoint[2],
            method=method,
            access="read" if reading else "write",
            body_present="body" in parameters,
            commitment=commitment,
        )


@dataclass(frozen=True)
class RestRequestBoundary:
    capability: RuntimeCapabilityBoundary
    requests: tuple[RestRequestAuthority, ...]

    def __post_init__(self):
        if (
            not isinstance(self.capability, RuntimeCapabilityBoundary)
            or not isinstance(self.requests, (tuple, list))
            or len(self.requests) > 128
            or any(not isinstance(request, RestRequestAuthority) for request in self.requests)
        ):
            raise ValueError("REST maximum requires bounded typed request declarations")
        object.__setattr__(self, "requests", tuple(self.requests))
        validate("assurance_rest_boundary", self.as_dict())

    def as_dict(self):
        return {
            "schema_version": "ordin.assurance_rest_boundary.v1",
            "capability": self.capability.as_dict(),
            "requests": [r.as_dict() for r in self.requests],
        }

    @cached_property
    def digest(self):
        return digest("rest_boundary", self.as_dict())

    @classmethod
    def from_dict(cls, value):
        validate("assurance_rest_boundary", value)
        return cls(
            RuntimeCapabilityBoundary.from_dict(value["capability"]),
            tuple(RestRequestAuthority.from_dict(r) for r in value["requests"]),
        )


@dataclass(frozen=True)
class RestRequestContract:
    capability: RuntimeCapabilityContract
    request: RestRequestAuthority

    def __post_init__(self):
        if not isinstance(self.capability, RuntimeCapabilityContract) or not isinstance(
            self.request, RestRequestAuthority
        ):
            raise ValueError("REST contract requires exact typed action/request data")
        required = [
            u
            for u in self.capability.unknowns
            if u.domain == "network" and u.reason_code == EXACT_REQUIREMENT
        ]
        expected = NetworkCapability(
            self.request.host,
            self.request.port,
            "rest",
            self.request.access,
            (self.request.method,),
            (self.request.path,),
        )
        if (
            len(required) != 1
            or self.capability.network != (expected,)
            or self.capability.source.get("adapter") != "network.rest"
            or self.capability.source.get("kind") != "network"
            or self.capability.source.get("operation") != "http.request"
            or tuple(self.capability.source.get("effects", ()))
            != ("network.download" if self.request.access == "read" else "network.upload",)
        ):
            raise ValueError("REST core capability differs from request commitment")
        validate("assurance_rest_contract", self.as_dict())

    def as_dict(self):
        return {
            "schema_version": "ordin.assurance_rest_contract.v1",
            "capability": self.capability.as_dict(),
            "request": self.request.as_dict(),
        }

    @cached_property
    def digest(self):
        return digest("rest_contract", self.as_dict())

    @classmethod
    def from_dict(cls, value):
        validate("assurance_rest_contract", value)
        return cls(
            RuntimeCapabilityContract.from_dict(value["capability"]),
            RestRequestAuthority.from_dict(value["request"]),
        )


def derive_rest_request_contract(review, *, capability=None):
    if review.adapter != "network.rest":
        raise ValueError("REST derivation needs host-selected deterministic semantics")
    selected = RestRequestAuthority.from_parameters(review.action.parameters)
    original = derive_runtime_capability_contract(review)
    if capability is not None:
        if (
            not isinstance(capability, RuntimeCapabilityContract)
            or replace(original, credentials=capability.credentials, contract_id="") != capability
        ):
            raise ValueError("REST capability differs from reviewed/host-bound requirements")
        original = capability
    return RestRequestContract(original, selected)


def verify_rest_request_authority(contract, boundary):
    if not isinstance(contract, RestRequestContract) or not isinstance(
        boundary, RestRequestBoundary
    ):
        raise ValueError("REST verification needs exact typed contract and maximum")
    # The original capability retains this explicit unrepresentable requirement.
    # Only this composite verifier accounts for it via the complete REST packet;
    # the projected question is never returned as a grant or execution contract.
    question = replace(
        contract.capability,
        unknowns=tuple(
            u
            for u in contract.capability.unknowns
            if not (u.domain == "network" and u.reason_code == EXACT_REQUIREMENT)
        ),
        contract_id="",
    )
    core = verify_runtime_capability(question, boundary.capability)
    if not core.ok:
        return RequestVerificationResult(
            core.result,
            core.reason_code,
            contract.digest,
            boundary.digest,
            {**dict(core.coverage), "requests": False},
            unsupported_fields=core.unsupported_fields,
        )
    matched = contract.request in boundary.requests
    return RequestVerificationResult(
        "within_boundary" if matched else "exceeds_boundary",
        "assurance.rest_request_within" if matched else "assurance.rest_request_commitment_exceeds",
        contract.digest,
        boundary.digest,
        {**dict(core.coverage), "requests": matched},
        counterexample=None if matched else {"request_digest": contract.request.digest},
    )
