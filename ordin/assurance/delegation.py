"""Pure authority containment plus optional host-owned grant lifecycle.

No object in this module mints credentials or enforces OS permissions. Agent
arguments and JSON grant artifacts cannot issue or restore current authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import cached_property
from typing import Callable, Mapping
import secrets
import threading
import time

from ordin._runtime_host import host_matches
from ordin.runtime_boundary import CapabilityVerificationResult, RuntimeCapabilityBoundary
from ordin.runtime_contract import NetworkCapability, RuntimeCapabilityContract
from ordin.runtime_requests_v2 import (
    NetworkAuthorityGrant,
    RequestAuthority,
    RuntimeRequestBoundaryV2,
    RuntimeRequestContractV2,
)
from ordin.runtime_requests import RequestVerificationResult

from ._json import digest, freeze, thaw, validate
from .host import HostEvidenceSource
from .models import ApprovedSecurityProfile, DelegationGrant, JsonRecord
from .requests import verify_assurance_capability, verify_assurance_request_authority

DOMAINS = (
    "filesystem",
    "network",
    "tools",
    "process",
    "privilege",
    "credentials",
    "requests",
    "approval",
)


@dataclass(frozen=True)
class DelegationAuthority:
    """Immutable data describing rights, not an issued or enforced grant."""

    capability: RuntimeCapabilityBoundary
    requests: tuple[RequestAuthority, ...] = ()
    network_grants: tuple[NetworkAuthorityGrant, ...] = ()
    requires_approval: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.capability, RuntimeCapabilityBoundary)
            or type(self.requires_approval) is not bool
        ):
            raise ValueError("delegation authority requires typed maxima and approval state")
        for name, model in (
            ("requests", RequestAuthority),
            ("network_grants", NetworkAuthorityGrant),
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, (tuple, list))
                or len(value) > 128
                or any(not isinstance(v, model) for v in value)
            ):
                raise ValueError("delegation request rights must be bounded typed data")
            object.__setattr__(self, name, tuple(value))
        freeze(self.as_dict())

    def as_dict(self) -> dict:
        return {
            "capability": self.capability.as_dict(),
            "requests": [v.as_dict() for v in self.requests],
            "network_grants": [v.as_dict() for v in self.network_grants],
            "requires_approval": self.requires_approval,
        }

    @cached_property
    def digest(self) -> str:
        return digest("delegation_authority", self.as_dict())

    @classmethod
    def from_dict(cls, payload: Mapping) -> DelegationAuthority:
        if not isinstance(payload, Mapping) or set(payload) != {
            "capability",
            "requests",
            "network_grants",
            "requires_approval",
        }:
            raise ValueError("invalid delegation authority data")
        parsed = thaw(freeze(payload))
        return cls(
            RuntimeCapabilityBoundary.from_dict(parsed["capability"]),
            tuple(RequestAuthority(**v) for v in parsed["requests"]),
            tuple(NetworkAuthorityGrant(**v) for v in parsed["network_grants"]),
            parsed["requires_approval"],
        )


@dataclass(frozen=True)
class DelegationVerification(JsonRecord):
    SCHEMA = "assurance_delegation_verification"
    result: str
    reason_codes: tuple[str, ...]
    child_authority_digest: str
    parent_authority_digest: str
    operator_authority_digest: str
    task_authority_digest: str
    coverage: Mapping[str, bool]
    proof_gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.result == "within_boundary" and (
            not all(self.coverage.values()) or self.proof_gaps
        ):
            raise ValueError("delegation containment requires complete supported coverage")

    @property
    def ok(self) -> bool:
        return self.result == "within_boundary"


def _requirements(authority: DelegationAuthority) -> RuntimeCapabilityContract:
    cap = authority.capability
    networks = list(cap.network)
    for grant in authority.network_grants:
        if "*" in grant.host_pattern:
            raise ValueError("child wildcard network authority cannot be represented exactly")
        networks.append(
            NetworkCapability(
                grant.host_pattern,
                grant.port,
                grant.protocol,
                grant.access,
                grant.methods,
                grant.paths,
            )
        )
    return RuntimeCapabilityContract(
        "delegation-proposal",
        authority.digest,
        "allow",
        "low",
        filesystem=cap.filesystem,
        network=tuple(networks),
        tools=cap.tools,
        process=cap.process,
        privilege=cap.privilege,
        credentials=cap.credentials,
        source={
            "kind": "delegation",
            "operation": "subset",
            "adapter": None,
            "effects": [],
            "provenance_digest": None,
        },
    )


def verify_delegation_subset(
    child: DelegationAuthority,
    parent: DelegationAuthority,
    operator: DelegationAuthority,
    task: DelegationAuthority,
) -> DelegationVerification:
    """Prove the requested child is inside all three maxima, without broadening it.

    The effective child is the verified proposal, a subset of the intersection.
    Unsupported wildcard child languages/any-executable rights or filesystem
    semantics are refused, never stripped. Literal requests, directory scopes,
    tools, process/privilege/credential and approval rights are all retained.
    """
    if any(not isinstance(v, DelegationAuthority) for v in (child, parent, operator, task)):
        raise ValueError("delegation subset requires four typed authority specifications")
    coverage = dict.fromkeys(DOMAINS, True)
    states, reasons, gaps = [], [], []
    if child.capability.allow_any_executable:
        states.append("unsupported")
        coverage["process"] = False
        reasons.append("delegation.any_executable_unsupported")
    if any(c.scope == "prefix" for c in child.capability.filesystem) and (
        child.capability.filesystem_semantics != "lexical_prefix"
        or not child.capability.runtime_filesystem_guarantees
    ):
        states.append("unsupported")
        coverage["filesystem"] = False
        reasons.append("delegation.child_filesystem_semantics_unsupported")
    try:
        contract = _requirements(child)
    except ValueError:
        contract = None
        states.append("unsupported")
        coverage["network"] = coverage["requests"] = False
        reasons.append("delegation.child_requirements_unrepresentable")
    for name, maximum in (("parent", parent), ("operator", operator), ("task", task)):
        check: CapabilityVerificationResult | RequestVerificationResult
        if maximum.requires_approval and not child.requires_approval:
            states.append("exceeds_boundary")
            reasons.append("delegation." + name + "_approval_removed")
        if contract is None:
            continue
        if child.requests or any(
            n.protocol in {"graphql", "mcp", "json-rpc"} for n in contract.network
        ):
            check = verify_assurance_request_authority(
                RuntimeRequestContractV2(contract, child.requests),
                RuntimeRequestBoundaryV2(
                    maximum.capability, maximum.requests, maximum.network_grants
                ),
            )
        else:
            networks = list(maximum.capability.network)
            for candidate in contract.network:
                networks.extend(
                    NetworkCapability(
                        candidate.host,
                        grant.port,
                        grant.protocol,
                        grant.access,
                        grant.methods,
                        grant.paths,
                    )
                    for grant in maximum.network_grants
                    if grant.port == candidate.port
                    and host_matches(grant.host_pattern, candidate.host)
                )
            check = verify_assurance_capability(
                contract, replace(maximum.capability, network=tuple(networks))
            )
        states.append(check.result)
        if not check.ok:
            reasons.append("delegation." + name + "_" + check.result)
            reasons.extend(check.unsupported_fields)
        for domain, complete in check.coverage.items():
            if not complete:
                coverage[domain] = False
    status = next(
        (v for v in ("exceeds_boundary", "unsupported", "inconclusive") if v in states),
        "within_boundary",
    )
    if status in {"unsupported", "inconclusive"} or not all(coverage.values()):
        gaps.append(
            "At least one intended authority domain cannot be proven contained; no grant may be issued."
        )
    return DelegationVerification(
        status,
        tuple(dict.fromkeys(reasons))[:64],
        child.digest,
        parent.digest,
        operator.digest,
        task.digest,
        coverage,
        tuple(gaps),
    )


@dataclass(frozen=True)
class _GrantSeal:
    issuer_key: str
    payload_digest: str


@dataclass(frozen=True)
class IssuedDelegation:
    """Private issuer handle; a serialized grant is only an advisory artifact."""

    record: DelegationGrant
    authority: DelegationAuthority
    host_source_key: str
    issuer_key: str
    _seal: _GrantSeal | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.record, DelegationGrant)
            or not isinstance(self.authority, DelegationAuthority)
            or self.record.status != "issued"
            or self.record.contract_digest != self.authority.digest
            or not isinstance(self._seal, _GrantSeal)
            or self._seal.issuer_key != self.issuer_key
            or self._seal.payload_digest != self.digest
        ):
            raise ValueError("delegation requires a current private host-issued handle")

    def as_dict(self) -> dict:
        return {
            "record": self.record.as_dict(),
            "authority_digest": self.authority.digest,
            "host_source_key": self.host_source_key,
            "issuer_key": self.issuer_key,
        }

    @cached_property
    def digest(self) -> str:
        return digest("issued_delegation", self.as_dict())

    @classmethod
    def from_dict(cls, payload: Mapping) -> IssuedDelegation:
        raise ValueError("JSON cannot issue or restore current delegation authority")


@dataclass(frozen=True)
class DelegationLimits:
    maximum_grants: int = 128
    active_children: int = 16
    in_flight_operations: int = 8
    actions_per_grant: int = 256

    def __post_init__(self) -> None:
        for name, limit in (
            ("maximum_grants", 128),
            ("active_children", 128),
            ("in_flight_operations", 128),
            ("actions_per_grant", 4096),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= limit:
                raise ValueError("invalid bounded delegation quota")


class DelegationIssuer:
    """Protected host service; callers supply actual operator/task maxima.

    The clock, identity, active policy, grant state and quota counters are host
    owned. This service does not create credentials, change OS permissions or
    prove that a child process is physically constrained to the declared rights.
    """

    def __init__(
        self,
        source: HostEvidenceSource,
        profile: ApprovedSecurityProfile,
        operator_maximum: DelegationAuthority,
        task_maximum: DelegationAuthority,
        *,
        clock: Callable[[], int] | None = None,
        limits: DelegationLimits | None = None,
    ):
        if (
            not isinstance(source, HostEvidenceSource)
            or not isinstance(profile, ApprovedSecurityProfile)
            or not isinstance(operator_maximum, DelegationAuthority)
            or not isinstance(task_maximum, DelegationAuthority)
        ):
            raise ValueError("issuer requires protected host/profile and typed maxima")
        source._check_profile(profile)
        if clock is not None and not callable(clock):
            raise ValueError("issuer clock must be host owned")
        self.source, self.profile = source, profile
        self.operator_maximum, self.task_maximum = operator_maximum, task_maximum
        self.limits = limits or DelegationLimits()
        if not isinstance(self.limits, DelegationLimits):
            raise ValueError("issuer quotas must be typed host configuration")
        self._clock = clock or (lambda: int(time.time()))
        self._last_now = -1
        self._issuer_key = digest(
            "delegation_issuer", [source.key, profile.digest, secrets.token_hex(32)]
        )
        self._configuration = (
            source.key,
            profile.digest,
            operator_maximum.digest,
            task_maximum.digest,
            self.limits,
        )
        self._issued: dict[str, IssuedDelegation] = {}
        self._revoked: dict[str, int] = {}
        self._used: dict[str, int] = {}
        self._pending: dict[str, tuple[str, str, str, int]] = {}
        self._generation = 0
        self._lock = threading.RLock()

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or not 0 <= now < 2**53 or now < self._last_now:
            raise ValueError("delegation clock is invalid or moved backward")
        self._last_now = now
        return now

    def _require_configuration(self) -> None:
        if self._configuration != (
            self.source.key,
            self.profile.digest,
            self.operator_maximum.digest,
            self.task_maximum.digest,
            self.limits,
        ):
            raise ValueError("delegation host configuration changed; create a fresh issuer")

    def _require_current(
        self, handle: IssuedDelegation, source: HostEvidenceSource, now: int
    ) -> None:
        self._require_configuration()
        if (
            not isinstance(handle, IssuedDelegation)
            or not isinstance(source, HostEvidenceSource)
            or handle.issuer_key != self._issuer_key
            or self._issued.get(handle.record.grant_id) is not handle
        ):
            raise ValueError("delegation is not issued by this host")
        if (
            handle.host_source_key != source.key
            or source.repository != self.source.repository
            or source.runtime_policy_digest != self.source.runtime_policy_digest
            or source.selection_digest != self.source.selection_digest
        ):
            raise ValueError("delegation principal/session/epoch/policy scope changed")
        if (source.principal, source.session_digest, source.epoch) != (
            handle.record.child_principal,
            handle.record.session_digest,
            handle.record.epoch,
        ):
            raise ValueError("delegation identity differs from current host principal")
        current = handle
        seen: set[str] = set()
        while True:
            identifier = current.record.grant_id
            if identifier in seen or len(seen) >= self.limits.maximum_grants:
                raise ValueError("delegation cycle or ancestry limit")
            seen.add(identifier)
            if (
                identifier in self._revoked
                or not current.record.issued_at <= now < current.record.expires_at
                or current.record.profile_digest != self.profile.digest
                or current.record.parent_policy_digest != self.source.runtime_policy_digest
            ):
                raise ValueError("delegation or ancestor is expired/revoked/stale")
            parent = current.record.parent_grant_id
            if parent is None:
                break
            if parent not in self._issued:
                raise ValueError("delegation parent is ambiguous or absent")
            current = self._issued[parent]

    def require_current(self, handle: IssuedDelegation, source: HostEvidenceSource) -> None:
        with self._lock:
            self._require_current(handle, source, self._now())

    def _issue(self, *, grant_id, parent, child_source, authority, expires_at, maximum_depth, now):
        self._require_configuration()
        validate(
            "assurance_authority_ref",
            {"authority_id": grant_id, "boundary_digest": authority.digest},
        )
        if grant_id in self._issued or len(self._issued) >= self.limits.maximum_grants:
            raise ValueError("duplicate delegation ID or grant quota exhausted")
        child_source._check_profile(self.profile)
        if child_source.repository != self.source.repository:
            raise ValueError("delegation child repository differs")
        if (
            type(expires_at) is not int
            or not now < expires_at < 2**53
            or type(maximum_depth) is not int
            or not 0 <= maximum_depth <= 16
        ):
            raise ValueError("invalid delegation expiry or depth limit")
        if parent is not None and child_source.principal in {
            parent.record.child_principal,
            parent.record.parent_principal,
        }:
            raise ValueError("self-delegation or principal cycle")
        if any(
            handle.record.child_principal == child_source.principal
            and handle.record.grant_id not in self._revoked
            and now < handle.record.expires_at
            for handle in self._issued.values()
        ):
            raise ValueError("principal already has a current grant; parent is ambiguous")
        if parent is not None:
            if (
                expires_at > parent.record.expires_at
                or maximum_depth > parent.record.maximum_delegation_depth
            ):
                raise ValueError("child lifetime/depth exceeds parent")
            depth = parent.record.depth + 1
            if depth > maximum_depth:
                raise ValueError("delegation depth exhausted")
            ancestor = parent
            while True:
                if child_source.principal in {
                    ancestor.record.parent_principal,
                    ancestor.record.child_principal,
                }:
                    raise ValueError("self-delegation or principal cycle")
                if ancestor.record.parent_grant_id is None:
                    break
                ancestor = self._issued[ancestor.record.parent_grant_id]
            children = sum(
                handle.record.parent_grant_id == parent.record.grant_id
                and handle.record.grant_id not in self._revoked
                and now < handle.record.expires_at
                for handle in self._issued.values()
            )
            if children >= self.limits.active_children:
                raise ValueError("active-child quota exhausted")
        else:
            depth = 0
            if child_source.principal == self.profile.operator_identity:
                raise ValueError("operator identity cannot be delegated to itself")
        parent_authority = parent.authority if parent is not None else self.operator_maximum
        verified = verify_delegation_subset(
            authority, parent_authority, self.operator_maximum, self.task_maximum
        )
        if not verified.ok:
            raise ValueError("delegation authority is outside a maximum or unsupported")
        record = DelegationGrant(
            grant_id,
            parent.record.child_principal if parent else self.profile.operator_identity,
            child_source.principal,
            self.profile.operator_identity,
            "protected-host:" + self._issuer_key[:24],
            child_source.session_digest,
            child_source.epoch,
            now,
            expires_at,
            self.source.runtime_policy_digest,
            self.profile.digest,
            authority.digest,
            parent_grant_id=parent.record.grant_id if parent else None,
            capability_refs=(authority.digest,),
            maximum_delegation_depth=maximum_depth,
            depth=depth,
            status="issued",
        )
        values = dict(
            record=record,
            authority=authority,
            host_source_key=child_source.key,
            issuer_key=self._issuer_key,
        )
        preview = object.__new__(IssuedDelegation)
        for key, value in values.items():
            object.__setattr__(preview, key, value)
        handle = IssuedDelegation(**values, _seal=_GrantSeal(self._issuer_key, preview.digest))
        self._issued[grant_id] = handle
        self._used[grant_id] = 0
        return handle

    def authorize_root(
        self,
        authority: DelegationAuthority,
        *,
        grant_id: str,
        expires_at: int,
        maximum_delegation_depth: int = 4,
    ) -> IssuedDelegation:
        """Host authorization of the root principal under operator/task maxima."""
        with self._lock:
            if not isinstance(authority, DelegationAuthority):
                raise ValueError("root authorization requires typed authority")
            return self._issue(
                grant_id=grant_id,
                parent=None,
                child_source=self.source,
                authority=authority,
                expires_at=expires_at,
                maximum_depth=maximum_delegation_depth,
                now=self._now(),
            )

    def issue_child(
        self,
        parent: IssuedDelegation,
        child_source: HostEvidenceSource,
        authority: DelegationAuthority,
        *,
        grant_id: str,
        expires_at: int,
        maximum_delegation_depth: int | None = None,
    ) -> IssuedDelegation:
        with self._lock:
            now = self._now()
            if (
                not isinstance(parent, IssuedDelegation)
                or not isinstance(child_source, HostEvidenceSource)
                or not isinstance(authority, DelegationAuthority)
            ):
                raise ValueError("child issuance requires typed host identity/authority")
            parent_source = self.source if parent.record.parent_grant_id is None else None
            # Current authority is checked against its original, immutable host
            # scope. The application separately supplies actual child process identity.
            if parent_source is None:
                parent_source = self._source_for(parent)
            self._require_current(parent, parent_source, now)
            return self._issue(
                grant_id=grant_id,
                parent=parent,
                child_source=child_source,
                authority=authority,
                expires_at=expires_at,
                maximum_depth=parent.record.maximum_delegation_depth
                if maximum_delegation_depth is None
                else maximum_delegation_depth,
                now=now,
            )

    def _source_for(self, handle: IssuedDelegation) -> HostEvidenceSource:
        return HostEvidenceSource(
            handle.record.child_principal,
            self.source.repository,
            handle.record.session_digest,
            handle.record.epoch,
            self.source.runtime_policy_digest,
            self.source.selection_digest,
        )

    def revoke(self, handle: IssuedDelegation) -> tuple[str, ...]:
        with self._lock:
            if (
                not isinstance(handle, IssuedDelegation)
                or self._issued.get(handle.record.grant_id) is not handle
            ):
                raise ValueError("revocation requires a host-issued handle")
            now = self._now()
            affected = {handle.record.grant_id}
            changed = True
            while changed:
                changed = False
                for identifier, grant in self._issued.items():
                    if grant.record.parent_grant_id in affected and identifier not in affected:
                        affected.add(identifier)
                        changed = True
            for identifier in affected:
                self._revoked[identifier] = now
            self._generation += 1
            # The generation change invalidates every cached use. Clear all
            # pending slots so unrelated children can obtain a fresh review.
            self._pending.clear()
            return tuple(sorted(affected))

    def invalidate_policy(self) -> None:
        """Host calls before changing active policy/profile/session generation."""
        with self._lock:
            now = self._now()
            self._revoked.update({identifier: now for identifier in self._issued})
            self._pending.clear()
            self._generation += 1

    def _check_operation(
        self,
        contract: RuntimeCapabilityContract | RuntimeRequestContractV2,
        handle: IssuedDelegation,
    ):
        if isinstance(contract, RuntimeRequestContractV2) and contract.requests:
            return verify_assurance_request_authority(
                contract,
                RuntimeRequestBoundaryV2(
                    handle.authority.capability,
                    handle.authority.requests,
                    handle.authority.network_grants,
                ),
            )
        cap = contract.capability if isinstance(contract, RuntimeRequestContractV2) else contract
        networks = list(handle.authority.capability.network)
        for candidate in cap.network:
            networks.extend(
                NetworkCapability(
                    candidate.host,
                    grant.port,
                    grant.protocol,
                    grant.access,
                    grant.methods,
                    grant.paths,
                )
                for grant in handle.authority.network_grants
                if grant.port == candidate.port and host_matches(grant.host_pattern, candidate.host)
            )
        return verify_assurance_capability(
            cap, replace(handle.authority.capability, network=tuple(networks))
        )

    def _reserve_operation(
        self,
        handle: IssuedDelegation,
        source: HostEvidenceSource,
        action_digest: str,
        contract: RuntimeCapabilityContract | RuntimeRequestContractV2,
    ) -> str:
        with self._lock:
            self._require_current(handle, source, self._now())
            if not self._check_operation(contract, handle).ok:
                raise ValueError("delegated operation exceeds current grant or is unsupported")
            active = sum(v[0] == handle.record.grant_id for v in self._pending.values())
            if (
                active >= self.limits.in_flight_operations
                or self._used[handle.record.grant_id] + active >= self.limits.actions_per_grant
            ):
                raise ValueError("delegated operation quota exhausted")
            ticket = secrets.token_hex(32)
            self._pending[ticket] = (
                handle.record.grant_id,
                action_digest,
                contract.digest,
                self._generation,
            )
            return ticket

    def cancel_operation(self, ticket: str) -> None:
        with self._lock:
            self._pending.pop(ticket, None)

    def _commit_operation(
        self,
        handle: IssuedDelegation,
        source: HostEvidenceSource,
        ticket: str,
        action_digest: str,
        contract_digest: str,
        *,
        binding_check: Callable[[], bool],
    ) -> bool:
        with self._lock:
            try:
                self._require_current(handle, source, self._now())
            except ValueError:
                self._pending.pop(ticket, None)
                return False
            expected = (handle.record.grant_id, action_digest, contract_digest, self._generation)
            if not binding_check():
                self._pending.pop(ticket, None)
                return False
            if (
                self._pending.pop(ticket, None) != expected
                or self._used[handle.record.grant_id] >= self.limits.actions_per_grant
            ):
                return False
            self._used[handle.record.grant_id] += 1
            return True
