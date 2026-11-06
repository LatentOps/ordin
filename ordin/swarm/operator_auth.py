"""Finite RBAC over original mutually authenticated operator channels.

The deployment owner keeps operator credentials outside workload/model access.
Certificate possession authenticates that enrolled operator credential; this
module does not claim biometric identity or human presence from TLS alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from uuid import uuid4

from ordin._runtime_json import digest

from .models import identifier
from .workload_auth import AuthorityChannel, WorkloadAuthenticator


@dataclass(frozen=True, slots=True, eq=False)
class HumanOperatorChannel:
    channel_id: str

    @classmethod
    def from_dict(cls, value):
        raise ValueError("JSON cannot authenticate a human operator")


@dataclass(frozen=True, slots=True)
class HumanOperator:
    enrollment_id: str
    principal_id: str
    certificate_digest: str
    roles: tuple[str, ...]
    task_ids: tuple[str, ...]

    @property
    def digest(self):
        return digest(
            [
                self.enrollment_id,
                self.principal_id,
                self.certificate_digest,
                self.roles,
                self.task_ids,
            ]
        )


class SwarmOperatorDirectory:
    """Protected bootstrap authority plus real TLS authentication, not caller labels."""

    def __init__(
        self,
        authenticator: WorkloadAuthenticator,
        *,
        operator: object,
        roles: tuple[str, ...] = ("approve", "deny", "break_glass", "recover", "policy_admin"),
        maximum_members: int = 128,
        maximum_channels: int = 256,
    ):
        if type(authenticator) is not WorkloadAuthenticator:
            raise ValueError("original operator TLS authenticator required")
        authenticator._operator_check(operator)
        self._names(roles, 16)
        if (
            type(maximum_members) is not int
            or not 1 <= maximum_members <= 256
            or type(maximum_channels) is not int
            or not 1 <= maximum_channels <= 512
        ):
            raise ValueError("invalid bounded human operator capacity")
        self.authenticator, self._operator = authenticator, operator
        self.roles, self._member_limit, self._channel_limit = (
            roles,
            maximum_members,
            maximum_channels,
        )
        self._nonce, self._generation = uuid4().hex, 0
        self._members: dict[str, HumanOperator] = {}
        self._channels: dict[HumanOperatorChannel, tuple[AuthorityChannel, int, str]] = {}
        self._lock = RLock()

    @staticmethod
    def _names(values, maximum):
        if (
            type(values) is not tuple
            or not 1 <= len(values) <= maximum
            or any(type(value) is not str for value in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError("finite distinct human operator roles/tasks required")
        for value in values:
            identifier(value, "operator_scope")
            if "*" in value:
                raise ValueError("operator scope cannot contain a wildcard")

    def _operator_check(self, operator):
        if operator is not self._operator:
            raise ValueError("original protected operator directory control required")
        self.authenticator._operator_check(operator)

    @property
    def binding_digest(self):
        with self._lock, self.authenticator._lock:
            if self.authenticator._configuration() != self.authenticator._tls_binding:
                raise ValueError("operator TLS trust configuration changed")
            return digest(
                [
                    self._nonce,
                    self._generation,
                    self.roles,
                    self.authenticator._generation,
                    sorted(self.authenticator._revoked),
                    sorted(row.digest for row in self._members.values()),
                ]
            )

    def enroll(
        self,
        *,
        principal_id: str,
        certificate_digest: str,
        roles: tuple[str, ...],
        task_ids: tuple[str, ...],
        operator: object,
    ) -> HumanOperator:
        self._operator_check(operator)
        self._names(roles, 16)
        self._names(task_ids, 64)
        identifier(principal_id, "operator_principal_id")
        if not set(roles) <= set(self.roles):
            raise ValueError("operator role exceeds configured maximum")
        with self._lock:
            if len(self._members) >= self._member_limit or any(
                row.principal_id == principal_id for row in self._members.values()
            ):
                raise ValueError("duplicate human principal or operator capacity reached")
            enrollment = self.authenticator.enroll_operator(
                principal_id=principal_id, certificate_digest=certificate_digest, operator=operator
            )
            row = HumanOperator(enrollment, principal_id, certificate_digest, roles, task_ids)
            self._members[enrollment] = row
            self._generation += 1
            self._channels.clear()
            return row

    def authenticate(self, connection) -> HumanOperatorChannel:
        authority = self.authenticator.authenticate_operator(connection)
        enrolled = self.authenticator.require_operator(authority)
        with self._lock:
            if enrolled.enrollment_id not in self._members:
                raise ValueError("operator credential has no protected RBAC enrollment")
            with self.authenticator._lock:
                self._channels = {
                    channel: row
                    for channel, row in self._channels.items()
                    if row[1] == self._generation and row[0] in self.authenticator._channels
                }
                if authority not in self.authenticator._channels:
                    raise ValueError("operator TLS channel changed during RBAC authentication")
            for channel, (original, generation, identity) in self._channels.items():
                if (
                    original is authority
                    and generation == self._generation
                    and identity == enrolled.enrollment_id
                ):
                    return channel
            if len(self._channels) >= self._channel_limit:
                raise ValueError("human operator channel capacity reached")
            channel = HumanOperatorChannel(uuid4().hex)
            self._channels[channel] = (authority, self._generation, enrolled.enrollment_id)
            return channel

    def member(self, enrollment_id: str, *, task_id: str, roles: tuple[str, ...]) -> HumanOperator:
        identifier(enrollment_id, "operator_enrollment")
        identifier(task_id, "operator_task_id")
        self._names(roles, 16)
        with self._lock:
            self.binding_digest
            row = self._members.get(enrollment_id)
            if row is None:
                raise ValueError("operator RBAC enrollment unavailable")
            actual = self.authenticator.enrollment(enrollment_id)
            if (
                actual.role != "operator"
                or actual.host_id != row.principal_id
                or actual.certificate_digest != row.certificate_digest
                or task_id not in row.task_ids
                or not set(roles) <= set(row.roles)
            ):
                raise ValueError("operator credential does not cover current task/roles")
            return row

    def require(
        self, channel: HumanOperatorChannel, *, task_id: str, roles: tuple[str, ...]
    ) -> HumanOperator:
        with self._lock:
            value = self._channels.get(channel) if type(channel) is HumanOperatorChannel else None
            if value is None or value[1] != self._generation:
                raise ValueError("original current authenticated human channel required")
        actual = self.authenticator.require_operator(value[0])
        with self._lock:
            if self._channels.get(channel) != value or value[1] != self._generation:
                raise ValueError("operator RBAC changed during authentication")
            if actual.enrollment_id != value[2]:
                raise ValueError("operator channel identity changed")
            return self.member(actual.enrollment_id, task_id=task_id, roles=roles)

    def close(self, channel: HumanOperatorChannel):
        with self._lock:
            value = (
                self._channels.pop(channel, None) if type(channel) is HumanOperatorChannel else None
            )
            if value is None:
                raise ValueError("original human operator channel required")
            self.authenticator.close(value[0])

    def revoke(self, enrollment_id: str, *, operator: object):
        self._operator_check(operator)
        with self._lock:
            if enrollment_id not in self._members:
                raise ValueError("original operator enrollment required")
            self.authenticator.revoke_enrollment(enrollment_id, operator=operator)
            self._generation += 1
            self._channels.clear()
