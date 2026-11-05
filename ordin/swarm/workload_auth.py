"""Pinned mutual-TLS workload channels; names or JSON claims do not authenticate."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ssl
from threading import RLock
from typing import Callable
from uuid import uuid4

from ordin._runtime_json import digest
from ordin.assurance.host import HostEvidenceSource
from ordin.session import SessionIdentity

from .events import _hex
from .identity import HostChannel
from .models import SwarmContext, identifier, timestamp
from .registry import AgentRegistry


@dataclass(frozen=True, eq=False, slots=True)
class AuthorityChannel:
    channel_id: str


@dataclass(frozen=True, slots=True)
class WorkloadEnrollment:
    enrollment_id: str
    host_id: str
    certificate_digest: str
    role: str
    context: SwarmContext | None = field(repr=False)
    source: HostEvidenceSource | None = field(repr=False)
    registry_channel: HostChannel | None = field(repr=False)
    adapter: object = field(repr=False)
    source_key: str | None = field(repr=False)
    runtime_identity: SessionIdentity | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _TLSChannel:
    enrollment: WorkloadEnrollment
    socket: ssl.SSLSocket
    expires_at: float
    generation: int


class WorkloadAuthenticator:
    """Protected enrollment plus actual verified server-side SSL sockets.

    The operator binds each distinct workload certificate to an original current
    registry/source scope. One host certificate shared by unrelated workloads is
    insufficient. The owner protects the SSLContext, CA/pin selection, source
    mappings and socket/EOF lifecycle; this is not an in-process sandbox.
    """

    def __init__(
        self,
        registry: AgentRegistry,
        server_context: ssl.SSLContext,
        *,
        operator: object,
        clock: Callable[[], float],
        channel_lifetime: float = 30,
        max_enrollments: int = 256,
        max_channels: int = 512,
    ) -> None:
        if (
            type(server_context) is not ssl.SSLContext
            or type(operator) is not object
            or not callable(clock)
        ):
            raise ValueError("protected TLS context, operator capability and clock required")
        if not 0 < timestamp(channel_lifetime) <= 60:
            raise ValueError("invalid authenticated channel lifetime")
        for value, maximum in ((max_enrollments, 4096), (max_channels, 8192)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid bounded workload authentication capacity")
        self._registry, self._tls, self._operator = registry, server_context, operator
        self._clock, self._last_now = clock, 0.0
        self._lifetime, self._enrollment_limit, self._channel_limit = (
            channel_lifetime,
            max_enrollments,
            max_channels,
        )
        self._tls_binding = self._configuration()
        self._enrollments: dict[str, WorkloadEnrollment] = {}
        self._certificates: dict[str, str] = {}
        self._channels: dict[AuthorityChannel, _TLSChannel] = {}
        self._revoked: set[str] = set()
        self._generation = 0
        self._scope: tuple[str, str, str | None] | None = None
        self._lock = RLock()

    def _configuration(self) -> str:
        if (
            self._tls.verify_mode != ssl.CERT_REQUIRED
            or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2
            or not self._tls.get_ca_certs(binary_form=True)
        ):
            raise ValueError(
                "authority TLS requires a trusted CA, mutual certificates and TLS 1.2+"
            )
        return digest(
            {
                "verify_mode": self._tls.verify_mode,
                "verify_flags": self._tls.verify_flags,
                "minimum": self._tls.minimum_version,
                "maximum": self._tls.maximum_version,
                "options": self._tls.options,
                "hostname": self._tls.check_hostname,
                "ca": sorted(
                    hashlib.sha256(v).hexdigest() for v in self._tls.get_ca_certs(binary_form=True)
                ),
            }
        )

    def _now(self) -> float:
        now = timestamp(self._clock())
        if now < self._last_now:
            raise ValueError("authority clock moved backward")
        self._last_now = now
        return now

    def _operator_check(self, operator: object) -> None:
        if operator is not self._operator:
            raise ValueError("protected operator capability required")

    def enroll_workload(
        self,
        *,
        host_id: str,
        certificate_digest: str,
        context: SwarmContext,
        source: HostEvidenceSource,
        channel: HostChannel,
        adapter: object,
        operator: object,
        runtime_identity: SessionIdentity | None = None,
    ) -> str:
        self._operator_check(operator)
        identifier(host_id, "host_id")
        _hex(certificate_digest, "certificate digest")
        with self._lock:
            self._registry.authenticate(context, channel, adapter)
            if (
                type(source) is not HostEvidenceSource
                or source.principal != context.identity.agent_id
                or source.epoch != context.identity.policy_epoch
            ):
                raise ValueError("workload identity must match its original protected host scope")
            if runtime_identity is not None and (
                type(runtime_identity) is not SessionIdentity
                or runtime_identity.session_id != context.identity.session_id
            ):
                raise ValueError(
                    "planned runtime identity must match the authenticated physical session"
                )
            scope = (
                context.identity.tenant_id,
                context.identity.swarm_id,
                context.identity.task_id,
            )
            if self._scope is not None and self._scope != scope:
                raise ValueError("workload belongs to another tenant, swarm or protected task")
            result = self._enroll(
                host_id,
                certificate_digest,
                "workload",
                context,
                source,
                channel,
                adapter,
                runtime_identity,
            )
            self._scope = scope
            return result

    def enroll_broker(self, *, host_id: str, certificate_digest: str, operator: object) -> str:
        self._operator_check(operator)
        identifier(host_id, "host_id")
        _hex(certificate_digest, "certificate digest")
        with self._lock:
            return self._enroll(host_id, certificate_digest, "broker", None, None, None, object())

    def _enroll(
        self, host, certificate, role, context, source, channel, adapter, runtime_identity=None
    ) -> str:
        if certificate in self._certificates or len(self._enrollments) >= self._enrollment_limit:
            raise ValueError("duplicate certificate or workload enrollment capacity reached")
        enrollment_id = uuid4().hex
        self._enrollments[enrollment_id] = WorkloadEnrollment(
            enrollment_id,
            host,
            certificate,
            role,
            context,
            source,
            channel,
            adapter,
            source.key if source else None,
            runtime_identity,
        )
        self._certificates[certificate] = enrollment_id
        return enrollment_id

    def enrollment(self, enrollment_id: str) -> WorkloadEnrollment:
        identifier(enrollment_id, "enrollment_id")
        with self._lock:
            row = self._enrollments.get(enrollment_id)
            if row is None or enrollment_id in self._revoked:
                raise ValueError("unknown protected workload enrollment")
            if row.role == "workload":
                if row.context is None or row.registry_channel is None or row.source is None:
                    raise ValueError("incomplete protected workload scope")
                self._registry.authenticate(row.context, row.registry_channel, row.adapter)
                if row.source.key != row.source_key:
                    raise ValueError("workload host source changed")
            return row

    def authenticate(self, connection: ssl.SSLSocket) -> AuthorityChannel:
        """Authenticate actual TLS state, never a certificate dictionary or peer name."""
        with self._lock:
            if (
                type(connection) is not ssl.SSLSocket
                or connection.context is not self._tls
                or not connection.server_side
                or self._configuration() != self._tls_binding
                or connection.fileno() < 0
                or connection.version() not in {"TLSv1.2", "TLSv1.3"}
            ):
                raise ValueError("original verified authority TLS connection required")
            certificate = connection.getpeercert(binary_form=True)
            if not certificate:
                raise ValueError("TLS workload certificate unavailable")
            certificate_hash = hashlib.sha256(certificate).hexdigest()
            enrollment_id = self._certificates.get(certificate_hash)
            if enrollment_id is None:
                raise ValueError("TLS workload certificate is not enrolled")
            enrollment = self.enrollment(enrollment_id)
            now = self._now()
            self._channels = {
                handle: row
                for handle, row in self._channels.items()
                if row.generation == self._generation
                and now < row.expires_at
                and row.socket.fileno() >= 0
            }
            for handle, row in self._channels.items():
                if (
                    row.socket is connection
                    and row.generation == self._generation
                    and now < row.expires_at
                ):
                    return handle
            if len(self._channels) >= self._channel_limit:
                raise ValueError("authenticated authority channel capacity reached")
            handle = AuthorityChannel(uuid4().hex)
            self._channels[handle] = _TLSChannel(
                enrollment, connection, now + self._lifetime, self._generation
            )
            return handle

    def require(self, channel: AuthorityChannel, *, role: str) -> WorkloadEnrollment:
        with self._lock:
            if type(channel) is not AuthorityChannel or channel not in self._channels:
                raise ValueError("unknown original authority channel")
            row = self._channels[channel]
            if (
                row.generation != self._generation
                or self._now() >= row.expires_at
                or row.enrollment.role != role
            ):
                raise ValueError("authority channel expired, fenced or has wrong role")
            if self.authenticate(row.socket) is not channel:
                raise ValueError("authority channel was replaced")
            return self.enrollment(row.enrollment.enrollment_id)

    def close(self, channel: AuthorityChannel) -> None:
        """Host connector must call this on EOF/disconnect before reusing any request."""
        with self._lock:
            if type(channel) is not AuthorityChannel or channel not in self._channels:
                raise ValueError("unknown original authority channel")
            del self._channels[channel]

    def fence(self, *, operator: object) -> None:
        self._operator_check(operator)
        with self._lock:
            self._generation += 1
            self._channels.clear()

    def revoke_enrollment(self, enrollment_id: str, *, operator: object) -> None:
        self._operator_check(operator)
        with self._lock:
            if enrollment_id not in self._enrollments:
                raise ValueError("unknown protected workload enrollment")
            self._revoked.add(enrollment_id)
            self._channels = {
                key: row
                for key, row in self._channels.items()
                if row.enrollment.enrollment_id != enrollment_id
            }

    def rebind_workload(
        self, enrollment_id: str, context: SwarmContext, *, operator: object
    ) -> None:
        """Rebind a verified authorization generation without changing process/session identity."""
        self._operator_check(operator)
        with self._lock:
            old = self._enrollments.get(enrollment_id)
            if (
                old is None
                or enrollment_id in self._revoked
                or old.role != "workload"
                or old.context is None
                or old.source is None
                or old.registry_channel is None
            ):
                raise ValueError("original protected workload enrollment required")
            self._registry.authenticate(context, old.registry_channel, old.adapter)
            before, after = old.context.identity, context.identity
            if (
                (
                    before.tenant_id,
                    before.swarm_id,
                    before.agent_id,
                    before.runtime_id,
                    before.session_id,
                    before.task_id,
                    before.policy_epoch,
                )
                != (
                    after.tenant_id,
                    after.swarm_id,
                    after.agent_id,
                    after.runtime_id,
                    after.session_id,
                    after.task_id,
                    after.policy_epoch,
                )
                or old.source.key != old.source_key
                or after.generation < before.generation
            ):
                raise ValueError(
                    "workload rebind cannot change the authenticated physical session or source"
                )
            if context is old.context:
                return
            self._enrollments[enrollment_id] = WorkloadEnrollment(
                old.enrollment_id,
                old.host_id,
                old.certificate_digest,
                old.role,
                context,
                old.source,
                old.registry_channel,
                old.adapter,
                old.source_key,
                old.runtime_identity,
            )
            self._channels = {
                key: row
                for key, row in self._channels.items()
                if row.enrollment.enrollment_id != enrollment_id
            }
