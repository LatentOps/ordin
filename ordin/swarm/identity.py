"""Opaque host-channel handles, accepted only by the registry that issued them."""

from dataclasses import dataclass


@dataclass(frozen=True, eq=False, slots=True)
class HostChannel:
    """A protected adapter binding, not OS/container attestation or a bearer JSON token.

    The host keeps the registry, adapter and channel outside agent control.
    Constructing or copying this value cannot enroll or authenticate a principal.
    """

    tenant_id: str
    swarm_id: str
    runtime_id: str
