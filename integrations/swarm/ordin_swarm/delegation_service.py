"""Opt-in online delegation over protected mutual-TLS workload channels."""

from ordin.swarm.delegation import (
    BrokerAdmissionScope,
    DelegationDispatch,
    RemoteDelegation,
    RemoteReview,
    SwarmDelegationService,
)
from ordin.swarm.workload_auth import AuthorityChannel, WorkloadAuthenticator

__all__ = [
    "AuthorityChannel",
    "WorkloadAuthenticator",
    "BrokerAdmissionScope",
    "DelegationDispatch",
    "RemoteDelegation",
    "RemoteReview",
    "SwarmDelegationService",
]
