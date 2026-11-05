"""Protected current delegation links, separate from data-transfer causality."""

from dataclasses import dataclass

from ordin._runtime_json import digest
from ordin.assurance.delegation import DelegationIssuer, IssuedDelegation
from ordin.assurance.delegated_paths import verify_current_delegation_relationship
from ordin.assurance.host import HostEvidenceSource

from .models import SwarmContext


@dataclass(frozen=True, slots=True)
class SwarmDelegationLink:
    issuer: DelegationIssuer
    grant: IssuedDelegation
    parent_source: HostEvidenceSource
    child_source: HostEvidenceSource
    parent_context: SwarmContext
    child_context: SwarmContext

    def validate(self) -> tuple[str, str]:
        verify_current_delegation_relationship(
            self.issuer, self.grant, self.parent_source, self.child_source
        )
        if (
            type(self.parent_context) is not SwarmContext
            or type(self.child_context) is not SwarmContext
        ):
            raise ValueError("delegation graph requires immutable scoped contexts")
        self.parent_context.__post_init__()
        self.child_context.__post_init__()
        parent, child = self.parent_context.identity, self.child_context.identity
        if (
            (parent.tenant_id, parent.swarm_id) != (child.tenant_id, child.swarm_id)
            or parent.agent_id != self.parent_source.principal
            or child.agent_id != self.child_source.principal
            or child.parent_agent_id != parent.agent_id
            or child.parent_generation != parent.generation
            or child.delegation_id != self.grant.record.grant_id
            or parent.policy_epoch != child.policy_epoch
        ):
            raise ValueError("delegation graph context/issuer scope mismatch")
        return digest(self.parent_context.as_dict()), digest(self.child_context.as_dict())
