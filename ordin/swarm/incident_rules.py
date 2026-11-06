"""Explicit opt-in cascading-risk templates over protected temporal facts."""

from dataclasses import replace

from .temporal_policy import (
    SwarmTemporalPolicySet,
    SwarmTemporalPredicate as P,
    SwarmTemporalRule as R,
    default_swarm_temporal_policy,
)

CASCADE_RULE_IDS = (
    "incident_repeated_denials",
    "incident_lateral_relay",
    "incident_privilege_fanout",
    "incident_mass_deletion",
    "incident_runaway_children",
)


def incident_temporal_policy() -> SwarmTemporalPolicySet:
    """Return finite data; selecting it never enables automatic containment."""
    existing = {rule.rule_id: rule for rule in default_swarm_temporal_policy().policy.rules}
    return SwarmTemporalPolicySet(
        "incident-cascades",
        1,
        (
            R(
                CASCADE_RULE_IDS[0],
                "high",
                (
                    P(event_kinds=("denied",)),
                    P(
                        action_kinds=("shell", "tool", "mcp", "file", "network", "database"),
                        evidence_classes=("current_proposal",),
                    ),
                ),
                scope="swarm",
                aggregation="causal_ancestors",
                quota=3,
                count_by="actions",
            ),
            replace(existing["sensitive_relay_upload"], rule_id=CASCADE_RULE_IDS[1]),
            R(
                CASCADE_RULE_IDS[2],
                "critical",
                (
                    P(effects_any=("privilege.escalate",), event_kinds=("reviewed", "denied")),
                    P(effects_any=("privilege.escalate",), evidence_classes=("current_proposal",)),
                ),
                scope="swarm",
                aggregation="causal_ancestors",
                quota=2,
                count_by="agents",
            ),
            R(
                CASCADE_RULE_IDS[3],
                "critical",
                (
                    P(effects_any=("filesystem.delete",), event_kinds=("reviewed",)),
                    P(effects_any=("filesystem.delete",), evidence_classes=("current_proposal",)),
                ),
                scope="swarm",
                aggregation="causal_ancestors",
                quota=4,
                count_by="actions",
            ),
            replace(existing["delegation_fanout"], rule_id=CASCADE_RULE_IDS[4]),
        ),
    )


def cascade_incident_rules(rule_ids: tuple[str, ...], *, max_affected: int = 4):
    """Enable only named templates, explicitly selected by the protected operator."""
    from .incident import IncidentRule

    if (
        type(rule_ids) is not tuple
        or len(rule_ids) > len(CASCADE_RULE_IDS)
        or any(type(name) is not str or name not in CASCADE_RULE_IDS for name in rule_ids)
        or len(set(rule_ids)) != len(rule_ids)
    ):
        raise ValueError("finite exact cascading incident rule IDs required")
    return tuple(IncidentRule(name, "high", "agent", max_affected) for name in rule_ids)
