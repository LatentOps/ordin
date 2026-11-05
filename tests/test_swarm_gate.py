from copy import copy
from dataclasses import replace
import json
import socket
import subprocess

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin._runtime_json import digest
from ordin.action import ActionHistory
from ordin.assurance import AssuranceGate, DelegatingAssuranceGate
from ordin.policy import ReviewPolicy
from ordin.swarm import InMemoryAgentRegistry, SwarmEventIngestor, SwarmEvent
from ordin.swarm.facts import SwarmAssessment, SwarmAssessmentSource
from ordin.swarm.gate import SwarmDecision, SwarmGate
from ordin.swarm.policy import SwarmPolicy, SwarmRule

from tests.assurance.test_delegating_gate import configured, action as child_action


def host(**options):
    now = [100.0]
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: now[0])
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="python")
    context = registry.enroll(channel, adapter, agent_id="agent", session_id="session")
    gate = SwarmGate(registry, **options)
    return registry, adapter, channel, context, gate, now


def evaluate(gate, context, adapter, channel, action=None, **options):
    return gate.evaluate_action(
        context,
        action or ActionEnvelope.shell("git status --short", action_id="action"),
        channel=channel,
        adapter=adapter,
        **options,
    )


@pytest.mark.parametrize(
    "command", ["git status --short", "rm -rf /", "unknown_future_tool --opaque"]
)
def test_no_policy_preserves_default_baseline_semantics(command):
    baseline = AgentGate()
    registry, adapter, channel, context, gate, now = host(baseline=baseline)
    proposed = ActionEnvelope.shell(command, action_id="action")
    ordinary = baseline.evaluate_action(proposed)
    result = evaluate(gate, context, adapter, channel, proposed)
    assert result.disposition == ordinary.disposition
    assert result.review.as_dict() == ordinary.review.as_dict()
    assert gate.binding_matches(result, context, proposed, channel=channel, adapter=adapter)


def test_permissive_swarm_rules_cannot_weaken_core_or_approval_requirements():
    policy = SwarmPolicy("permissive", "1", (SwarmRule("allow-all", "execute"),))
    baseline = AgentGate(Ordin(policy=ReviewPolicy("block")))
    _, adapter, channel, context, gate, _ = host(baseline=baseline, policy=policy)
    assert evaluate(gate, context, adapter, channel, ActionEnvelope.shell("rm -rf /")).denied
    for command in ("rm ./report.txt", "unknown_future_tool --opaque"):
        result = evaluate(gate, context, adapter, channel, ActionEnvelope.shell(command))
        assert result.review.decision in {"warn", "ask"}
        assert not result.may_execute
        assert result.requires_approval or result.denied


def test_policy_selectors_use_core_effects_and_protected_actor_not_parameter_claims():
    policy = SwarmPolicy(
        "bounded",
        "1",
        (
            SwarmRule("other-agent", "deny", agent_ids=("other",)),
            SwarmRule(
                "read-prohibition", "deny", action_kinds=("shell",), effects=("filesystem.read",)
            ),
        ),
    )
    _, adapter, channel, context, gate, _ = host(policy=policy)
    result = evaluate(gate, context, adapter, channel, ActionEnvelope.shell("cat ./report.txt"))
    assert result.denied and "read-prohibition" in result.matched_rules
    assert "other-agent" not in result.matched_rules


def test_mandatory_facts_require_original_current_action_snapshot_bound_host_receipts():
    clock = [100.0]
    provider = SwarmAssessmentSource("host-checks", clock=lambda: clock[0])
    policy = SwarmPolicy("mandatory", "1", required_checks=("budget",))
    _, adapter, channel, context, gate, _ = host(policy=policy, assessment_source=provider)
    proposed = ActionEnvelope.shell("git status --short", action_id="action")
    assert evaluate(gate, context, adapter, channel, proposed).denied
    receipt = provider.issue(
        check_id="budget",
        status="satisfied",
        action_digest=digest(proposed.as_dict()),
        context_digest=digest(context.as_dict()),
        policy_digest=gate.policy_digest,
        snapshot_digest=gate.evidence_snapshot_digest(context),
        lifetime=1,
    )
    result = evaluate(gate, context, adapter, channel, proposed, assessments=(receipt,))
    assert result.may_execute
    assert gate.binding_matches(result, context, proposed, channel=channel, adapter=adapter)
    assert not evaluate(
        gate, context, adapter, channel, proposed, assessments=(copy(receipt),)
    ).may_execute
    assert evaluate(
        gate, context, adapter, channel, proposed, assessments=({"approved": True},)
    ).denied
    with pytest.raises(ValueError):
        SwarmAssessment.from_dict(receipt._payload())
    with pytest.raises(ValueError):
        replace(result, _assessments=())
    clock[0] = 102
    assert not gate.binding_matches(result, context, proposed, channel=channel, adapter=adapter)
    assert evaluate(gate, context, adapter, channel, proposed, assessments=(receipt,)).denied


def test_event_snapshot_changes_and_provider_fences_invalidate_prior_reviews():
    registry, adapter, channel, context, _, _ = host()
    events = SwarmEventIngestor(registry)
    sender = events.bind_source(context, channel, adapter, source_id="gateway")
    provider = SwarmAssessmentSource("checks", clock=lambda: 100)
    gate = SwarmGate(registry, events=events, assessment_source=provider)
    proposed = ActionEnvelope.shell("git status --short", action_id="action")
    result = evaluate(gate, context, adapter, channel, proposed, event_source=sender)
    assert result.may_execute
    events.ingest(
        sender,
        SwarmEvent(
            "event",
            "message_sent",
            context.registry_id,
            context.identity,
            "gateway",
            1,
            100,
            evidence_class="host_authenticated",
        ),
    )
    assert not gate.binding_matches(
        result, context, proposed, channel=channel, adapter=adapter, event_source=sender
    )
    result = evaluate(gate, context, adapter, channel, proposed, event_source=sender)
    provider.fence()
    assert not gate.binding_matches(
        result, context, proposed, channel=channel, adapter=adapter, event_source=sender
    )


def test_identity_epoch_action_and_history_mutation_require_fresh_review():
    registry, adapter, channel, context, gate, _ = host()
    proposed = ActionEnvelope.shell("git status --short", action_id="action")
    history = ActionHistory(())
    result = evaluate(gate, context, adapter, channel, proposed, history=history)
    assert gate.binding_matches(
        result, context, proposed, channel=channel, adapter=adapter, history=history
    )
    assert not gate.binding_matches(result, context, proposed, channel=channel, adapter=adapter)
    assert not gate.binding_matches(
        result,
        context,
        ActionEnvelope.shell("git diff", action_id="action"),
        channel=channel,
        adapter=adapter,
        history=history,
    )
    registry.advance_policy_epoch(1)
    assert not gate.binding_matches(
        result, context, proposed, channel=channel, adapter=adapter, history=history
    )
    assert evaluate(gate, context, adapter, channel, proposed).denied


def test_pure_evaluation_emits_no_audit_or_execution_and_serialization_is_redacted(monkeypatch):
    class RejectAudit:
        def record(self, review):
            raise AssertionError("audit executed during pure review")

    def forbidden(*args, **kwargs):
        raise AssertionError("execution/network during pure review")

    _, adapter, channel, context, gate, _ = host(baseline=AgentGate(Ordin(audit=RejectAudit())))
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    proposed = ActionEnvelope.shell("git status --short", action_id="action")
    result = evaluate(gate, context, adapter, channel, proposed)
    payload = json.dumps(result.as_dict())
    assert result.may_execute and "git status" not in payload and "parameters" not in payload
    with pytest.raises(ValueError):
        SwarmDecision.from_dict(result.as_dict())


def test_mutation_during_baseline_review_is_denied(monkeypatch):
    _, adapter, channel, context, gate, _ = host()
    original = ActionEnvelope.shell("git status --short", action_id="action")
    saved = AgentGate.evaluate_action

    def changing(self, action, **kwargs):
        result = saved(self, action, **kwargs)
        object.__setattr__(original, "parameters", {"command": "rm -rf /"})
        return result

    monkeypatch.setattr(AgentGate, "evaluate_action", changing)
    result = evaluate(gate, context, adapter, channel, original)
    assert result.denied and "swarm.review_binding_changed" in result.reason_codes


def test_assurance_and_delegation_denials_are_never_weakened_and_preview_is_pure(tmp_path):
    delegated_issuer, root, source, grant, delegated, clock = configured(tmp_path)
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: 100)
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="python")
    parent = registry.enroll(channel, adapter, agent_id="parent", session_id="parent-session")
    context = registry.enroll(
        channel,
        adapter,
        agent_id=source.principal,
        session_id="child-session",
        parent_agent_id=parent.identity.agent_id,
        delegation_id=grant.record.grant_id,
    )
    policy = SwarmPolicy("permissive", "1", (SwarmRule("allow-all", "execute"),))
    gate = SwarmGate(registry, delegated, policy=policy, delegation_context=context)
    before, pending = delegated.snapshot(), dict(delegated_issuer._pending)
    allowed = evaluate(gate, context, adapter, channel, child_action())
    assert allowed.may_execute and isinstance(allowed.review, type(allowed.baseline.review))
    assert delegated.snapshot() == before and delegated_issuer._pending == pending
    forbidden = evaluate(gate, context, adapter, channel, child_action("bad", "/fixture/.env"))
    assert forbidden.denied
    assert delegated.snapshot() == before and delegated_issuer._pending == pending
    assurance_gate = SwarmGate(registry, AssuranceGate(require_profile=True), policy=policy)
    missing_profile = evaluate(assurance_gate, context, adapter, channel)
    assert not missing_profile.may_execute
    assert missing_profile.disposition == missing_profile.baseline.disposition
    delegated_issuer.revoke(root)
    assert evaluate(gate, context, adapter, channel, child_action("revoked")).denied


@pytest.mark.parametrize("status,expected", [("violated", "deny"), ("unknown", "escalate")])
def test_host_facts_only_strengthen_and_unknown_checks_keep_configured_escalation(status, expected):
    provider = SwarmAssessmentSource("checks", clock=lambda: 100)
    policy = SwarmPolicy(
        "checks", "1", required_checks=("lineage",), unknown_disposition="escalate"
    )
    _, adapter, channel, context, gate, _ = host(policy=policy, assessment_source=provider)
    proposed = ActionEnvelope.shell("git status --short", action_id="action")
    receipt = provider.issue(
        check_id="lineage",
        status=status,
        action_digest=digest(proposed.as_dict()),
        context_digest=digest(context.as_dict()),
        policy_digest=gate.policy_digest,
        snapshot_digest=gate.evidence_snapshot_digest(context),
    )
    assert (
        evaluate(gate, context, adapter, channel, proposed, assessments=(receipt,)).disposition
        == expected
    )
    if status == "unknown":
        assert evaluate(gate, context, adapter, channel, proposed).requires_approval
    with pytest.raises(ValueError):
        SwarmPolicy("unsafe", "1", unknown_disposition="execute")


def test_foreign_fact_issuers_and_forged_approval_data_cannot_override_core():
    actual = SwarmAssessmentSource("same-name", clock=lambda: 100)
    foreign = SwarmAssessmentSource("same-name", clock=lambda: 100)
    policy = SwarmPolicy("checks", "1", required_checks=("approval",))
    _, adapter, channel, context, gate, _ = host(
        baseline=AgentGate(Ordin(policy=ReviewPolicy("block"))),
        policy=policy,
        assessment_source=actual,
    )
    proposed = ActionEnvelope.shell("rm ./report.txt", action_id="action")
    bindings = dict(
        check_id="approval",
        status="satisfied",
        action_digest=digest(proposed.as_dict()),
        context_digest=digest(context.as_dict()),
        policy_digest=gate.policy_digest,
        snapshot_digest=gate.evidence_snapshot_digest(context),
    )
    assert evaluate(
        gate, context, adapter, channel, proposed, assessments=(foreign.issue(**bindings),)
    ).denied
    genuine = actual.issue(**bindings)
    result = evaluate(gate, context, adapter, channel, proposed, assessments=(genuine,))
    assert not result.may_execute
    with pytest.raises(TypeError):
        evaluate(gate, context, adapter, channel, proposed, approved=True)


def test_decision_binding_rejects_reconstructed_owner_and_mutated_review():
    registry, adapter, channel, context, gate, _ = host()
    proposed = ActionEnvelope.shell("git status --short", action_id="action")
    result = evaluate(gate, context, adapter, channel, proposed)
    other = SwarmGate(registry)
    assert not other.binding_matches(result, context, proposed, channel=channel, adapter=adapter)
    result.review.effects.append("caller-invented.effect")
    assert not gate.binding_matches(result, context, proposed, channel=channel, adapter=adapter)
    with pytest.raises(ValueError):
        replace(result, disposition="deny")


def test_assessment_expiry_during_review_is_rechecked_before_result():
    times = iter((100.0, 100.0, 102.0))
    provider = SwarmAssessmentSource("checks", clock=lambda: next(times))
    policy = SwarmPolicy("checks", "1", required_checks=("quota",))
    _, adapter, channel, context, gate, _ = host(policy=policy, assessment_source=provider)
    proposed = ActionEnvelope.shell("git status --short", action_id="action")
    receipt = provider.issue(
        check_id="quota",
        status="satisfied",
        lifetime=1,
        action_digest=digest(proposed.as_dict()),
        context_digest=digest(context.as_dict()),
        policy_digest=gate.policy_digest,
        snapshot_digest=gate.evidence_snapshot_digest(context),
    )
    result = evaluate(gate, context, adapter, channel, proposed, assessments=(receipt,))
    assert result.denied and "swarm.assessment_changed" in result.reason_codes
