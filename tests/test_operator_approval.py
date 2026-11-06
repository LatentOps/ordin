"""Original core fulfillment remains distinct from a live exact-job execution check."""

from concurrent.futures import ThreadPoolExecutor
from copy import copy
from dataclasses import replace

import pytest

from ordin import ActionEnvelope, ToolCallAdapter
from ordin.agent import AgentGate
from ordin.action_policy import ActionPolicySet, ActionPolicyRule, ActionPolicyCondition
from ordin._runtime_json import digest
from ordin.approval import ApprovalSource
from ordin.runtime_contract import derive_runtime_capability_contract
from ordin.runtime_contract import RuntimeCapabilityContract
from ordin.session import configuration_digest
from ordin.assurance import AssuranceGate
from tests.test_swarm_broker import fixture


def configured(data, *, verifier=None):
    service, clock, operator, maximum = data[1], data[10], data[11], data[12]
    source = ApprovalSource(
        service.issuer.source,
        service.issuer.profile,
        maximum,
        operator=operator,
        clock=lambda: clock[0],
        verifier=verifier if verifier is not None else lambda identity, scope, stage: True,
    )
    action = data[4]
    review = service.assurance.ordin.review_action(action)
    contract = derive_runtime_capability_contract(review)
    scope = source.create_scope(
        operator=operator,
        context_digest=digest(data[14]._agents["parent"].context.as_dict()),
        policy_digest=service.issuer.source.runtime_policy_digest,
        policy_epoch=0,
        scope_digest=digest(["tenant", "swarm", "task"]),
        operator_maximum_digest=maximum.digest,
        owner_fence=1,
        revocation_epoch=0,
        budget_digest=data[2].policy.digest,
        delegation_digest=maximum.digest,
        capabilities_digest=contract.digest,
    )
    return source, scope, action, review, contract, operator


def issue(configured):
    source, scope, action, review, _, operator = configured
    return source.issue(
        action,
        review,
        "a" * 64,
        scope,
        satisfaction_id="human-approval",
        lifetime=5,
        operator=operator,
    )


def test_original_host_approval_is_current_but_json_copy_and_other_scope_are_not(tmp_path):
    with fixture(tmp_path) as data:
        configured_scope = configured(data)
        source, scope, action, review, _, _ = configured_scope
        proof = issue(configured_scope)
        assert source.verify(proof, action, review, "a" * 64, scope)
        assert not source.verify(copy(proof), action, review, "a" * 64, scope)
        assert not source.verify(proof.as_dict(), action, review, "a" * 64, scope)
        assert not source.verify(proof, action, review, "a" * 64, copy(scope))
        native = source.host_approval(proof)
        assert native.current and not copy(native).current
        assert not proof.as_dict()["execution_authority"]
        data[10][0] += 6
        assert not source.verify(proof, action, review, "a" * 64, scope)
        assert not native.current
        with pytest.raises(ValueError):
            source.host_approval(proof)


def test_exact_job_lease_is_one_use_and_historical_witness_survives_settlement(tmp_path):
    with fixture(tmp_path) as data:
        settings = configured(data)
        source, scope, action, review, contract, operator = settings
        proof = issue(settings)
        broker, executor, job = object(), object(), object()
        lease = source.reserve_lease(proof, contract, broker, operator=operator)
        assert source.witnessed(lease, contract.digest)
        assert not source.verify_execution(lease, executor, job)
        with pytest.raises(ValueError):
            source.reserve_lease(proof, contract, broker, operator=operator)
        source.bind_job(lease, broker, executor, job, operator=operator)
        source.begin(lease, broker, executor, job, operator=operator)
        assert source.verify_execution(lease, executor, job)
        assert not source.verify_execution(copy(lease), executor, job)
        assert not source.verify_execution(lease, executor, object())
        with pytest.raises(ValueError):
            source.begin(lease, broker, executor, job, operator=operator)
        source.finish(lease, operator=operator)
        assert not source.verify_execution(lease, executor, job)
        assert not source.verify(proof, action, review, "a" * 64, scope)
        assert source.witnessed(lease, contract.digest)


def test_concurrent_lease_consumption_has_exactly_one_winner(tmp_path):
    with fixture(tmp_path) as data:
        settings = configured(data)
        source, _, _, _, contract, operator = settings
        proof = issue(settings)
        broker, executor, job = object(), object(), object()
        lease = source.reserve_lease(proof, contract, broker, operator=operator)
        source.bind_job(lease, broker, executor, job, operator=operator)

        def begin(_):
            try:
                source.begin(lease, broker, executor, job, operator=operator)
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            assert sum(pool.map(begin, range(8))) == 1


def test_lost_durable_consumption_ack_leaves_no_executable_local_lease(tmp_path):
    phase = ["approved"]

    def verifier(identity, scope, stage):
        if stage == "begin":
            phase[0] = "consumed"
            raise RuntimeError("synthetic committed ACK lost")
        return phase[0] == "approved"

    with fixture(tmp_path) as data:
        settings = configured(data, verifier=verifier)
        source, scope, action, review, contract, operator = settings
        proof = issue(settings)
        broker, executor, job = object(), object(), object()
        lease = source.reserve_lease(proof, contract, broker, operator=operator)
        source.bind_job(lease, broker, executor, job, operator=operator)
        with pytest.raises(ValueError, match="committed approval consumption"):
            source.begin(lease, broker, executor, job, operator=operator)
        assert not source.verify_execution(lease, executor, job)
        assert not source.verify(proof, action, review, "a" * 64, scope)


@pytest.mark.parametrize(
    "action",
    (ActionEnvelope.shell("rm -rf /"), ToolCallAdapter("fixture").adapt("opaque_tool", {})),
)
def test_original_operator_cannot_approve_block_or_missing_semantics(tmp_path, action):
    with fixture(tmp_path) as data:
        source, scope, _, _, _, operator = configured(data)
        review = data[1].assurance.ordin.review_action(action)
        with pytest.raises(ValueError, match="block or missing action semantics"):
            source.issue(
                action,
                review,
                "a" * 64,
                scope,
                satisfaction_id="blocked",
                lifetime=5,
                operator=operator,
            )


@pytest.mark.parametrize("required", ("warn", "ask"))
def test_core_approval_fulfills_obligation_without_rewriting_original_review_or_disposition(
    tmp_path, required
):
    with fixture(tmp_path) as data:
        source, old_scope, action, _, _, operator = configured(data)
        core = replace(
            data[1].assurance.ordin,
            action_policy=ActionPolicySet(
                "human-guard",
                "1",
                (
                    ActionPolicyRule(
                        "human", required, ActionPolicyCondition(effects_any=("filesystem.read",))
                    ),
                ),
            ),
        )
        gate = AgentGate(core, approval_source=source)
        pending = gate.evaluate_action(action)
        assert pending.review.decision == required
        assert pending.disposition == "escalate" and not pending.may_execute
        raw = derive_runtime_capability_contract(pending.review)
        assert not raw.unknowns and raw.grant_state == "requires_approval"
        scope = source.create_scope(
            operator=operator, **(old_scope.as_dict() | {"capabilities_digest": raw.digest})
        )
        proof = source.issue(
            action,
            pending.review,
            configuration_digest(gate),
            scope,
            satisfaction_id="known-human-warning",
            lifetime=5,
            operator=operator,
        )
        approved = gate.evaluate_action(action, approval_satisfaction=proof, approval_scope=scope)
        assert approved.review.as_dict() == pending.review.as_dict()
        assert approved.disposition == "escalate" and approved.approval_fulfilled
        assert approved.execution_eligibility == "approved" and approved.may_execute
        from ordin.swarm.gate import SwarmGate
        from ordin.swarm.policy import SwarmPolicy, SwarmRule

        enrollment = next(
            row
            for row in data[1].authenticator._enrollments.values()
            if row.context is not None and row.context.identity.agent_id == "parent"
        )
        options = {
            "channel": enrollment.registry_channel,
            "adapter": enrollment.adapter,
            "approval_satisfaction": proof,
            "approval_scope": scope,
        }
        unrestrained = SwarmGate(data[14], baseline=gate).evaluate_action(
            enrollment.context, action, **options
        )
        assert unrestrained.approval_fulfilled and unrestrained.may_execute
        for policy in (
            SwarmPolicy("independent", "1", rules=(SwarmRule("escalation", "escalate"),)),
            SwarmPolicy(
                "mandatory", "1", required_checks=("unknown",), unknown_disposition="escalate"
            ),
        ):
            restricted = SwarmGate(data[14], baseline=gate, policy=policy).evaluate_action(
                enrollment.context, action, **options
            )
            assert restricted.baseline.approval_fulfilled
            assert restricted.disposition == "escalate" and not restricted.may_execute
        assert not source._used
        assert not gate.evaluate_action(
            action, approval_satisfaction=copy(proof), approval_scope=scope
        ).may_execute
        lease = source.reserve_lease(proof, raw, object(), operator=operator)
        contract = derive_runtime_capability_contract(
            approved.review, approval_execution_lease=lease
        )
        assert contract.decision == required and contract.grant_state == "eligible"
        assert contract.approval_base_digest == raw.digest
        with pytest.raises(ValueError):
            RuntimeCapabilityContract.from_dict(contract.as_dict())
        immutable = contract.digest
        data[10][0] += 6
        assert not approved.may_execute and contract.digest == immutable


def test_assurance_accepts_only_fulfilled_core_obligation_and_keeps_mandatory_profile_unknown(
    tmp_path,
):
    with fixture(tmp_path) as data:
        source, old_scope, action, _, _, operator = configured(data)
        core = replace(
            data[1].assurance.ordin,
            action_policy=ActionPolicySet(
                "human",
                "1",
                (
                    ActionPolicyRule(
                        "approve", "warn", ActionPolicyCondition(effects_any=("filesystem.read",))
                    ),
                ),
            ),
        )
        baseline = AgentGate(core, approval_source=source)
        before = baseline.evaluate_action(action)
        raw = derive_runtime_capability_contract(before.review)
        scope = source.create_scope(
            operator=operator, **(old_scope.as_dict() | {"capabilities_digest": raw.digest})
        )
        proof = source.issue(
            action,
            before.review,
            configuration_digest(baseline),
            scope,
            satisfaction_id="assurance-human",
            lifetime=5,
            operator=operator,
        )
        host = source.host.context(approvals=(source.host_approval(proof),))
        gate = AssuranceGate(baseline)
        approved = gate.evaluate_action(
            action, host_context=host, approval_satisfaction=proof, approval_scope=scope
        )
        assert approved.disposition == "escalate" and approved.review.decision == "warn"
        assert approved.approval_fulfilled and approved.may_execute
        assert "approval_satisfaction_digest" in approved.as_dict()
        unknown = AssuranceGate(baseline, require_profile=True).evaluate_action(
            action, host_context=host, approval_satisfaction=proof, approval_scope=scope
        )
        assert unknown.disposition == "escalate" and not unknown.may_execute
        assert not unknown.approval_fulfilled
        assert gate.evaluate_action(action, host_context=host).denied
        assert gate.evaluate_action(
            action, host_context=host, approval_satisfaction=copy(proof), approval_scope=scope
        ).denied
        data[10][0] += 6
        assert not approved.may_execute
        assert gate.evaluate_action(
            action, host_context=host, approval_satisfaction=proof, approval_scope=scope
        ).denied
