"""Declarative maximum containment and actual current-epoch dispatch fencing."""

from concurrent.futures import ThreadPoolExecutor
from copy import copy
from dataclasses import replace
import json
from threading import Event
from itertools import permutations

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin._runtime_json import digest
from ordin.swarm import CoverageManifest, InMemoryAgentRegistry, SwarmGate, SwarmToolGateway
from ordin.swarm.budgets import BudgetCost, BudgetLedger, BudgetLimit, BudgetPolicy
from ordin.swarm.policy_set import (
    SwarmBudgetCondition,
    SwarmBudgetConstraint,
    SwarmPolicyPermissions,
    SwarmPolicyResource,
    SwarmPolicyRule,
    SwarmPolicySelector,
    SwarmPolicySet,
    SwarmPolicyTool,
    load_swarm_policy_set,
)
from ordin.swarm.policy_compiler import (
    SwarmPolicyMaximum,
    SwarmRoleBinding,
    compile_swarm_policy_set,
    diff_swarm_policies,
)
from ordin.swarm.policy_facts import SwarmBudgetFact, SwarmPolicyFacts, SwarmPolicyFactsSource
from ordin.swarm.policy_runtime import (
    SwarmPolicyApproval,
    SwarmPolicyReplayCase,
    SwarmPolicyRuntime,
)


def fixture(*, permissions=None, maximum=None, budget=False):
    now = [100.0]
    clock = lambda: now[0]
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=clock, heartbeat_timeout=3600)
    actors = {}
    for name, parent in (("parent", None), ("a", "parent"), ("b", "parent")):
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id="fixture")
        context = registry.enroll(
            channel,
            adapter,
            agent_id=name,
            session_id="physical-" + name,
            parent_agent_id=parent,
            task_id="task",
            coverage=CoverageManifest("intercept"),
        )
        actors[name] = (context, channel, adapter)
    operator = object()
    limits = (BudgetLimit("swarm", "requests", 100),) if budget else ()
    maximum = maximum or SwarmPolicyMaximum(
        "tenant",
        "swarm",
        permissions
        or SwarmPolicyPermissions(
            action_kinds=("shell", "tool", "file", "network", "mcp", "database")
        ),
        role_bindings=(SwarmRoleBinding("a", ("reader",)), SwarmRoleBinding("b", ("worker",))),
        budget_limits=limits,
    )
    ledger = (
        BudgetLedger(registry, BudgetPolicy(0, limits), clock=clock, operator=object())
        if budget
        else None
    )
    runtime = SwarmPolicyRuntime(
        registry, maximum, operator=operator, clock=clock, budget_ledger=ledger
    )
    return runtime, registry, actors, now, operator


def policy(*, revision=1, default="execute", rules=(), **options):
    return SwarmPolicySet(
        "policy", revision, "tenant", "swarm", rules=rules, default_disposition=default, **options
    )


def cases(actors):
    return (
        SwarmPolicyReplayCase(
            "benign", actors["a"][0], ActionEnvelope.shell("git status"), "benign"
        ),
        SwarmPolicyReplayCase("unsafe", actors["a"][0], ActionEnvelope.shell("rm -rf /"), "unsafe"),
    )


def approval(runtime, operator, actors, selected, *, allow_relaxation=False):
    proposal = runtime.prepare(selected)
    simulation = runtime.simulate(proposal, cases(actors))
    return runtime.approve(
        proposal, simulation, operator=operator, allow_relaxation=allow_relaxation
    ), simulation


def refresh(registry, actors):
    for name in ("parent", "a", "b"):
        context, channel, adapter = actors[name]
        actors[name] = (
            registry.refresh_policy_context(
                context, channel, adapter, coverage=CoverageManifest("intercept")
            ),
            channel,
            adapter,
        )


def deploy(runtime, registry, actors, operator, selected=None):
    approved, _ = approval(runtime, operator, actors, selected or policy())
    activated = runtime.activate(approved, operator=operator)
    assert activated.state == "active_requires_reenrollment"
    refresh(registry, actors)
    return activated


def evaluate(gate, actor, selected=None, **options):
    context, channel, adapter = actor
    return gate.evaluate_action(
        context,
        selected or ActionEnvelope.shell("git status", action_id="action"),
        channel=channel,
        adapter=adapter,
        **options,
    )


def test_policy_parser_roundtrip_closed_shape_wildcards_and_malformed_rules(tmp_path):
    selected = policy(
        rules=(SwarmPolicyRule("reader", "execute", SwarmPolicySelector(role_ids=("reader",))),)
    )
    assert SwarmPolicySet.from_dict(selected.as_dict()).digest == selected.digest
    for replacement in (
        {"include": "https://untrusted.invalid/policy"},
        {"eval": "arbitrary()"},
        {"unknown_disposition": "execute"},
        {"rules": [{"rule_id": "r", "disposition": "execute", "match": {"role_ids": ["*"]}}]},
        {"permissions": {"resources": [{"type": "path", "value": "/workspace/*"}]}},
    ):
        with pytest.raises(ValueError):
            SwarmPolicySet.from_dict(selected.as_dict() | replacement)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(selected.as_dict()))
    assert load_swarm_policy_set(path).digest == selected.digest
    path.write_text('{"schema_version":"ordin.swarm_policy_set.v1","schema_version":"other"}')
    with pytest.raises(ValueError):
        load_swarm_policy_set(path)


def test_exact_operator_maximum_cannot_be_widened_by_policy_or_null_inheritance():
    maximum = SwarmPolicyMaximum(
        "tenant",
        "swarm",
        SwarmPolicyPermissions(
            action_kinds=("file",),
            effects=("filesystem.read",),
            resources=(SwarmPolicyResource("path", "/workspace/public"),),
        ),
    )
    for permissions in (
        SwarmPolicyPermissions(action_kinds=("shell",)),
        SwarmPolicyPermissions(effects=("filesystem.delete",)),
        SwarmPolicyPermissions(resources=(SwarmPolicyResource("path", "/workspace/private"),)),
    ):
        with pytest.raises(ValueError, match="maximum"):
            compile_swarm_policy_set(policy(permissions=permissions), maximum)
    inherited = compile_swarm_policy_set(policy(), maximum)
    assert inherited.permissions == maximum.permissions
    with pytest.raises(ValueError, match="scope"):
        compile_swarm_policy_set(replace(policy(), tenant_id="foreign"), maximum)


def test_precedence_roles_and_parameters_never_weaken_core_decisions():
    runtime, registry, actors, _, operator = fixture()
    selected = policy(
        default="deny",
        rules=(
            SwarmPolicyRule("reader-allow", "execute", SwarmPolicySelector(role_ids=("reader",))),
            SwarmPolicyRule(
                "read-deny", "deny", SwarmPolicySelector(effects_any=("filesystem.read",))
            ),
            SwarmPolicyRule(
                "read-escalate", "escalate", SwarmPolicySelector(effects_any=("filesystem.read",))
            ),
        ),
    )
    deploy(runtime, registry, actors, operator, selected)
    gate = SwarmGate(registry, policy_runtime=runtime)
    assert evaluate(gate, actors["a"]).may_execute
    assert evaluate(
        gate,
        actors["b"],
        ActionEnvelope("shell", "execute", {"command": "git status", "role": "reader"}),
    ).denied
    for command in ("cat /workspace/data", "rm -rf /", "unknown_opaque_tool"):
        decision = evaluate(gate, actors["a"], ActionEnvelope.shell(command))
        assert not decision.may_execute
    assert evaluate(gate, actors["a"], ActionEnvelope.shell("cat /workspace/data")).denied
    assert evaluate(gate, actors["a"], ActionEnvelope.shell("rm -rf /")).review.decision == "block"


def test_protected_label_message_temporal_and_budget_facts_are_required_and_exactly_bound():
    runtime, registry, actors, now, operator = fixture()
    selected = policy(
        rules=(
            SwarmPolicyRule(
                "sensitive-input", "deny", SwarmPolicySelector(data_labels_any=("secret",))
            ),
            SwarmPolicyRule(
                "poisoned-result",
                "deny",
                SwarmPolicySelector(
                    message_classes_any=("tool_result",),
                    temporal_categories_any=("injection-chain",),
                ),
            ),
            SwarmPolicyRule(
                "low-budget",
                "escalate",
                SwarmPolicySelector(budgets=(SwarmBudgetCondition("swarm", "requests", 10),)),
            ),
        ),
        unknown_disposition="deny",
    )
    deploy(runtime, registry, actors, operator, selected)
    gate = SwarmGate(registry, policy_runtime=runtime)
    action = ActionEnvelope.shell("git status", action_id="action")
    assert evaluate(gate, actors["a"], action).denied
    context, _, _ = actors["a"]
    kwargs = dict(
        policy_digest=gate.policy_digest, snapshot_digest=gate.evidence_snapshot_digest(context)
    )
    safe = runtime.facts_source.issue(
        context,
        action,
        data_labels=("public",),
        message_classes=(),
        temporal_categories=(),
        budgets=(SwarmBudgetFact("swarm", "requests", 100),),
        lifetime=1,
        **kwargs,
    )
    allowed = evaluate(gate, actors["a"], action, policy_facts=safe)
    assert allowed.may_execute
    for fake in (
        {"data_labels": ["public"]},
        copy(safe),
        SwarmPolicyFactsSource(clock=lambda: now[0]).issue(
            context, action, data_labels=("public",), **kwargs
        ),
    ):
        assert evaluate(gate, actors["a"], action, policy_facts=fake).denied
    secret = runtime.facts_source.issue(
        context,
        action,
        data_labels=("secret",),
        message_classes=(),
        temporal_categories=(),
        budgets=(SwarmBudgetFact("swarm", "requests", 100),),
        **kwargs,
    )
    assert evaluate(gate, actors["a"], action, policy_facts=secret).denied
    now[0] += 2
    assert not gate.binding_matches(
        allowed, context, action, channel=actors["a"][1], adapter=actors["a"][2]
    )
    assert evaluate(gate, actors["a"], action, policy_facts=safe).denied


def test_operator_approval_is_original_exact_version_and_single_epoch_use():
    runtime, registry, actors, _, operator = fixture()
    approved, simulation = approval(runtime, operator, actors, policy())
    for fake in (
        copy(approved),
        {"approved": True},
        replace(approved, target_epoch=approved.target_epoch + 1),
    ):
        with pytest.raises(ValueError):
            runtime.activate(fake, operator=operator)
    assert registry._policy_epoch == 0
    with pytest.raises(ValueError):
        runtime.activate(approved, operator=object())
    runtime.activate(approved, operator=operator)
    with pytest.raises(ValueError):
        runtime.activate(approved, operator=operator)
    assert registry._policy_epoch == 1 and not simulation.as_dict()["execution_authority"]


def test_reload_and_rollback_use_new_epochs_and_never_resurrect_old_forward_tickets():
    runtime, registry, actors, _, operator = fixture()
    original = policy()
    deploy(runtime, registry, actors, operator, original)
    gate = SwarmGate(registry, policy_runtime=runtime)
    gateway = SwarmToolGateway(clock=lambda: 100)
    actor = gateway.bind_agent(
        actors["a"][0], gate, actors["a"][1], actors["a"][2], routes=frozenset({"sdk"})
    )
    pending = gateway.prepare(actor, ActionEnvelope.shell("git status"))
    old_context = actors["a"][0]
    strict = policy(revision=2, default="deny")
    approved, _ = approval(runtime, operator, actors, strict)
    runtime.activate(approved, operator=operator)
    calls = []
    with pytest.raises(ValueError):
        gateway.forward(actor, pending.ticket, lambda action: calls.append(action))
    refresh(registry, actors)
    assert actors["a"][0].identity.session_id == old_context.identity.session_id
    assert actors["a"][0].identity.generation > old_context.identity.generation
    approved, _ = approval(runtime, operator, actors, original, allow_relaxation=True)
    activated = runtime.activate(approved, operator=operator)
    assert activated.epoch == 3
    with pytest.raises(ValueError):
        gateway.forward(actor, pending.ticket, lambda action: calls.append(action))
    assert not calls


def test_hidden_structural_relaxation_requires_approval_even_if_replay_does_not_show_it():
    runtime, registry, actors, _, operator = fixture()
    deploy(runtime, registry, actors, operator, policy(default="deny"))
    proposal = runtime.prepare(policy(revision=2))
    simulation = runtime.simulate(
        proposal,
        (
            SwarmPolicyReplayCase(
                "always-blocked", actors["a"][0], ActionEnvelope.shell("rm -rf /"), "unsafe"
            ),
        ),
    )
    assert (
        simulation.as_dict()["relaxations"] == 0 and simulation.as_dict()["structural_relaxation"]
    )
    with pytest.raises(ValueError, match="relaxation"):
        runtime.approve(proposal, simulation, operator=operator)
    assert runtime.approve(proposal, simulation, operator=operator, allow_relaxation=True)


def test_inflight_callback_delays_cutover_and_other_old_epoch_calls_never_start():
    runtime, registry, actors, _, operator = fixture()
    deploy(runtime, registry, actors, operator)
    gate = SwarmGate(registry, policy_runtime=runtime)
    gateway = SwarmToolGateway(clock=lambda: 100)
    handle = gateway.bind_agent(
        actors["a"][0], gate, actors["a"][1], actors["a"][2], routes=frozenset({"sdk"})
    )
    ticket = gateway.prepare(handle, ActionEnvelope.shell("git status")).ticket
    approved, _ = approval(runtime, operator, actors, policy(revision=2, default="deny"))
    entered, release, switched = Event(), Event(), Event()

    def execute(action):
        entered.set()
        assert release.wait(5)
        return "completed"

    def activate():
        result = runtime.activate(approved, operator=operator)
        switched.set()
        return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        forward = executor.submit(gateway.forward, handle, ticket, execute)
        assert entered.wait(5)
        update = executor.submit(activate)
        assert not switched.wait(0.05)
        release.set()
        assert forward.result(timeout=5).value == "completed"
        assert update.result(timeout=5).epoch == 2
    with pytest.raises(ValueError):
        gateway.forward(handle, ticket, execute)


def test_competing_approved_updates_have_one_atomic_winner():
    runtime, registry, actors, _, operator = fixture()
    deploy(runtime, registry, actors, operator)
    approvals = [
        approval(runtime, operator, actors, policy(revision=revision, default="deny"))[0]
        for revision in (2, 3)
    ]

    def activate(value):
        try:
            return runtime.activate(value, operator=operator).epoch
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(activate, approvals))
    assert results.count(2) == 1 and results.count(None) == 1 and runtime.epoch == 2


def test_budget_cutover_preserves_consumed_and_uncertain_and_rejects_fresh_zero_history():
    runtime, registry, actors, _, operator = fixture(budget=True)
    ledger = runtime._budget
    context, channel, adapter = actors["a"]
    selected = ActionEnvelope.shell("git status", action_id="spent")
    ticket = ledger.reserve(
        context,
        selected,
        channel=channel,
        adapter=adapter,
        idempotency_key="spent",
        costs=(BudgetCost("requests", 70),),
    )
    ledger.begin_forward(ticket, context, selected, channel=channel, adapter=adapter)
    ledger.commit(ticket)
    deployed = deploy(
        runtime,
        registry,
        actors,
        operator,
        policy(budgets=(SwarmBudgetConstraint("swarm", "requests", 80),)),
    )
    current = deployed.budget_ledger
    report = current.report(actors["a"][0], channel=actors["a"][1], adapter=actors["a"][2])
    assert report["limits"][0]["consumed"] == 70 and report["limits"][0]["remaining"] == 10
    fresh = BudgetLedger(registry, current.policy, clock=lambda: 100, operator=object())
    with pytest.raises(ValueError, match="reset"):
        runtime.rebind_sources(operator=operator, budget_ledger=fresh)


def test_post_fence_failure_consumes_epoch_and_leaves_every_old_authorization_invalid(monkeypatch):
    import ordin.swarm.policy_runtime as module

    runtime, registry, actors, _, operator = fixture(budget=True)
    deploy(runtime, registry, actors, operator)
    approved, _ = approval(runtime, operator, actors, policy(revision=2, default="deny"))

    def unavailable(*args, **kwargs):
        raise OSError("private budget path")

    monkeypatch.setattr(module, "BudgetLedger", unavailable)
    result = runtime.activate(approved, operator=operator)
    assert result.state == "failed_closed" and result.epoch == registry._policy_epoch == 2
    refresh(registry, actors)
    assert evaluate(SwarmGate(registry, policy_runtime=runtime), actors["a"]).denied
    assert "private budget path" not in json.dumps(result.as_dict())


def test_budget_facts_are_reissued_after_own_reservation_before_forwarding():
    runtime, registry, actors, _, operator = fixture(budget=True)
    selected = policy(
        rules=(
            SwarmPolicyRule(
                "nearly-exhausted",
                "deny",
                SwarmPolicySelector(budgets=(SwarmBudgetCondition("swarm", "requests", 10),)),
            ),
        )
    )
    activation = deploy(runtime, registry, actors, operator, selected)
    ledger = activation.budget_ledger
    gate = SwarmGate(registry, policy_runtime=runtime)

    def facts(context, action, gate, options):
        row = registry._agents[context.identity.agent_id]
        adapter = registry._channels[row.channel][0]
        values = ledger.report(context, channel=row.channel, adapter=adapter)["limits"]
        return runtime.facts_source.issue(
            context,
            action,
            policy_digest=gate.policy_digest,
            snapshot_digest=gate.evidence_snapshot_digest(context, **options),
            budgets=tuple(SwarmBudgetFact(v["scope"], v["metric"], v["remaining"]) for v in values),
        )

    gateway = SwarmToolGateway(
        clock=lambda: 100,
        budget_ledger=ledger,
        budget_cost_provider=lambda *args: (BudgetCost("requests", 70),),
    )
    handle = gateway.bind_agent(
        actors["a"][0],
        gate,
        actors["a"][1],
        actors["a"][2],
        routes=frozenset({"sdk"}),
        policy_facts_provider=facts,
    )
    authorized = gateway.prepare(
        handle, ActionEnvelope.shell("git status"), budget_idempotency_key="operation"
    )
    assert authorized.ticket is not None
    assert gateway.forward(handle, authorized.ticket, lambda action: "ok").value == "ok"
    assert (
        ledger.report(actors["a"][0], channel=actors["a"][1], adapter=actors["a"][2])["limits"][0][
            "consumed"
        ]
        == 70
    )


def test_post_reservation_policy_denial_releases_unforwarded_budget():
    runtime, registry, actors, _, operator = fixture(budget=True)
    selected = policy(
        rules=(
            SwarmPolicyRule(
                "protect-margin",
                "deny",
                SwarmPolicySelector(budgets=(SwarmBudgetCondition("swarm", "requests", 90),)),
            ),
        )
    )
    activation = deploy(runtime, registry, actors, operator, selected)
    ledger = activation.budget_ledger
    gate = SwarmGate(registry, policy_runtime=runtime)

    def facts(context, action, gate, options):
        row = registry._agents[context.identity.agent_id]
        adapter = registry._channels[row.channel][0]
        values = ledger.report(context, channel=row.channel, adapter=adapter)["limits"]
        return runtime.facts_source.issue(
            context,
            action,
            policy_digest=gate.policy_digest,
            snapshot_digest=gate.evidence_snapshot_digest(context, **options),
            budgets=tuple(SwarmBudgetFact(v["scope"], v["metric"], v["remaining"]) for v in values),
        )

    gateway = SwarmToolGateway(
        clock=lambda: 100,
        budget_ledger=ledger,
        budget_cost_provider=lambda *args: (BudgetCost("requests", 70),),
    )
    handle = gateway.bind_agent(
        actors["a"][0],
        gate,
        actors["a"][1],
        actors["a"][2],
        routes=frozenset({"sdk"}),
        policy_facts_provider=facts,
    )
    denied = gateway.prepare(
        handle, ActionEnvelope.shell("git status"), budget_idempotency_key="protected-margin"
    )
    assert denied.disposition == "deny" and denied.ticket is None
    values = ledger.report(actors["a"][0], channel=actors["a"][1], adapter=actors["a"][2])[
        "limits"
    ][0]
    assert values["reserved"] == values["consumed"] == 0


def test_positive_policy_fact_cannot_erase_legacy_mandatory_unknown_assessment():
    from ordin.swarm import SwarmAssessmentSource, SwarmPolicy

    runtime, registry, actors, _, operator = fixture()
    deploy(runtime, registry, actors, operator, policy(required_checks=("hard-check",)))
    source = SwarmAssessmentSource("existing-source", clock=lambda: 100)
    legacy = SwarmPolicy(
        "legacy", "1", required_checks=("hard-check",), unknown_disposition="escalate"
    )
    gate = SwarmGate(registry, policy=legacy, policy_runtime=runtime, assessment_source=source)
    context, _, _ = actors["a"]
    action = ActionEnvelope.shell("git status", action_id="action")
    bindings = dict(
        policy_digest=gate.policy_digest, snapshot_digest=gate.evidence_snapshot_digest(context)
    )
    receipt = source.issue(
        check_id="hard-check",
        status="unknown",
        action_digest=digest(action.as_dict()),
        context_digest=digest(context.as_dict()),
        **bindings,
    )
    facts = runtime.facts_source.issue(
        context, action, checks=(("hard-check", "satisfied"),), **bindings
    )
    decision = evaluate(gate, actors["a"], action, assessments=(receipt,), policy_facts=facts)
    assert not decision.may_execute and dict(decision.check_results)["hard-check"] == "unknown"


def test_required_unavailable_broker_and_all_paths_never_become_applied_from_flags():
    runtime, registry, actors, _, _ = fixture()
    for selected in (
        policy(required_capabilities=("broker.enforce",)),
        policy(enforcement_scope="all_agent_paths"),
        policy(
            enforcement_scope="broker_owned_fresh_worker_route",
            required_capabilities=("broker.enforce",),
        ),
    ):
        with pytest.raises(ValueError, match="unsupported|unavailable"):
            runtime.prepare(selected)
    assert registry._policy_epoch == 0
    with pytest.raises(ValueError):
        SwarmPolicySet.from_dict(policy().as_dict() | {"physical_enforcement": True})


def test_simulation_diff_is_redacted_scoped_and_foreign_tenant_never_executes():
    runtime, _, actors, _, _ = fixture()
    proposal = runtime.prepare(policy())
    foreign = replace(
        actors["a"][0], identity=replace(actors["a"][0].identity, tenant_id="foreign")
    )
    result = runtime.simulate(
        proposal,
        (SwarmPolicyReplayCase("foreign", foreign, ActionEnvelope.shell("git status"), "unsafe"),),
    )
    assert result.outcomes[0][2] == "deny" and not result.as_dict()["execution_authority"]
    assert "physical-a" not in json.dumps(result.as_dict())
    changed = diff_swarm_policies(policy(default="deny"), policy(revision=2))
    assert "default_disposition" in changed["changed_fields"]
    with pytest.raises(ValueError):
        diff_swarm_policies(policy(), replace(policy(), tenant_id="foreign"))


def test_permissive_policy_cannot_override_mandatory_assurance_escalation(tmp_path):
    from tests.assurance.test_source_flow import setup
    from tests.assurance.test_invariants import READ

    approved, source, assurance, _ = setup(tmp_path, READ)
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: 100)
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="fixture")
    context = registry.enroll(channel, adapter, agent_id=source.principal, session_id="physical")
    operator = object()
    maximum = SwarmPolicyMaximum(
        "tenant", "swarm", SwarmPolicyPermissions(action_kinds=("tool", "shell"))
    )
    runtime = SwarmPolicyRuntime(registry, maximum, operator=operator, clock=lambda: 100)
    proposal = runtime.prepare(policy())
    simulation = runtime.simulate(
        proposal,
        (SwarmPolicyReplayCase("baseline", context, ActionEnvelope.shell("git status"), "benign"),),
    )
    runtime.activate(runtime.approve(proposal, simulation, operator=operator), operator=operator)
    current = registry.refresh_policy_context(context, channel, adapter)
    gate = SwarmGate(registry, assurance, policy_runtime=runtime)
    snapshot = gate.evidence_snapshot_digest(current, host_context=source.context())
    facts = runtime.facts_source.issue(
        current,
        READ,
        policy_digest=gate.policy_digest,
        snapshot_digest=snapshot,
        checks=(("source-guard", "satisfied"),),
    )
    decision = gate.evaluate_action(
        current,
        READ,
        channel=channel,
        adapter=adapter,
        host_context=source.context(),
        policy_facts=facts,
    )
    assert decision.baseline.requires_approval and not decision.may_execute


def test_original_delegated_baseline_composition_does_not_repeat_quota_preview(tmp_path):
    from ordin.assurance import DelegatingAssuranceGate, DelegationIssuer, DelegationLimits
    from tests.assurance.test_delegating_gate import configured, action as read_action

    issuer, root, child_source, grant, old_gate, clock = configured(
        tmp_path, limits=DelegationLimits(in_flight_operations=1, actions_per_grant=1)
    )
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: 100)
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="fixture")
    parent = registry.enroll(
        channel, adapter, agent_id=issuer.source.principal, session_id="parent"
    )
    child = registry.enroll(
        channel,
        adapter,
        agent_id=child_source.principal,
        session_id="child",
        parent_agent_id=issuer.source.principal,
        delegation_id=grant.record.grant_id,
    )
    operator = object()
    maximum = SwarmPolicyMaximum(
        "tenant",
        "swarm",
        SwarmPolicyPermissions(action_kinds=("tool", "shell")),
        delegation_maximum_digest=issuer.operator_maximum.digest,
    )
    runtime = SwarmPolicyRuntime(
        registry, maximum, operator=operator, clock=lambda: 100, delegation_issuer=issuer
    )
    proposal = runtime.prepare(policy())
    simulation = runtime.simulate(
        proposal,
        (SwarmPolicyReplayCase("parent", parent, ActionEnvelope.shell("git status"), "benign"),),
    )
    runtime.activate(runtime.approve(proposal, simulation, operator=operator), operator=operator)
    registry.refresh_policy_context(parent, channel, adapter)
    child = registry.refresh_policy_context(child, channel, adapter)
    fresh_parent_source = replace(issuer.source, epoch=1)
    fresh_child_source = replace(child_source, epoch=1)
    fresh_issuer = DelegationIssuer(
        fresh_parent_source,
        issuer.profile,
        issuer.operator_maximum,
        issuer.task_maximum,
        limits=issuer.limits,
        clock=issuer._clock,
    )
    fresh_root = fresh_issuer.authorize_root(root.authority, grant_id="new-root", expires_at=200)
    fresh_grant = fresh_issuer.issue_child(
        fresh_root, fresh_child_source, grant.authority, grant_id="child", expires_at=150
    )
    runtime.rebind_sources(operator=operator, delegation_issuer=fresh_issuer)
    native_gate = DelegatingAssuranceGate(
        old_gate.assurance, fresh_issuer, fresh_grant, fresh_child_source
    )
    gate = SwarmGate(registry, native_gate, delegation_context=child, policy_runtime=runtime)
    action = read_action("native")
    original = native_gate.evaluate_action(action)
    assert original.may_execute
    assert native_gate.preview_action(read_action("second-preview")).denied
    composed = gate.evaluate_action(
        child, action, channel=channel, adapter=adapter, delegated_baseline=original
    )
    assert composed.may_execute and composed.baseline is original
    with pytest.raises(ValueError, match="original"):
        gate.evaluate_action(
            child, action, channel=channel, adapter=adapter, delegated_baseline=copy(original)
        )
    fresh_issuer.revoke(fresh_root)
    assert not gate.binding_matches(composed, child, action, channel=channel, adapter=adapter)
    denied = gate.evaluate_action(child, read_action("revoked"), channel=channel, adapter=adapter)
    assert denied.denied and denied.baseline.denied


def test_refresh_is_parent_first_same_session_and_never_revives_expired_principals():
    runtime, registry, actors, now, operator = fixture()
    approved, _ = approval(runtime, operator, actors, policy())
    runtime.activate(approved, operator=operator)
    context, channel, adapter = actors["a"]
    with pytest.raises(ValueError):
        registry.refresh_policy_context(context, channel, adapter)
    parent, pchannel, padapter = actors["parent"]
    refreshed_parent = registry.refresh_policy_context(parent, pchannel, padapter)
    refreshed_child = registry.refresh_policy_context(context, channel, adapter)
    assert refreshed_child.identity.session_id == context.identity.session_id
    assert refreshed_child.identity.parent_generation == refreshed_parent.identity.generation
    assert refreshed_child.coverage.mode == "uncovered"
    context, channel, adapter = actors["b"]
    now[0] += 3601
    with pytest.raises(ValueError):
        registry.refresh_policy_context(context, channel, adapter)


def test_independent_runtime_instances_share_the_registry_execution_barrier():
    first, registry, actors, _, operator = fixture()
    second = SwarmPolicyRuntime(registry, first.maximum, operator=object(), clock=lambda: 100)
    assert first.execution_barrier is second.execution_barrier
    deploy(first, registry, actors, operator)
    with pytest.raises(ValueError):
        second.prepare(policy())


def test_cli_validate_explain_diff_and_offline_simulation_never_deploy(tmp_path, capsys):
    from ordin.entrypoint import main
    from ordin.schema import validate_named_schema

    _, _, actors, _, _ = fixture()
    before, after = policy(default="deny"), policy(revision=2)
    maximum = SwarmPolicyMaximum("tenant", "swarm", SwarmPolicyPermissions(action_kinds=("shell",)))
    before_path, after_path, maximum_path, corpus_path = (
        tmp_path / name for name in ("before.json", "after.json", "maximum.json", "corpus.json")
    )
    before_path.write_text(json.dumps(before.as_dict()))
    after_path.write_text(json.dumps(after.as_dict()))
    maximum_path.write_text(json.dumps(maximum.as_dict()))
    corpus_path.write_text(
        json.dumps(
            {
                "schema_version": "ordin.swarm_policy_corpus.v1",
                "cases": [
                    {
                        "case_id": "benign",
                        "identity": actors["a"][0].identity.as_dict(),
                        "action": ActionEnvelope.shell("git status").as_dict(),
                        "expected": "benign",
                    },
                    {
                        "case_id": "unsafe",
                        "identity": actors["a"][0].identity.as_dict(),
                        "action": ActionEnvelope.shell("rm -rf /").as_dict(),
                        "expected": "unsafe",
                    },
                ],
            }
        )
    )
    contents = {
        path: path.read_bytes() for path in (before_path, after_path, maximum_path, corpus_path)
    }
    for command in ("validate", "explain"):
        assert (
            main(
                [
                    "swarm",
                    "policy",
                    command,
                    str(after_path),
                    "--maximum",
                    str(maximum_path),
                    "--json",
                ]
            )
            == 0
        )
        output = json.loads(capsys.readouterr().out)
        assert output["valid"] and output["maximum_checked"] and not output["deployment_authorized"]
        assert validate_named_schema("swarm_policy_validation", output) == []
    assert main(["swarm", "policy", "diff", str(before_path), str(after_path), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert validate_named_schema("swarm_policy_diff", output) == []
    assert (
        main(
            [
                "swarm",
                "policy",
                "simulate",
                str(after_path),
                "--before",
                str(before_path),
                "--maximum",
                str(maximum_path),
                "--corpus",
                str(corpus_path),
                "--json",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["evidence_class"] == "offline_simulation" and output["structural_relaxation"]
    assert output["unsafe_executable"] == 0 and not output["execution_authority"]
    assert validate_named_schema("swarm_policy_simulation", output) == []
    assert all(path.read_bytes() == value for path, value in contents.items())


def test_exact_url_literals_support_queries_and_ipv6_without_wildcard_language():
    values = ("https://api.invalid/v1?query=value", "https://[::1]/v1?query=value")
    selected = policy(permissions=SwarmPolicyPermissions(destinations=values))
    assert SwarmPolicySet.from_dict(selected.as_dict()).permissions.destinations == values
    for value in ("https://*.invalid/v1", "/workspace/*", "https://user:secret@api.invalid/v1"):
        with pytest.raises(ValueError):
            SwarmPolicyPermissions(destinations=(value,))


@pytest.mark.parametrize("order", list(permutations(("execute", "escalate", "deny"))))
def test_rule_order_does_not_change_most_restrictive_result(order):
    runtime, registry, actors, _, operator = fixture()
    selected = policy(rules=tuple(SwarmPolicyRule("rule-" + value, value) for value in order))
    deploy(runtime, registry, actors, operator, selected)
    assert evaluate(SwarmGate(registry, policy_runtime=runtime), actors["a"]).denied


def test_oversized_direct_policy_and_oversized_composed_checks_fail_before_epoch_change():
    roles = tuple("r" + "a" * 100 + str(index) for index in range(32))
    with pytest.raises(ValueError, match="byte"):
        policy(
            rules=tuple(
                SwarmPolicyRule("rule" + str(index), "deny", SwarmPolicySelector(role_ids=roles))
                for index in range(30)
            )
        )
    maximum = SwarmPolicyMaximum(
        "tenant",
        "swarm",
        SwarmPolicyPermissions(action_kinds=("shell",)),
        required_checks=tuple("maximum" + str(index) for index in range(64)),
    )
    with pytest.raises(ValueError, match="capacity"):
        compile_swarm_policy_set(policy(required_checks=("extra",)), maximum)


def test_copied_simulation_or_deployment_never_becomes_operator_authority():
    runtime, registry, actors, _, operator = fixture()
    proposal = runtime.prepare(policy())
    simulation = runtime.simulate(proposal, cases(actors))
    with pytest.raises(ValueError, match="original"):
        runtime.simulate(copy(proposal), cases(actors))
    with pytest.raises(ValueError, match="original"):
        runtime.approve(proposal, copy(simulation), operator=operator)
    assert registry._policy_epoch == 0


def test_policy_budget_wildcard_cannot_raise_a_specific_operator_maximum():
    maximum = SwarmPolicyMaximum(
        "tenant",
        "swarm",
        SwarmPolicyPermissions(action_kinds=("shell",)),
        budget_limits=(
            BudgetLimit("swarm", "requests", 100),
            BudgetLimit("agent", "requests", 10, subject="a"),
        ),
    )
    with pytest.raises(ValueError, match="maximum"):
        compile_swarm_policy_set(
            policy(budgets=(SwarmBudgetConstraint("agent", "requests", 20),)), maximum
        )


def test_policy_compilation_simulation_and_activation_reports_match_closed_schemas():
    from ordin.schema import validate_named_schema

    runtime, registry, actors, _, operator = fixture()
    selected = policy()
    proposal = runtime.prepare(selected)
    simulation = runtime.simulate(proposal, cases(actors))
    approved = runtime.approve(proposal, simulation, operator=operator)
    activated = runtime.activate(approved, operator=operator)
    compilation = compile_swarm_policy_set(selected, runtime.maximum)
    for name, value in (
        ("swarm_policy_set", selected.as_dict()),
        ("swarm_policy_maximum", runtime.maximum.as_dict()),
        ("swarm_policy_compilation", compilation.as_dict()),
        ("swarm_policy_simulation", simulation.as_dict()),
        ("swarm_policy_activation", activated.as_dict()),
    ):
        assert validate_named_schema(name, value) == []
        if "execution_authority" in value:
            assert value["execution_authority"] is False


def test_online_delegation_uses_current_policy_and_reload_fences_actual_tls_admission(tmp_path):
    from contextlib import ExitStack
    from ordin.assurance import DelegationIssuer, HostEvidenceSource
    from ordin.swarm.delegation import SwarmDelegationService
    from ordin.swarm.workload_auth import WorkloadAuthenticator
    from tests.test_swarm_delegation import configured, fingerprint, server_context, tls_pair
    from tests.assurance.test_delegation import child_max
    from tests.assurance.test_delegating_gate import action as read_action

    with configured(tmp_path) as data, ExitStack() as stack:
        (
            old_service,
            _,
            issuer,
            _,
            _,
            _,
            sources,
            contexts,
            registry,
            registry_channels,
            adapters,
            clock,
            service_operator,
            authority,
            _,
        ) = data
        operator = object()
        maximum = SwarmPolicyMaximum(
            "tenant",
            "swarm",
            SwarmPolicyPermissions(action_kinds=("shell", "tool")),
            delegation_maximum_digest=issuer.operator_maximum.digest,
        )
        runtime = SwarmPolicyRuntime(
            registry,
            maximum,
            operator=operator,
            clock=lambda: clock[0],
            delegation_service=old_service,
            delegation_operator=service_operator,
        )
        selected = policy()
        proposal = runtime.prepare(selected)
        simulation = runtime.simulate(
            proposal,
            (
                SwarmPolicyReplayCase(
                    "parent", contexts["parent"], ActionEnvelope.shell("git status"), "benign"
                ),
            ),
        )
        runtime.activate(
            runtime.approve(proposal, simulation, operator=operator), operator=operator
        )
        fresh_contexts = {}
        for name in ("parent", "child"):
            fresh_contexts[name] = registry.refresh_policy_context(
                contexts[name], registry_channels[name], adapters[name]
            )
        parent_source = replace(sources["parent"], epoch=1)
        child_source = replace(sources["child"], epoch=1)
        fresh_issuer = DelegationIssuer(
            parent_source, issuer.profile, authority, authority, clock=lambda: clock[0]
        )
        root = fresh_issuer.authorize_root(authority, grant_id="epoch-root", expires_at=200)
        tls = server_context()
        auth = WorkloadAuthenticator(
            registry, tls, operator=service_operator, clock=lambda: clock[0]
        )
        service = SwarmDelegationService(
            fresh_issuer, old_service.assurance, auth, operator=service_operator
        )
        enrollments, sockets = {}, {}
        for name, source in (("parent", parent_source), ("child", child_source)):
            enrollments[name] = auth.enroll_workload(
                host_id="host-a" if name == "parent" else "host-b",
                certificate_digest=fingerprint(name),
                context=fresh_contexts[name],
                source=source,
                channel=registry_channels[name],
                adapter=adapters[name],
                operator=service_operator,
            )
            sockets[name] = stack.enter_context(tls_pair(tls, name))[0]
        auth.enroll_broker(
            host_id="host-b", certificate_digest=fingerprint("broker-b"), operator=service_operator
        )
        sockets["broker-b"] = stack.enter_context(tls_pair(tls, "broker-b"))[0]
        root_ref = service.publish_root(enrollments["parent"], root, operator=service_operator)
        runtime.rebind_sources(
            operator=operator, delegation_service=service, delegation_operator=service_operator
        )
        parent_channel = auth.authenticate(sockets["parent"])
        child_grant = service.issue_child(
            parent_channel,
            root_ref.grant_id,
            enrollments["child"],
            child_max(),
            request_id="policy-child",
            lifetime=30,
        )
        service.bind_delegation_context(child_grant.grant_id, operator=service_operator)
        child_channel = auth.authenticate(sockets["child"])
        broker_channel = auth.authenticate(sockets["broker-b"])
        first = service.review(child_channel, child_grant.grant_id, read_action("first"))
        assert first.disposition == "execute" and first.admission_id is not None
        calls = []
        result = service.guarded_dispatch(
            broker_channel,
            first.admission_id,
            read_action("first"),
            lambda action: calls.append(action) or "ok",
        )
        assert result.status == "host_completed" and len(calls) == 1
        pending = service.review(child_channel, child_grant.grant_id, read_action("pending"))
        assert pending.admission_id is not None
        current_parent = auth.enrollment(enrollments["parent"]).context
        proposal = runtime.prepare(policy(revision=2, default="deny"))
        simulation = runtime.simulate(
            proposal,
            (
                SwarmPolicyReplayCase(
                    "parent", current_parent, ActionEnvelope.shell("git status"), "benign"
                ),
            ),
        )
        runtime.activate(
            runtime.approve(proposal, simulation, operator=operator), operator=operator
        )
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                broker_channel,
                pending.admission_id,
                read_action("pending"),
                lambda action: calls.append(action),
            )
        assert len(calls) == 1
