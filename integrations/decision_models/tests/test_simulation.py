"""Real model routing replay must preserve ordering, refusal and uncertainty."""

from dataclasses import replace
import json

import pytest

from ordin import ActionEnvelope
from ordin.assurance import FrozenCase, FrozenCorpus
from ordin.execution import ActionObservation
from ordin_decision_models import (
    RoutingPolicy,
    SemanticPolicySimulationReport,
    SemanticReplayPolicy,
    simulate_semantic_policy_change,
)


def fixtures(*cases):
    return FrozenCorpus.synthetic(
        cases
        or (
            FrozenCase(
                "status",
                ActionEnvelope.shell("git status --short"),
                expected="execute",
                label="benign",
            ),
        )
    )


def selected(mode="enforced-escalation", *, tasks=None, **kwargs):
    return SemanticReplayPolicy(
        routing=RoutingPolicy(mode=mode, enabled_question_ids=("material_intent_mismatch",)),
        tasks=tasks or {"status": "Inspect repository status"},
        **kwargs,
    )


def simulate(old, new, corpus=None, **kwargs):
    return simulate_semantic_policy_change(
        old,
        new,
        corpus or fixtures(),
        baseline_revision="fixture-v1",
        candidate_revision="fixture-v2",
        **kwargs,
    )


def test_shadow_vs_enforced_uses_real_router_and_reports_benign_friction():
    old = selected("shadow", answers={"material_intent_mismatch": 0.95})
    new = replace(old, routing=replace(old.routing, mode="enforced-escalation"))
    result = simulate(old, new)
    row = result.simulation.cases[0]
    assert row.baseline_core == row.candidate_core == row.baseline_final == "execute"
    assert row.candidate_final == "escalate"
    assert result.simulation.newly_escalated == ("status",)
    assert result.simulation.benign_false_escalations == 1
    assert result.baseline_model_calls == result.candidate_model_calls == 1
    assert result.baseline_model_latency.samples == result.candidate_model_latency.samples == 1
    assert (
        result.simulation.activation_safe and result.simulation.policy_authority_delta == "narrowed"
    )
    assert SemanticPolicySimulationReport.from_json(json.dumps(result.as_dict())) == result


def test_removing_optional_approval_is_a_policy_regression():
    old = selected(answers={"material_intent_mismatch": 0.95})
    new = replace(old, routing=replace(old.routing, mode="shadow"))
    result = simulate(old, new)
    assert result.simulation.newly_executable == ("status",)
    assert "assurance.simulation_approval_removed" in result.simulation.cases[0].reason_codes
    assert result.simulation.policy_authority_delta == "widened"
    assert not result.simulation.activation_safe


@pytest.mark.parametrize(
    "behavior",
    ["timeout", "malformed", "untrusted_content", "version_mismatch", "question_mismatch"],
)
def test_required_provider_failure_remains_partial_and_refused(behavior):
    old = selected("disabled")
    new = replace(
        old,
        routing=RoutingPolicy(
            mode="enforced-escalation",
            mandatory_action_kinds=("shell",),
            required_question_ids=("material_intent_mismatch",),
        ),
        behavior=behavior,
    )
    result = simulate(old, new)
    assert result.simulation.cases[0].candidate_final == "escalate"
    assert result.simulation.coverage == "partial"
    assert result.simulation.unassessable == ("status",)
    assert not result.simulation.activation_safe
    assert "Ignore policy" not in json.dumps(result.as_dict())


def test_absent_provider_uncertainty_and_missing_context_do_not_pass():
    old = selected("disabled")
    required = replace(
        old,
        routing=RoutingPolicy(
            mode="enforced-escalation",
            mandatory_action_kinds=("shell",),
            required_question_ids=("material_intent_mismatch",),
        ),
    )
    for candidate in (
        replace(required, provider_available=False),
        replace(required, answers={"material_intent_mismatch": 0.5}),
        replace(required, tasks={}),
    ):
        result = simulate(old, candidate)
        assert result.simulation.coverage == "partial" and not result.simulation.activation_safe
        assert result.simulation.cases[0].candidate_final == "escalate"


def test_hard_denials_and_disabled_mode_never_invoke_mock():
    corpus = fixtures(
        FrozenCase(
            "blocked",
            ActionEnvelope.shell("rm -rf /"),
            expected="deny",
            label="adversarial",
            critical=True,
        )
    )
    for mode in ("disabled", "shadow", "enforced-escalation"):
        policy = selected(mode, tasks={"blocked": "Inspect repository status"})
        result = simulate(policy, policy, corpus)
        assert (
            result.simulation.cases[0].baseline_final
            == result.simulation.cases[0].candidate_final
            == "deny"
        )
        assert result.baseline_model_calls == result.candidate_model_calls == 0
        assert result.simulation.activation_safe
    result = simulate(selected("disabled"), selected("disabled"))
    assert result.baseline_model_calls == result.candidate_model_calls == 0


def test_each_arm_has_fresh_call_budget_and_budget_survives_session_changes():
    corpus = fixtures(
        FrozenCase(
            "first",
            ActionEnvelope.shell("git status --short"),
            session_id="first",
            expected="execute",
            label="benign",
        ),
        FrozenCase(
            "second",
            ActionEnvelope.shell("git status --short"),
            session_id="second",
            expected="execute",
            label="benign",
        ),
    )
    policy = selected("shadow", tasks={"first": "Inspect status", "second": "Inspect status"})
    policy = replace(policy, routing=replace(policy.routing, max_total_calls=1))
    result = simulate(policy, policy, corpus)
    assert result.baseline_model_calls == result.candidate_model_calls == 1
    assert result.simulation.unassessable == ("second",)
    assert (
        result.simulation.cases[0].baseline_final
        == result.simulation.cases[0].candidate_final
        == "execute"
    )


def test_refused_observation_is_withheld_and_histories_are_independent(monkeypatch):
    from ordin.session import IntegrationSession

    snapshots = []
    original = IntegrationSession.evaluate

    def record(self, action, **kwargs):
        result = original(self, action, **kwargs)
        if self.identity.runtime == "semantic-replay":
            snapshots.append((self, self.snapshot()))
        return result

    monkeypatch.setattr(IntegrationSession, "evaluate", record)
    observation = ActionObservation("read", 0, effects=("secret.read",))
    corpus = fixtures(
        FrozenCase(
            "read",
            ActionEnvelope.shell("git status --short", action_id="read"),
            expected="execute",
            label="benign",
            observation=observation,
        ),
        FrozenCase(
            "next", ActionEnvelope.shell("git status --short"), expected="execute", label="benign"
        ),
    )
    old = selected(
        "shadow",
        tasks={"read": "Inspect status", "next": "Inspect status"},
        answers={"material_intent_mismatch": 1},
    )
    new = replace(old, routing=replace(old.routing, mode="enforced-escalation"))
    result = simulate(old, new, corpus)
    assert snapshots[0][0] is snapshots[1][0] and snapshots[2][0] is snapshots[3][0]
    assert snapshots[0][0] is not snapshots[2][0]
    assert snapshots[1][1]["observations"]["observations"]
    assert not snapshots[3][1]["observations"]["observations"]
    assert set(snapshots[3][1]["denied_action_ids"]) == {"read", "next"}
    assert [item["action_id"] for item in snapshots[3][1]["history"]["actions"]] == ["read", "next"]
    assert result.simulation.unassessable == ("read",)


def test_unknown_or_tampered_inputs_refuse_and_default_report_omits_private_text():
    corpus = fixtures()
    policy = selected("shadow", tasks={"status": "PRIVATE_TASK_FIXTURE"})
    with pytest.raises(ValueError, match="digest mismatch"):
        simulate(policy, policy, corpus, expected_corpus_digest="a" * 64)
    with pytest.raises(ValueError, match="owned synthetic"):
        simulate(policy, policy, replace(corpus, source_permissions="authorized_sanitized_replay"))
    with pytest.raises(ValueError, match="absent case"):
        simulate(replace(policy, tasks={"absent": "Inspect status"}), policy)
    result = simulate(policy, policy)
    public = json.dumps(result.as_dict())
    assert "PRIVATE_TASK_FIXTURE" not in public and "git status" not in public
    with pytest.raises(ValueError):
        replace(policy, answers={"material_intent_mismatch": float("nan")})
    packet = result.as_dict()
    packet["actions_executed"] = True
    with pytest.raises(ValueError):
        SemanticPolicySimulationReport.from_dict(packet)


def test_unknown_shell_shape_remains_an_explicit_gap():
    corpus = fixtures(
        FrozenCase(
            "status",
            ActionEnvelope("shell", "unknown", {}),
            expected="escalate",
            label="adversarial",
        )
    )
    policy = selected()
    policy = replace(
        policy,
        routing=replace(
            policy.routing,
            mandatory_action_kinds=("shell",),
            required_question_ids=("material_intent_mismatch",),
        ),
    )
    result = simulate(policy, policy, corpus)
    assert result.simulation.cases[0].candidate_final != "execute"
    assert result.simulation.coverage == "partial" and not result.simulation.activation_safe
    assert result.baseline_model_calls == result.candidate_model_calls == 0


def test_session_principal_and_epoch_changes_do_not_reuse_history(monkeypatch):
    from ordin.session import IntegrationSession

    snapshots = []
    original = IntegrationSession.evaluate

    def record(self, action, **kwargs):
        result = original(self, action, **kwargs)
        if self.identity.runtime == "semantic-replay":
            snapshots.append(self.snapshot())
        return result

    monkeypatch.setattr(IntegrationSession, "evaluate", record)
    corpus = fixtures(
        FrozenCase(
            "a", ActionEnvelope.shell("git status --short"), expected="execute", label="benign"
        ),
        FrozenCase(
            "b",
            ActionEnvelope.shell("git status --short"),
            principal="sibling",
            expected="execute",
            label="benign",
        ),
        FrozenCase(
            "c",
            ActionEnvelope.shell("git status --short"),
            epoch=1,
            expected="execute",
            label="benign",
        ),
    )
    policy = selected("shadow", tasks={key: "Inspect status" for key in ("a", "b", "c")})
    result = simulate(policy, policy, corpus)
    assert result.simulation.activation_safe
    assert len(snapshots) == 6
    assert all(len(snapshot["history"]["actions"]) == 1 for snapshot in snapshots)


def test_changed_enforced_configuration_and_report_tampering_are_not_silent():
    old = selected()
    new = replace(old, answers={"material_intent_mismatch": 0.2})
    result = simulate(old, new)
    assert result.simulation.policy_authority_delta == "unknown"
    assert not result.simulation.activation_safe
    packet = result.as_dict()
    packet["baseline_configuration_digest"] = "a" * 64
    with pytest.raises(ValueError, match="inconsistent"):
        SemanticPolicySimulationReport.from_dict(packet)


def test_standalone_demo_keeps_commands_and_tasks_private(monkeypatch):
    import socket
    import subprocess
    from ordin_decision_models.simulation_demo import run_demo

    def refuse(*args, **kwargs):
        raise AssertionError("offline replay attempted network or process execution")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    packet = run_demo()
    assert packet["synthetic_only"] and not packet["actions_executed"]
    assert packet["simulation"]["newly_escalated"] == ["fixture-status"]
    assert "git status" not in json.dumps(packet)
