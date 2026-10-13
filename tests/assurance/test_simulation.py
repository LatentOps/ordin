"""Real independent sessions, immutable replay, and conservative change guards."""

from dataclasses import replace

import pytest

from ordin import ActionEnvelope, ActionHistory, AgentGate, Ordin, ReviewPolicy
from ordin.assurance._json import canonical_json, loads
from ordin.assurance.host import HostCapabilityAuthority
from ordin.assurance.models import InvariantSelectors, PolicySimulationReport, SecurityInvariant
from ordin.assurance.simulation import (
    FrozenCase,
    FrozenCorpus,
    SimulationPolicy,
    compare_capability_boundaries,
    freeze_trajectory,
    simulate_policy_change,
)
from ordin.execution import ActionObservation
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability, PrivilegeCapability
from ordin.runtime_contract import ToolCapability
from ordin.session import IntegrationSession
from ordin.trajectory_corpus import AgentTrajectory, TrajectoryStep

from .test_invariants import READ, SEMANTICS, WRITE
from .test_profiles import approve, config_profile, selected


def simulate(old, new, corpus, **kwargs):
    return simulate_policy_change(
        old, new, corpus, baseline_revision="fixture-v1", candidate_revision="fixture-v2", **kwargs
    )


def case(identifier="safe", action=None, **kwargs):
    return FrozenCase(
        identifier,
        action or ActionEnvelope.shell("git status --short"),
        expected=kwargs.pop("expected", "execute"),
        label=kwargs.pop("label", "benign"),
        **kwargs,
    )


def test_identical_configuration_replays_baseline_without_permission_change():
    corpus = FrozenCorpus.synthetic(
        (
            case(),
            case(
                "blocked",
                ActionEnvelope.shell("rm -rf /"),
                expected="deny",
                label="adversarial",
                critical=True,
            ),
        )
    )
    policy = SimulationPolicy()
    result = simulate(policy, policy, corpus, expected_corpus_digest=corpus.digest)
    assert result.activation_safe and result.coverage == "complete"
    assert result.critical_caught == 1 and result.critical_misses == 0
    assert result.policy_authority_delta == "unchanged"
    assert {v.change for v in result.cases} == {"unchanged"}
    assert (
        result.cases[0].baseline_final
        == AgentGate().evaluate_action(corpus.cases[0].action).disposition
    )
    assert PolicySimulationReport.from_json(canonical_json(result.as_dict())) == result
    assert result.coverage_by_kind[0].total == 2
    assert result.baseline_latency.samples == result.candidate_latency.samples == 2
    assert all(v.baseline_core_ms <= v.baseline_ms for v in result.cases)


def test_approval_becomes_execution_and_critical_miss_rejects_guard():
    unknown = ActionEnvelope(
        "mcp", "call", {"server": "fixture", "tool": "unknown", "arguments": {}}
    )
    corpus = FrozenCorpus.synthetic(
        (case("unknown", unknown, expected="escalate", label="adversarial", critical=True),)
    )
    result = simulate(
        SimulationPolicy(), SimulationPolicy(Ordin(policy=ReviewPolicy("block"))), corpus
    )
    assert result.newly_executable == ("unknown",)
    assert (
        result.cases[0].baseline_core == "escalate" and result.cases[0].candidate_core == "execute"
    )
    assert "assurance.simulation_approval_removed" in result.cases[0].reason_codes
    assert result.critical_misses == 1 and result.policy_authority_delta == "widened"
    assert not result.activation_safe


def test_tighter_threshold_reports_new_escalation_and_benign_friction():
    corpus = FrozenCorpus.synthetic((case("write", WRITE),))
    loose = SimulationPolicy(Ordin(policy=ReviewPolicy("block"), tool_semantics=SEMANTICS))
    strict = SimulationPolicy(Ordin(tool_semantics=SEMANTICS))
    result = simulate(loose, strict, corpus)
    assert result.newly_escalated == ("write",)
    assert result.benign_false_escalations == 1 and result.benign_false_denials == 0
    assert result.policy_authority_delta == "narrowed" and result.activation_safe


def test_profile_blocks_production_and_preserves_benign_control(tmp_path):
    approved = approve(
        selected(
            tmp_path,
            config_profile(
                SecurityInvariant(
                    "protect-production",
                    "protected_policy_mutation",
                    InvariantSelectors(resource_ref="prod"),
                    on_violation="block",
                )
            ),
        )
    )
    core = Ordin(tool_semantics=SEMANTICS)
    corpus = FrozenCorpus.synthetic(
        (
            case("production", WRITE, expected="deny", label="adversarial", critical=True),
            case("read", READ),
        )
    )
    result = simulate(SimulationPolicy(core), SimulationPolicy(core, approved), corpus)
    assert result.newly_denied == ("production",)
    assert result.cases[1].candidate_final == result.cases[1].baseline_final == "execute"
    assert result.new_profile_digest == approved.digest
    assert result.new_profile_selection_digest == approved.selection_digest
    assert result.critical_caught == 1
    assert result.policy_authority_delta == "unknown" and not result.activation_safe


def test_independent_session_history_includes_denied_proposals(monkeypatch):
    snapshots = []
    original = IntegrationSession.evaluate

    def record(self, action, **kwargs):
        result = original(self, action, **kwargs)
        snapshots.append((self, self.snapshot()))
        return result

    monkeypatch.setattr(IntegrationSession, "evaluate", record)
    corpus = FrozenCorpus.synthetic(
        (
            case("denied", ActionEnvelope.shell("rm -rf /"), expected="deny", label="adversarial"),
            case("retry"),
        )
    )
    simulate(SimulationPolicy(), SimulationPolicy(), corpus)
    assert len(snapshots) == 4
    assert snapshots[0][0] is snapshots[1][0]
    assert snapshots[2][0] is snapshots[3][0]
    assert snapshots[0][0] is not snapshots[2][0]
    for _, snapshot in (snapshots[1], snapshots[3]):
        assert [v["action_id"] for v in snapshot["history"]["actions"]] == ["denied", "retry"]
        assert snapshot["denied_action_ids"] == ["denied"]


def test_sessions_and_epochs_do_not_reuse_state(monkeypatch):
    states = []
    original = IntegrationSession.evaluate

    def record(self, action, **kwargs):
        result = original(self, action, **kwargs)
        states.append(self.snapshot()["history"]["actions"])
        return result

    monkeypatch.setattr(IntegrationSession, "evaluate", record)
    corpus = FrozenCorpus.synthetic(
        (
            case("one", principal="agent-one"),
            case("two", principal="agent-two"),
            case("reset", principal="agent-one", epoch=1),
        )
    )
    simulate(SimulationPolicy(), SimulationPolicy(), corpus)
    assert all(len(v) == 1 for v in states)
    with pytest.raises(ValueError, match="stale session epoch"):
        FrozenCorpus.synthetic((case("new", epoch=1), case("old", epoch=0)))


def test_deep_freeze_actions_and_policy_and_public_copies():
    action = ActionEnvelope(
        "tool",
        "call",
        {"runtime": "fixture", "tool": "read_file", "arguments": {"path": "/fixture/source"}},
    )
    frozen = case("frozen", action)
    corpus = FrozenCorpus.synthetic((frozen,))
    original_digest = corpus.digest
    action.parameters["arguments"]["path"] = "/other"
    frozen.action.parameters["arguments"]["path"] = "/again"
    public = corpus.as_dict()
    public["cases"][0]["action"]["parameters"]["arguments"]["path"] = "/third"
    assert corpus.digest == original_digest
    assert frozen.as_dict()["action"]["parameters"]["arguments"]["path"] == "/fixture/source"
    policy = SimulationPolicy(Ordin(tool_semantics=SEMANTICS))
    assert (
        SimulationPolicy.from_dict(loads(canonical_json(policy.as_dict()))).digest == policy.digest
    )


def test_missing_changed_duplicate_or_unknown_fixtures_cannot_pass():
    first = case()
    manifest = {first.case_id: first.digest, "required": "a" * 64}
    corpus = FrozenCorpus((first,), manifest, "synthetic_fixture", True)
    result = simulate(SimulationPolicy(), SimulationPolicy(), corpus)
    assert result.missing_required_cases == ("required",) and not result.activation_safe
    with pytest.raises(ValueError, match="content/version digest mismatch"):
        FrozenCorpus((replace(first, expected="deny"),), {first.case_id: first.digest})
    with pytest.raises(ValueError, match="duplicate replay case"):
        FrozenCorpus.synthetic((first, first))
    with pytest.raises(ValueError, match="corpus digest mismatch"):
        simulate(
            SimulationPolicy(),
            SimulationPolicy(),
            FrozenCorpus.synthetic((first,)),
            expected_corpus_digest="f" * 64,
        )
    result = simulate(
        SimulationPolicy(),
        SimulationPolicy(),
        FrozenCorpus.synthetic((case("unknown", label="unknown"),)),
    )
    assert result.unassessable == ("unknown",) and result.coverage == "partial"


def test_imported_report_cannot_hide_regressions_or_contradict_passing_summary():
    policy = SimulationPolicy()
    report = simulate(policy, policy, FrozenCorpus.synthetic((case(),)))
    packet = report.as_dict()
    packet["cases"][0]["candidate_core"] = "deny"
    with pytest.raises(ValueError, match="cannot weaken"):
        PolicySimulationReport.from_dict(packet)
    packet = report.as_dict()
    packet["cases"][0]["change"] = "newly_denied"
    with pytest.raises(ValueError, match="change does not match"):
        PolicySimulationReport.from_dict(packet)
    packet = report.as_dict()
    packet["coverage_by_kind"] = []
    with pytest.raises(ValueError, match="passing simulation summary"):
        PolicySimulationReport.from_dict(packet)


def test_caller_observation_after_refused_proposal_is_partial(monkeypatch):
    observed = []
    original = IntegrationSession.observe

    def record(self, observation):
        observed.append(observation)
        original(self, observation)

    monkeypatch.setattr(IntegrationSession, "observe", record)
    # The existing observation format is intentionally reused, not backend evidence.
    observation = ActionObservation.from_dict(
        {
            "schema_version": "ordin.action_observation.v1",
            "action_id": "blocked",
            "exit_code": 0,
            "effects": [],
            "resources": [],
        }
    )
    corpus = FrozenCorpus.synthetic(
        (
            case(
                "blocked",
                ActionEnvelope.shell("rm -rf /", action_id="blocked"),
                expected="deny",
                label="adversarial",
                observation=observation,
            ),
        )
    )
    result = simulate(SimulationPolicy(), SimulationPolicy(), corpus)
    assert observed == [] and result.unassessable == ("blocked",) and not result.activation_safe


def test_unresolved_mandatory_profile_evidence_stays_partial(tmp_path):
    approved = approve(
        selected(
            tmp_path,
            config_profile(
                SecurityInvariant(
                    "source-flow",
                    "source_flow_guard",
                    InvariantSelectors(effects=("filesystem.read",)),
                )
            ),
        )
    )
    policy = SimulationPolicy(Ordin(tool_semantics=SEMANTICS), approved)
    result = simulate(policy, policy, FrozenCorpus.synthetic((case("read", READ),)))
    assert result.cases[0].candidate_final == "escalate"
    assert result.coverage == "partial" and not result.activation_safe


def test_boundary_comparison_checks_every_domain_and_directory_boundary():
    old = RuntimeCapabilityBoundary(
        "old",
        filesystem=(FilesystemCapability("read", "/repo", "prefix"),),
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )
    narrow = replace(
        old, boundary_id="new", filesystem=(FilesystemCapability("read", "/repo/file", "exact"),)
    )
    assert compare_capability_boundaries(old, narrow) == "narrowed"
    assert compare_capability_boundaries(narrow, old) == "widened"
    assert (
        compare_capability_boundaries(
            old, replace(narrow, filesystem=(FilesystemCapability("read", "/repo2/file", "exact"),))
        )
        == "widened"
    )
    assert (
        compare_capability_boundaries(
            old, replace(old, privilege=PrivilegeCapability(escalation=True, required_euid=0))
        )
        == "widened"
    )
    unknown = replace(old, filesystem=(FilesystemCapability("unknown", None, "unknown"),))
    assert compare_capability_boundaries(old, unknown) == "unsupported"
    result = simulate(
        SimulationPolicy(capability_authorities=(HostCapabilityAuthority("maximum", old),)),
        SimulationPolicy(capability_authorities=(HostCapabilityAuthority("maximum", narrow),)),
        FrozenCorpus.synthetic((case(),)),
    )
    assert result.policy_authority_delta == "narrowed"


def test_json_never_imports_profile_authority_and_audit_sink_never_runs():
    payload = SimulationPolicy().as_dict()
    payload["profile_digest"] = "a" * 64
    with pytest.raises(ValueError, match="JSON cannot activate"):
        SimulationPolicy.from_dict(payload)

    class Sink:
        def record(self, review):
            pytest.fail("simulation may not write audit state")

    with pytest.raises(ValueError, match="audit sink"):
        SimulationPolicy(Ordin(audit=Sink()))


def test_existing_trajectory_adapter_preserves_order_and_contract_checks():
    trajectory = AgentTrajectory(
        "fixture-trajectory",
        "fixture",
        "synthetic",
        ("benign_multi_step",),
        (
            TrajectoryStep(
                ActionEnvelope.shell("git status --short", action_id="step-one"), "allow"
            ),
            TrajectoryStep(ActionEnvelope.shell("rm -rf /", action_id="step-two"), "block"),
        ),
    )
    cases = freeze_trajectory(trajectory, label="adversarial")
    assert [v.as_dict()["action"]["action_id"] for v in cases] == ["step-one", "step-two"]
    result = simulate(SimulationPolicy(), SimulationPolicy(), FrozenCorpus.synthetic(cases))
    assert [v.candidate_final for v in result.cases] == ["execute", "deny"]


def test_principal_selected_maxima_produce_distinct_agent_outcomes(tmp_path):
    rules = tuple(
        SecurityInvariant(
            f"{principal}-subset",
            "resource_subset",
            InvariantSelectors(effects=("filesystem.read",), principal=principal),
            on_violation="block",
            authority_ref=principal,
        )
        for principal in ("reader", "writer")
    )
    approved = approve(selected(tmp_path, config_profile(*rules)))
    authorities = tuple(
        HostCapabilityAuthority(
            principal,
            RuntimeCapabilityBoundary(
                principal,
                filesystem=(FilesystemCapability("read", path, "prefix"),),
                tools=(ToolCapability("fixture", None, "read_file"),),
                filesystem_semantics="lexical_prefix",
                runtime_filesystem_guarantees=True,
            ),
        )
        for principal, path in (("reader", "/fixture/docs"), ("writer", "/fixture"))
    )
    old = SimulationPolicy(Ordin(tool_semantics=SEMANTICS))
    candidate = SimulationPolicy(
        Ordin(tool_semantics=SEMANTICS), approved, capability_authorities=authorities
    )
    corpus = FrozenCorpus.synthetic(
        (
            case("reader-proposal", READ, principal="reader", expected="deny", label="adversarial"),
            case("writer-proposal", READ, principal="writer"),
        )
    )
    result = simulate(old, candidate, corpus)
    assert [v.candidate_final for v in result.cases] == ["deny", "execute"]
    assert result.unassessable == ()


def test_golden_scenarios_are_offline_read_only_and_preserve_decision_replay(monkeypatch):
    import socket
    import subprocess
    from pathlib import Path
    from scripts.freeze_assurance_simulation import DESTINATION, inputs
    from ordin.assurance._json import loads

    def unexpected(*args, **kwargs):
        raise AssertionError("simulation attempted an external process or network connection")

    monkeypatch.setattr(socket, "create_connection", unexpected)
    monkeypatch.setattr(subprocess, "Popen", unexpected)
    old, new, corpus = inputs()
    frozen = FrozenCorpus.from_dict(loads((DESTINATION / "simulation-corpus.json").read_bytes()))
    assert frozen.digest == corpus.digest
    assert len(corpus.cases) == 22 and len({v.family for v in corpus.cases}) == 11
    snapshot = {v.name: v.read_bytes() for v in DESTINATION.iterdir() if v.is_file()}
    first, second = simulate(old, new, frozen), simulate(old, new, frozen)
    assert [(v.case_id, v.candidate_final, v.reason_codes) for v in first.cases] == [
        (v.case_id, v.candidate_final, v.reason_codes) for v in second.cases
    ]
    assert first.newly_denied == ("production_write:adversarial", "policy_alteration:adversarial")
    assert first.critical_misses == 0 and first.benign_false_escalations == 3
    assert first.coverage == "partial" and not first.activation_safe
    assert {v.name: v.read_bytes() for v in DESTINATION.iterdir() if v.is_file()} == snapshot
