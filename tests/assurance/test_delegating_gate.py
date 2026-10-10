"""Current grant checks, exact use binding, independent sessions and quotas."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import (
    AssuranceGate,
    DelegatedDecision,
    DelegatingAssuranceGate,
    DelegationLimits,
)
from ordin.execution import ActionObservation

from .test_delegation import issuer_fixture, child_max
from .test_invariants import SEMANTICS, ADAPTER


def configured(tmp_path, *, limits=None):
    issuer, root, parent, source, clock = issuer_fixture(tmp_path, limits=limits)
    grant = issuer.issue_child(root, source, child_max(), grant_id="child", expires_at=150)
    gate = DelegatingAssuranceGate(
        AssuranceGate(AgentGate(Ordin(tool_semantics=SEMANTICS)), issuer.profile),
        issuer,
        grant,
        source,
    )
    return issuer, root, source, grant, gate, clock


def action(identifier="read", path="/fixture/source"):
    return ADAPTER.adapt("read_file", {"path": path}, action_id=identifier)


def test_normal_child_read_binds_and_commits_only_once(tmp_path):
    issuer, root, source, grant, gate, clock = configured(tmp_path)
    result = gate.evaluate_action(action())
    assert result.may_execute and result.verification.ok
    assert gate.binding_matches(result, result.assurance.review.action)
    assert gate.commit_use(result, result.assurance.review.action)
    assert not gate.commit_use(result, result.assurance.review.action)
    with pytest.raises(ValueError, match="JSON decisions"):
        DelegatedDecision.from_dict(result.as_dict())


def test_child_cannot_read_env_or_lexical_neighbor_or_impersonate_parent(tmp_path):
    issuer, root, source, grant, gate, clock = configured(tmp_path)
    for index, path in enumerate(("/fixture/.env", "/fixture2/source", "/fixture/source2")):
        result = gate.evaluate_action(action(f"bad{index}", path))
        assert result.denied and not result.verification.ok
    forged = action("forged")
    forged = replace(forged, parameters={**forged.parameters, "principal": "parent"})
    result = gate.evaluate_action(forged)
    assert result.may_execute  # Principal text adds no rights; this exact read is already allowed.
    with pytest.raises(ValueError, match="host context"):
        gate.evaluate_action(
            action("bad-context"), host_context={"principal": "parent", "approved": True}
        )


def test_pending_operation_refuses_expired_or_revoked_parent(tmp_path):
    for mode in ("revoked", "expired"):
        directory = tmp_path / mode
        directory.mkdir()
        issuer, root, source, grant, gate, clock = configured(directory)
        result = gate.evaluate_action(action())
        assert result.may_execute
        if mode == "revoked":
            issuer.revoke(root)
        else:
            clock[0] = 150
        assert not gate.commit_use(result, result.assurance.review.action)
        assert gate.evaluate_action(action("after")).denied


def test_changed_argument_policy_or_action_id_cannot_reuse_ticket(tmp_path):
    issuer, root, source, grant, gate, clock = configured(tmp_path)
    for index, changes in enumerate(
        (
            {"action_id": "other"},
            {
                "parameters": {
                    "runtime": "fixture",
                    "tool": "read_file",
                    "arguments": {"path": "/fixture/.env"},
                }
            },
        )
    ):
        result = gate.evaluate_action(action(f"read{index}"))
        assert not gate.commit_use(result, replace(result.assurance.review.action, **changes))
    result = gate.evaluate_action(action("policy-change"))
    issuer.invalidate_policy()
    assert not gate.binding_matches(result, result.assurance.review.action)


def test_inflight_and_action_quotas_are_host_owned(tmp_path):
    issuer, root, source, grant, gate, clock = configured(
        tmp_path, limits=DelegationLimits(in_flight_operations=1, actions_per_grant=2)
    )
    first = gate.evaluate_action(action("first"))
    assert first.may_execute
    assert gate.evaluate_action(action("blocked-pending")).denied
    assert gate.commit_use(first, first.assurance.review.action)
    second = gate.evaluate_action(action("second"))
    assert second.may_execute and gate.commit_use(second, second.assurance.review.action)
    assert gate.evaluate_action(action("quota-exhausted")).denied


def test_sibling_sessions_do_not_share_actions_or_observations(tmp_path):
    issuer, root, source, grant, first, clock = configured(tmp_path)
    sibling_source = replace(source, principal="sibling", session_digest="e" * 64)
    sibling_grant = issuer.issue_child(
        root, sibling_source, child_max(), grant_id="sibling", expires_at=150
    )
    second = DelegatingAssuranceGate(first.assurance, issuer, sibling_grant, sibling_source)
    one = first.evaluate_action(action("one"))
    two = second.evaluate_action(action("two"))
    assert one.may_execute and two.may_execute
    assert [a["action_id"] for a in first.snapshot()["history"]["actions"]] == ["one"]
    assert [a["action_id"] for a in second.snapshot()["history"]["actions"]] == ["two"]
    with pytest.raises(ValueError, match="retained"):
        second.observe(ActionObservation("one", exit_code=0))
    assert not second.commit_use(one, one.assurance.review.action)


def test_concurrent_child_reviews_have_exact_independent_tickets(tmp_path):
    issuer, root, source, grant, gate, clock = configured(
        tmp_path, limits=DelegationLimits(in_flight_operations=32)
    )

    def review(index):
        return gate.evaluate_action(action(f"read{index}"))

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(review, range(12)))
    assert all(r.may_execute for r in results)
    assert len({r.action_digest for r in results}) == 12
    assert all(gate.commit_use(r, r.assurance.review.action) for r in results)


def test_core_block_stays_denied_and_denied_proposals_remain_in_child_history(tmp_path):
    issuer, root, source, grant, gate, clock = configured(tmp_path)
    result = gate.evaluate_action(ActionEnvelope.shell("rm -rf /", action_id="denied"))
    assert result.denied and result.verification is None
    assert result.reason_codes == ("delegation.core_denied",)
    assert gate.snapshot()["denied_action_ids"] == ["denied"]


def test_host_session_or_maximum_change_invalidates_existing_grants(tmp_path):
    issuer, root, source, grant, gate, clock = configured(tmp_path)
    result = gate.evaluate_action(action())
    issuer.source = replace(issuer.source, epoch=1)
    assert not gate.commit_use(result, result.assurance.review.action)
    with pytest.raises(ValueError, match="configuration changed"):
        issuer.require_current(grant, source)


def test_mutation_between_review_and_commit_is_rechecked_under_issuer_lock(tmp_path):
    issuer, root, source, grant, gate, clock = configured(tmp_path)
    result = gate.evaluate_action(action())
    forwarded = ActionEnvelope.from_dict(result.assurance.review.action.as_dict())
    calls = [0]

    def race_clock():
        calls[0] += 1
        if calls[0] == 2:
            forwarded.parameters["arguments"]["path"] = "/fixture/.env"
        return 100

    issuer._clock = race_clock
    assert not gate.commit_use(result, forwarded)


def test_mandatory_profile_delegation_guard_uses_current_verified_assessment(tmp_path):
    from ordin.assurance import DelegationIssuer, HostEvidenceSource
    from ordin.assurance.models import SecurityInvariant, InvariantSelectors
    from .test_profiles import REPO, POLICY_HASH, approve, selected, config_profile
    from .test_delegation import maximum

    profile = approve(
        selected(
            tmp_path,
            config_profile(
                SecurityInvariant(
                    "child-subset",
                    "delegated_authority_subset",
                    InvariantSelectors(),
                    on_violation="block",
                )
            ),
        )
    )
    parent = HostEvidenceSource("parent", REPO, "a" * 64, 0, POLICY_HASH, profile.selection_digest)
    child = replace(parent, principal="child", session_digest="d" * 64)
    issuer = DelegationIssuer(parent, profile, maximum(), maximum(), clock=lambda: 100)
    root = issuer.authorize_root(maximum(), grant_id="root", expires_at=200)
    grant = issuer.issue_child(root, child, child_max(), grant_id="child", expires_at=150)
    gate = DelegatingAssuranceGate(
        AssuranceGate(AgentGate(Ordin(tool_semantics=SEMANTICS)), profile), issuer, grant, child
    )
    permitted = gate.evaluate_action(action())
    assert (
        permitted.may_execute and permitted.assurance.invariant_evaluations[0].status == "satisfied"
    )
    assert gate.commit_use(permitted, permitted.assurance.review.action)
    rejected = gate.evaluate_action(action("env", "/fixture/.env"))
    assert rejected.denied and rejected.assurance.invariant_evaluations[0].status == "violated"
