"""Preserved reproduction/benign controls, immutable proposals and adverse fixes."""

from dataclasses import replace
import json

import pytest

from ordin import Ordin, ReviewPolicy
from ordin.action_policy import ActionPolicyCondition, ActionPolicyRule, ActionPolicySet
from ordin.assurance.simulation import SimulationPolicy
from ordin.assurance.validation import validate_finding_replay, load_replay_fixture
from ordin.assurance.remediation import (
    RemediationProposal,
    FixVerification,
    propose_remediation,
    propose_invariant_remediation,
    verify_fix,
)
from ordin.assurance.source_patch import propose_source_patch, SourcePatchProposal

from .test_validation import fixture, reference
from .test_invariants import SEMANTICS, WRITE, ADAPTER


def control(scope, name, action):
    action = replace(action, action_id=name)
    packet = {
        "schema_version": "ordin.assurance_replay_input.v1",
        "case_id": name,
        "action": action.as_dict(),
    }
    (scope.root / (name + ".json")).write_text(json.dumps(packet), encoding="utf-8")
    return load_replay_fixture(scope, reference(scope, name + ".json"))


def setup(tmp_path, *, candidate_policy=None):
    before = fixture(tmp_path, action=WRITE, revision="before-v1")
    after = fixture(tmp_path, action=WRITE, revision="after-v2")
    old = SimulationPolicy(Ordin(policy=ReviewPolicy("block"), tool_semantics=SEMANTICS))
    new = candidate_policy or SimulationPolicy(Ordin(tool_semantics=SEMANTICS))
    validation = validate_finding_replay(*before[:5], old.build_gate(), before[6])
    assert validation.result == "confirmed"
    proposal = propose_remediation(validation, old, new, after[0].repository)
    benign = ADAPTER.adapt("read_file", {"path": "/fixture/allowed.txt"})
    pair = (control(before[0], "benign", benign), control(after[0], "benign", benign))
    arguments = dict(
        before_scope=before[0],
        before_source=before[1],
        before_finding=before[2],
        before_review=before[3],
        after_scope=after[0],
        after_source=after[1],
        after_finding=after[2],
        after_review=after[3],
        reproduction=(before[4], after[4]),
        benign_controls=(pair,),
        boundary=before[6],
    )
    return before, after, old, new, validation, proposal, arguments


def test_narrow_policy_fix_and_benign_counterpart_verified_without_application(
    tmp_path, monkeypatch
):
    before, after, _, _, validation, proposal, arguments = setup(tmp_path)
    unchanged = (before[0].root / "app.py").read_bytes()
    monkeypatch.setattr(
        "subprocess.Popen", lambda *a, **k: pytest.fail("fix verification executed a command")
    )
    result = verify_fix(proposal, validation, **arguments)
    assert result.result == "fixed-verified" and result.authority_delta == "narrowed"
    assert result.tested_scope == "policy_replay" and not result.integrated
    assert not result.proof_gaps and not result.benign_regressions
    assert result.simulation_digest and result.baseline_p95_ms is not None
    assert (before[0].root / "app.py").read_bytes() == unchanged
    assert not proposal.applied and proposal.review_required
    assert proposal.private_policy_artifact()["after"]["core"]["fail_on"] == "warn"
    draft = propose_invariant_remediation(validation)
    assert not draft.authoritative and draft.invariant_suggestions and draft.unresolved_facts
    with pytest.raises(ValueError):
        RemediationProposal.from_dict(proposal.as_dict())
    with pytest.raises(ValueError):
        FixVerification.from_dict(result.as_dict())
    with pytest.raises(ValueError):
        replace(result, result="fixed-verified", benign_regressions=1)


def test_apparent_fix_that_leaves_the_path_executable_is_still_vulnerable(tmp_path):
    unchanged = SimulationPolicy(Ordin(policy=ReviewPolicy("block"), tool_semantics=SEMANTICS))
    _, _, _, _, validation, proposal, arguments = setup(tmp_path, candidate_policy=unchanged)
    result = verify_fix(proposal, validation, **arguments)
    assert result.result == "still-vulnerable"


@pytest.mark.parametrize("change", ["changed_test", "deleted_test", "missing_control"])
def test_test_suppression_and_missing_provenance_do_not_verify(tmp_path, change):
    _, after, _, _, validation, proposal, arguments = setup(tmp_path)
    if change == "changed_test":
        packet = json.loads((after[0].root / "case.json").read_text())
        packet["action"]["intent"] = "Altered test label to hide the original failure"
        (after[0].root / "case.json").write_text(json.dumps(packet), encoding="utf-8")
        arguments["reproduction"] = (
            arguments["reproduction"][0],
            load_replay_fixture(after[0], reference(after[0], "case.json")),
        )
    elif change == "deleted_test":
        (after[0].root / "case.json").unlink()
    else:
        arguments["benign_controls"] = ()
    result = verify_fix(proposal, validation, **arguments)
    assert result.result == "inconclusive" and result.proof_gaps


def test_patch_that_breaks_benign_behavior_retains_regression_and_unknown_containment(tmp_path):
    new = SimulationPolicy(
        Ordin(
            tool_semantics=SEMANTICS,
            action_policy=ActionPolicySet(
                "break-read",
                "1",
                (
                    ActionPolicyRule(
                        "deny-benign-read", "block", ActionPolicyCondition(kinds=("tool",))
                    ),
                ),
            ),
        )
    )
    _, _, _, _, validation, proposal, arguments = setup(tmp_path, candidate_policy=new)
    result = verify_fix(proposal, validation, **arguments)
    assert result.result == "inconclusive" and result.proof_gaps
    assert result.authority_delta == "unknown" and result.benign_regressions == 1


def test_overbroad_policy_patch_cannot_become_verified(tmp_path):
    _, after, old, _, validation, _, arguments = setup(tmp_path)
    widened = SimulationPolicy(Ordin(policy=ReviewPolicy("block"), tool_semantics=SEMANTICS))
    # Removing a required approved-profile boundary is an explicit widening.
    required = replace(old, require_profile=True)
    # Its denied original cannot supply the existing confirmed replay receipt.
    with pytest.raises(ValueError, match="matching"):
        propose_remediation(validation, required, widened, after[0].repository)
    proposal = propose_remediation(validation, old, widened, after[0].repository)
    result = verify_fix(proposal, validation, **arguments)
    assert result.result == "still-vulnerable"
    from ordin.assurance.host import HostCapabilityAuthority
    from ordin.runtime_boundary import RuntimeCapabilityBoundary
    from ordin.runtime_contract import FilesystemCapability

    broader = SimulationPolicy(
        Ordin(tool_semantics=SEMANTICS),
        capability_authorities=(
            HostCapabilityAuthority(
                "new-grant",
                RuntimeCapabilityBoundary(
                    "broad",
                    filesystem=(FilesystemCapability("write", "/fixture", "prefix"),),
                ),
            ),
        ),
    )
    proposal = propose_remediation(validation, old, broader, after[0].repository)
    result = verify_fix(proposal, validation, **arguments)
    assert result.authority_delta == "widened" and result.result == "inconclusive"


def test_alternative_route_keeps_an_apparent_fix_still_vulnerable(tmp_path):
    before, after, _, _, validation, proposal, arguments = setup(tmp_path)
    alternative = ADAPTER.adapt("read_file", {"path": "/fixture/unrelated-private-document"})
    arguments["alternative_routes"] = (
        (
            control(before[0], "alternative", alternative),
            control(after[0], "alternative", alternative),
        ),
    )
    result = verify_fix(proposal, validation, **arguments)
    assert result.result == "still-vulnerable" and result.alternative_route_misses == 1


def test_source_patch_is_private_exact_data_and_never_evidence_of_a_fix(tmp_path):
    before, after, old, new, validation, _, arguments = setup(tmp_path)
    ref = reference(before[0], "app.py")
    original = (before[0].root / "app.py").read_bytes()
    patch = propose_source_patch(before[0], validation, ref, "# Proposed narrow config change.\n")
    assert "--- a/app.py" in patch.private_patch() and not patch.applied
    assert (before[0].root / "app.py").read_bytes() == original
    assert "Proposed narrow" not in json.dumps(patch.public_dict())
    assert "app.py" not in json.dumps(patch.public_dict())
    with pytest.raises(ValueError):
        SourcePatchProposal.from_dict(patch.as_dict())
    proposal = propose_remediation(
        validation, old, new, after[0].repository, source_patch_digest=patch.digest
    )
    result = verify_fix(proposal, validation, **arguments)
    assert result.result == "inconclusive" and any(
        "source code" in gap for gap in result.proof_gaps
    )
    assert result.candidate_validation_digest and result.simulation_digest


def test_unterminated_line_patch_has_explicit_marker(tmp_path):
    before, _, _, _, validation, _, _ = setup(tmp_path)
    patch = propose_source_patch(
        before[0], validation, reference(before[0], "app.py"), "# No terminal newline"
    )
    assert "\\ No newline at end of file\n" in patch.private_patch()
