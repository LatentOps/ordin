"""Measured original/candidate code through the finite vetted worker."""

from dataclasses import replace
import json

import pytest

from ordin.assurance import RepositoryScope, HostEvidenceSource, SecurityFinding
from ordin.assurance.inventory import AuthorizedRepository
from ordin.assurance.validation import review_finding, close_finding
from ordin.assurance.validation_models import FindingRubric
from ordin.assurance.synthetic_tests import (
    PATH_PROPERTY_DIGEST,
    load_vetted_program,
    load_synthetic_suite,
)
from ordin.assurance.sandbox_tests import sandbox_test_action, authorize_sandbox_test
from ordin.assurance.sandbox_validation import validate_finding_sandboxed, verify_source_fix
from ordin.assurance.source_patch import propose_source_patch
from ordin.assurance.profiles import load_approved_profile

from .test_sandbox_tests import setup, FIX, BUG
from .test_profiles import selected, config_profile, POLICY_HASH
from .test_validation import reference


def finding(scope, source, program, suite):
    candidate = SecurityFinding(
        "synthetic-candidate",
        "synthetic_path_boundary",
        scope.repository,
        "a" * 64,
        affected_sources=(program.source,),
        invariant_id="synthetic.lexical_path_subset",
        attacker_control=("synthetic.path_input",),
        origin="imported_claim",
        status="imported",
    )
    rubric = FindingRubric(
        source.principal,
        (suite.source,),
        ("synthetic.path",),
        candidate.invariant_id,
        PATH_PROPERTY_DIGEST,
        (program.source,),
    )
    return candidate, review_finding(scope, candidate, rubric)


def selections(setup, tmp_path, code=FIX):
    scope, source, runtime, program, suite, consent, _ = setup
    candidate, review = finding(scope, source, program, suite)
    initial, actual = validate_finding_sandboxed(
        scope, source, candidate, review, program, suite, runtime, consent()
    )
    assert initial.result == "confirmed" and actual.status == "completed"
    patch = propose_source_patch(scope, initial, program.source, code)
    new_root = tmp_path / "candidate"
    new_root.mkdir()
    (new_root / "guard.py").write_bytes(code.encode("utf-8"))
    (new_root / "suite.json").write_bytes((scope.root / "suite.json").read_bytes())
    new_repo = RepositoryScope(scope.repository.id, "snapshot-2")
    new_scope = AuthorizedRepository(new_root.resolve(), new_repo, "/fixture")
    new_program = load_vetted_program(new_scope, reference(new_scope, "guard.py"))
    new_suite = load_synthetic_suite(new_scope, reference(new_scope, "suite.json"))
    profile_before = load_approved_profile(
        selected(tmp_path, config_profile()),
        current_repository=scope.repository,
        active_runtime_policy_digest=POLICY_HASH,
    )
    before_source = replace(source, selection_digest=profile_before.selection_digest)
    profile_data = replace(config_profile(), repository=new_repo)
    (tmp_path / "after-config").mkdir(mode=0o700)
    profile_after = load_approved_profile(
        selected(tmp_path / "after-config", profile_data, repository=new_repo),
        current_repository=new_repo,
        active_runtime_policy_digest=POLICY_HASH,
    )
    new_source = HostEvidenceSource(
        source.principal,
        new_repo,
        source.session_digest,
        source.epoch,
        POLICY_HASH,
        profile_after.selection_digest,
    )
    # Keep the original protected selection for original evidence rather than
    # pretending a new selected profile is its source. Its bytes/selection match.
    assert before_source.key == source.key
    new_candidate, new_review = finding(new_scope, new_source, new_program, new_suite)

    def lease(source, profile, program, suite):
        action = sandbox_test_action(runtime, program, suite, source)
        approval = source.record_approval(action, profile, receipt_id="synthetic-source-test")
        isolation = source.record_assessment(
            action,
            profile,
            assessment_id="synthetic-broker-scope",
            invariant_id="validation.sandbox",
            kind="validation_isolation",
            status="satisfied",
        )
        return authorize_sandbox_test(source, profile, approval, isolation, runtime, program, suite)

    before = dict(
        scope=scope,
        source=source,
        candidate=candidate,
        review=review,
        program=program,
        suite=suite,
        runtime=runtime,
        consent=lease(source, profile_before, program, suite),
    )
    after = dict(
        scope=new_scope,
        source=new_source,
        candidate=new_candidate,
        review=new_review,
        program=new_program,
        suite=new_suite,
        runtime=runtime,
        consent=lease(new_source, profile_after, new_program, new_suite),
    )
    return patch, initial, before, after, profile_before, profile_after


def test_executed_source_closure_keeps_actual_test_digest(setup):
    scope, source, runtime, program, suite, consent, _ = setup
    candidate, review = finding(scope, source, program, suite)
    result, actual = validate_finding_sandboxed(
        scope, source, candidate, review, program, suite, runtime, consent()
    )
    assert result.result == "confirmed" and result.sandbox_test_digest == actual.digest
    closed = close_finding(scope, source, candidate, review, result)
    assert closed.status == "confirmed" and closed.verification_scope == "synthetic_path_boundary"
    assert candidate.status == "imported"


@pytest.mark.parametrize(
    "code,expected",
    [
        (FIX, "fixed-verified"),
        (BUG, "still-vulnerable"),
        ("def within_root(path, root):\n    return path == root\n", "inconclusive"),
    ],
)
def test_source_patch_correct_ineffective_and_benign_breaking_results(
    setup, tmp_path, code, expected
):
    patch, original, before, after, a, b = selections(setup, tmp_path, code)
    result = verify_source_fix(
        patch, original, before=before, after=after, before_profile=a, after_profile=b
    )
    assert (
        result.result == expected and result.original_run_digest and result.candidate_run_digest
    ), result.proof_gaps
    assert not result.integrated and not patch.applied
    if expected == "fixed-verified":
        assert result.authority_delta == "narrowed" and not result.proof_gaps
    elif expected == "inconclusive":
        assert result.benign_regressions == 1 and result.proof_gaps


def test_changed_test_provenance_cannot_make_a_patch_green(setup, tmp_path, monkeypatch):
    patch, original, before, after, a, b = selections(setup, tmp_path)
    packet = json.loads((after["scope"].root / "suite.json").read_text())
    packet["cases"][0]["case_id"] = "relabeled-original-test"
    (after["scope"].root / "suite.json").write_text(json.dumps(packet), encoding="utf-8")
    after["suite"] = load_synthetic_suite(after["scope"], reference(after["scope"], "suite.json"))
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("changed test executed"))
    result = verify_source_fix(
        patch, original, before=before, after=after, before_profile=a, after_profile=b
    )
    assert result.result == "inconclusive" and not result.original_run_digest
