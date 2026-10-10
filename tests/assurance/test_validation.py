"""Actual pure replay, source pins and protected observation closure; no actions."""

from dataclasses import replace
import hashlib
import json

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import AuthorizedRepository, AssuranceGate, HostEvidenceSource, RepositoryScope
from ordin.assurance.models import SecurityFinding, SourceReference
from ordin.assurance.validation_models import FindingRubric, FindingReview, FindingValidation
from ordin.assurance.validation import (
    review_finding,
    load_replay_fixture,
    validate_finding_static,
    validate_finding_replay,
    validate_finding_host_observation,
    close_finding,
    deduplicate_findings,
    record_contract_authorization,
)
from ordin.assurance.attack_paths import ReviewedAction
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import (
    FilesystemCapability,
    ToolCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation

from .test_invariants import SEMANTICS, READ


def reference(scope, path, line=1):
    return SourceReference(
        path,
        line,
        scope.repository.revision,
        hashlib.sha256((scope.root / path).read_bytes()).hexdigest(),
    )


def fixture(tmp_path, *, action=None, revision="before-v1"):
    root = tmp_path / revision
    root.mkdir()
    (root / "app.py").write_text(
        "# Synthetic authorization configuration. No imports or effects.\n", encoding="utf-8"
    )
    (root / "control.py").write_text(
        "# Existing guard is a static counterevidence candidate.\n", encoding="utf-8"
    )
    scope = AuthorizedRepository(
        root.resolve(), RepositoryScope("fixture/validation", revision), "/fixture"
    )
    source = HostEvidenceSource("fixture-agent", scope.repository, "a" * 64, 1, "b" * 64, "c" * 64)
    action = replace(action or READ, action_id="reproduce")
    packet = {
        "schema_version": "ordin.assurance_replay_input.v1",
        "case_id": "reproduce",
        "action": action.as_dict(),
    }
    (root / "case.json").write_text(json.dumps(packet), encoding="utf-8")
    selected = load_replay_fixture(scope, reference(scope, "case.json"))
    boundary = RuntimeCapabilityBoundary(
        "expected-task-bound",
        filesystem=(FilesystemCapability("read", "/fixture/allowed.txt"),),
        tools=(ToolCapability("fixture", None, "read_file"),),
    )
    candidate = SecurityFinding(
        "candidate",
        "gate_authority_subset",
        scope.repository,
        "d" * 64,
        affected_sources=(reference(scope, "app.py"),),
        attacker_control=("tool.arguments",),
        invariant_id="task.authority_subset",
        origin="imported_claim",
        status="imported",
        proof_gaps=("Imported claim is unverified.",),
        occurrence_ids=("occurrence-1",),
    )
    rubric = FindingRubric(
        source.principal,
        (reference(scope, "app.py"),),
        ("filesystem.read",),
        candidate.invariant_id,
        boundary.digest,
        (reference(scope, "app.py"),),
        (reference(scope, "control.py"),),
        changes=("Pure synthetic task-bound test.",),
    )
    review = review_finding(scope, candidate, rubric)
    gate = AssuranceGate(AgentGate(Ordin(tool_semantics=SEMANTICS)))
    return scope, source, candidate, review, selected, gate, boundary


def test_static_review_retains_counterevidence_and_cannot_reproduce(tmp_path):
    scope, source, candidate, review, *_ = fixture(tmp_path)
    assert review.status == "reviewed" and review.counterevidence
    result = validate_finding_static(scope, source, candidate, review)
    assert result.mode == "static" and result.result == "inconclusive" and result.proof_gaps
    assert close_finding(scope, source, candidate, review, result).status == "inconclusive"
    with pytest.raises(ValueError, match="verified receipt"):
        replace(result, result="confirmed", proof_gaps=())
    with pytest.raises(ValueError):
        FindingReview.from_dict(review.as_dict())


def test_true_positive_pure_replay_and_imported_origin_preserved_separately(tmp_path, monkeypatch):
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path)
    monkeypatch.setattr(
        "subprocess.Popen", lambda *a, **k: pytest.fail("replay executed a proposal")
    )
    result = validate_finding_replay(scope, source, candidate, review, selected, gate, boundary)
    assert result.result == "confirmed" and not result.proof_gaps
    assert (
        result.tested_scope == "gate_authority_subset"
        and result.fixture_digest == selected.source.content_digest
    )
    closed = close_finding(scope, source, candidate, review, result)
    assert closed.status == "confirmed" and closed.confidence is None
    assert (
        closed.validation_digest == result.digest
        and closed.verification_scope == result.tested_scope
    )
    assert candidate.status == "imported" and candidate.origin == "imported_claim"
    assert result.finding_digest == candidate.digest and result.review_digest == review.digest
    with pytest.raises(ValueError):
        SecurityFinding.from_dict(closed.as_dict())
    with pytest.raises(ValueError):
        FindingValidation.from_dict(result.as_dict())
    assert "app.py" not in json.dumps(result.public_dict())


def test_existing_control_refutes_only_the_tested_path(tmp_path):
    # Preserve adapter envelope shape by adapting the benign counterpart.
    from .test_invariants import ADAPTER

    allowed = ADAPTER.adapt("read_file", {"path": "/fixture/allowed.txt"}, action_id="reproduce")
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path, action=allowed)
    result = validate_finding_replay(scope, source, candidate, review, selected, gate, boundary)
    assert result.result == "refuted" and result.counterevidence
    assert close_finding(scope, source, candidate, review, result).status == "refuted"
    assert any("exact revision" in limitation for limitation in result.limitations)


@pytest.mark.parametrize(
    "change", ["reference", "fixture", "precondition", "unknown", "class", "actor"]
)
def test_invalid_unexercised_and_nonreproducible_findings_stay_inconclusive(tmp_path, change):
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path)
    if change == "reference":
        rubric = replace(
            review.rubric,
            controlled_sources=(replace(review.rubric.controlled_sources[0], line=999),),
        )
        review = review_finding(scope, candidate, rubric)
    elif change == "fixture":
        (scope.root / "case.json").write_text("{}", encoding="utf-8")
    elif change in {"precondition", "unknown", "actor"}:
        rubric = replace(
            review.rubric,
            **{
                "precondition": {"preconditions": ("Requires an unverified external identity.",)},
                "unknown": {"unknowns": ("Deployment is unknown.",)},
                "actor": {"actor": "other-agent"},
            }[change],
        )
        review = review_finding(scope, candidate, rubric)
    else:
        candidate = replace(candidate, issue_class="unregistered-vulnerability")
        review = review_finding(scope, candidate, review.rubric)
    result = validate_finding_replay(scope, source, candidate, review, selected, gate, boundary)
    assert result.result == "inconclusive" and result.proof_gaps


def test_stale_source_and_foreign_boundary_cannot_close(tmp_path):
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path)
    result = validate_finding_replay(scope, source, candidate, review, selected, gate, boundary)
    (scope.root / "app.py").write_text("# Changed after validation.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale"):
        close_finding(scope, source, candidate, review, result)
    with pytest.raises(ValueError, match="bound"):
        validate_finding_replay(
            scope, source, candidate, review, selected, gate, RuntimeCapabilityBoundary("other")
        )


@pytest.mark.parametrize(
    "outcome,expected",
    [
        ("completed", "inconclusive"),
        ("allowed", "confirmed"),
        ("denied", "refuted"),
        ("failed", "inconclusive"),
    ],
)
def test_authenticated_host_outcomes_have_scoped_closure(tmp_path, outcome, expected):
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path)
    context = source.context()
    decision = gate.evaluate_action(selected.action, host_context=context)
    row = ReviewedAction(decision, context)
    contract = derive_runtime_capability_contract(decision.review)
    runtime = RuntimeEvidenceSource(
        "fixture", source.session_digest, "synthetic-sandbox", source.runtime_policy_digest
    )
    observation = runtime.observe(
        contract,
        observation_id="event",
        trust="backend_enforced" if outcome == "allowed" else "backend_observed",
        enforcement_point="filesystem",
        outcome=outcome,
        operation="filesystem.read",
    )
    authorization = (
        record_contract_authorization(source, runtime, observation, contract)
        if outcome == "allowed"
        else None
    )
    result = validate_finding_host_observation(
        scope,
        source,
        candidate,
        review,
        selected,
        row,
        boundary,
        observation,
        runtime,
        contract_authorization=authorization,
    )
    assert result.result == expected and result.mode == "host_observation"
    if authorization:
        with pytest.raises(ValueError):
            type(authorization).from_dict(authorization.as_dict())
        absent = validate_finding_host_observation(
            scope, source, candidate, review, selected, row, boundary, observation, runtime
        )
        assert absent.result == "inconclusive"
    assert (
        any(
            link.origin == "runtime_backend_observed"
            for link in (*result.evidence, *result.counterevidence)
        )
        or expected == "inconclusive"
    )


def test_forged_and_cross_session_observations_are_not_validation(tmp_path):
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path)
    context = source.context()
    row = ReviewedAction(gate.evaluate_action(selected.action, host_context=context), context)
    runtime = RuntimeEvidenceSource(
        "fixture", source.session_digest, "synthetic-sandbox", source.runtime_policy_digest
    )
    weak = RuntimeObservation("weak", "reproduce", outcome="completed")
    result = validate_finding_host_observation(
        scope, source, candidate, review, selected, row, boundary, weak, runtime
    )
    assert result.result == "inconclusive"
    with pytest.raises(ValueError, match="session"):
        validate_finding_host_observation(
            scope,
            source,
            candidate,
            review,
            selected,
            row,
            boundary,
            weak,
            replace(runtime, session_digest="e" * 64),
        )


def test_duplicates_preserve_occurrences_without_merging_proof(tmp_path):
    _, _, candidate, *_ = fixture(tmp_path)
    duplicate = replace(candidate, finding_id="duplicate", occurrence_ids=("occurrence-2",))
    groups = deduplicate_findings((candidate, duplicate))
    assert len(groups) == 1 and set(groups[0][1]) == {candidate.digest, duplicate.digest}
    same_id = replace(candidate, occurrence_ids=("another-occurrence",))
    assert len(deduplicate_findings((candidate, same_id))[0][1]) == 2
    foreign = replace(
        duplicate, repository=RepositoryScope("another-repo", candidate.repository.revision)
    )
    assert len(deduplicate_findings((candidate, foreign))) == 2


def test_fixture_mutation_after_validation_prevents_closure(tmp_path):
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path)
    result = validate_finding_replay(scope, source, candidate, review, selected, gate, boundary)
    (scope.root / "case.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="test provenance"):
        close_finding(scope, source, candidate, review, result)


def test_public_review_and_validation_omit_secret_looking_metadata(tmp_path):
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path)
    secret = "sk-synthetic-raw-secret-fixture-ABC123"
    candidate = replace(candidate, invariant_id=secret)
    rubric = replace(review.rubric, invariant_id=secret, changes=(secret,))
    review = review_finding(scope, candidate, rubric)
    result = validate_finding_replay(scope, source, candidate, review, selected, gate, boundary)
    assert secret in json.dumps(review.as_dict())
    assert secret not in json.dumps(review.public_dict())
    assert secret not in json.dumps(result.public_dict())


def test_explicit_repository_snapshot_pin_is_enforced(tmp_path):
    scope, source, candidate, review, selected, gate, boundary = fixture(tmp_path)
    pinned = replace(scope, expected_snapshot_digest="e" * 64)
    inspected = review_finding(pinned, candidate, review.rubric)
    assert inspected.status == "inconclusive" and any(
        "snapshot" in gap for gap in inspected.proof_gaps
    )
    result = validate_finding_replay(pinned, source, candidate, review, selected, gate, boundary)
    assert result.result == "inconclusive" and result.proof_gaps
