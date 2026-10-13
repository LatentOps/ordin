"""Only reproduced, reviewed cases enter a protected new-file-only corpus."""

from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from ordin import ActionEnvelope
from ordin.assurance import (
    BoundaryRegression,
    HostApproval,
    HostEvidenceSource,
    ProtectedRegressionDestination,
    challenge_authority_subset,
    challenge_property,
    load_boundary_regressions,
    prepare_boundary_regression,
    promote_reviewed_boundary_regression,
    regression_promotion_action,
    replay_boundary_regression,
    replay_boundary_regression_corpus,
)
from ordin.assurance._json import digest
from ordin.runtime_contract import FilesystemCapability
from .test_profiles import REPO, POLICY_HASH, approve, selected, config_profile


@pytest.fixture
def record():
    return challenge_authority_subset(
        seed=14, revision=REPO.revision, trials=16, variant="seeded_prefix_bug"
    ).counterexamples[0]


@pytest.fixture
def setup(tmp_path, record):
    selection = selected(tmp_path, config_profile())
    profile = approve(selection)
    source = HostEvidenceSource(
        "fixture-operator", REPO, "b" * 64, 1, POLICY_HASH, profile.selection_digest
    )
    root = tmp_path / "corpus"
    root.mkdir(mode=0o700)
    destination = ProtectedRegressionDestination(
        root.resolve(),
        "/trusted/regressions",
        REPO,
        selection.agent_boundary,
        selection.runtime_source,
    )
    case = prepare_boundary_regression(
        record, case_id="prefix-fixture", expected_revision=REPO.revision
    )
    action = regression_promotion_action(case, destination, source)
    approval = source.record_approval(action, profile, receipt_id="owned-fixture-review")
    return case, destination, source, profile, approval


def test_reviewed_promotion_is_durable_and_replays_failure_plus_benign(setup):
    case, destination, source, profile, approval = setup
    assert not case.reviewed
    written = promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    assert written.reviewed and written.advisory_only and not written.host_boundary_exercised
    assert load_boundary_regressions(destination) == (written,)
    assert BoundaryRegression.from_dict(written.as_dict()) == written
    result = replay_boundary_regression_corpus(
        destination, expected_cases={written.case_id: written.digest}
    )
    assert result["all_reproduced"] and not result["host_boundary_exercised"]
    assert result["cases"][0]["result"] == "verified_failure_with_benign_control"
    with pytest.raises(ValueError):
        HostApproval.from_dict(approval.as_dict())


def test_existing_case_is_never_overwritten_or_reapproved_in_place(setup):
    case, destination, source, profile, approval = setup
    written = promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    before = {p.name: p.read_bytes() for p in destination.root.iterdir()}
    with pytest.raises(FileExistsError):
        promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    with pytest.raises(ValueError, match="selection"):
        regression_promotion_action(written, destination, source)
    assert before == {p.name: p.read_bytes() for p in destination.root.iterdir()}


@pytest.mark.parametrize("change", ["case", "destination", "source", "json", "wrong_action"])
def test_review_is_exact_and_caller_json_never_approves(setup, tmp_path, change):
    case, destination, source, profile, approval = setup
    if change == "case":
        case = replace(case, case_id="different-case")
    elif change == "destination":
        root = tmp_path / "different-corpus"
        root.mkdir(mode=0o700)
        destination = replace(destination, root=root)
    elif change == "source":
        source = replace(source, principal="other-operator")
    elif change == "json":
        approval = approval.as_dict()
    else:
        approval = source.record_approval(
            ActionEnvelope.shell("git status --short"), profile, receipt_id="unrelated-review"
        )
    with pytest.raises(ValueError, match="approval"):
        promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    assert list(destination.root.iterdir()) == []


def test_forged_failed_status_and_mutated_benign_control_cannot_promote(setup):
    case, destination, source, profile, _ = setup
    with pytest.raises(ValueError, match="reproduced"):
        prepare_boundary_regression(
            replace(case.counterexample, candidate_result="exceeds_boundary"),
            case_id="forged",
            expected_revision=REPO.revision,
        )
    text = case.benign_input.replace("/fixture/benign", "/other/benign")
    modified = replace(case, benign_input=text, benign_digest=digest("boundary_benign_input", text))
    action = regression_promotion_action(modified, destination, source)
    approval = source.record_approval(action, profile, receipt_id="owned-invalid-control-review")
    with pytest.raises(ValueError, match="benign"):
        promote_reviewed_boundary_regression(modified, destination, source, profile, approval)
    assert list(destination.root.iterdir()) == []


def test_revision_and_reproducer_changes_require_new_review(setup, monkeypatch):
    import ordin.assurance.regression as module

    case, destination, source, profile, approval = setup
    with pytest.raises(ValueError, match="revision"):
        replay_boundary_regression(case, expected_revision="different")
    monkeypatch.setattr(module, "_reproducer_digest", lambda generator: "0" * 64)
    with pytest.raises(ValueError, match="reproducer changed"):
        promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    assert list(destination.root.iterdir()) == []


@pytest.mark.parametrize(
    "capability",
    [
        FilesystemCapability("write", "/trusted/regressions", "prefix"),
        FilesystemCapability("delete", "/trusted", "exact"),
        FilesystemCapability("write", "/trusted/regressions/case.json", "exact"),
        FilesystemCapability("write", "/", "exact"),
        FilesystemCapability("unknown", None, "unknown"),
    ],
)
def test_agent_writable_or_unknown_corpus_is_not_a_protected_destination(setup, capability):
    _, destination, *_ = setup
    with pytest.raises(ValueError, match="protection|writable"):
        replace(
            destination,
            agent_boundary=replace(destination.agent_boundary, filesystem=(capability,)),
        )


@pytest.mark.parametrize("change", ["missing", "digest", "empty", "partial"])
def test_missing_changed_or_partial_mandatory_case_cannot_pass(setup, change):
    case, destination, source, profile, approval = setup
    written = promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    manifest = {written.case_id: written.digest}
    if change == "missing":
        manifest["mandatory-absent"] = "a" * 64
    elif change == "digest":
        manifest[written.case_id] = "a" * 64
    elif change == "empty":
        manifest = {}
    else:
        path = next(destination.root.iterdir())
        path.write_bytes(b'{"schema_version":')
    with pytest.raises(ValueError):
        replay_boundary_regression_corpus(destination, expected_cases=manifest)


def test_failed_write_stays_partial_and_never_produces_promotion_receipt(setup, monkeypatch):
    case, destination, source, profile, approval = setup
    monkeypatch.setattr(
        os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("owned fsync failure"))
    )
    with pytest.raises(OSError, match="fsync failure"):
        promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    assert len(list(destination.root.iterdir())) == 1
    # No promotion success returned; surviving data remains advisory even if
    # a complete write happened before its durability check failed.
    assert case.reviewed is False


def test_symlink_corpus_entry_is_not_loaded(setup, tmp_path):
    _, destination, *_ = setup
    target = tmp_path / "outside"
    target.write_bytes(b"Owned marker")
    try:
        (destination.root / ("a" * 64 + ".json")).symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError):
        load_boundary_regressions(destination)


def test_actions_and_programs_never_execute_during_promotion_or_replay(setup, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("boundary regression attempted network or process execution")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    case, destination, source, profile, approval = setup
    written = promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    assert replay_boundary_regression_corpus(
        destination, expected_cases={written.case_id: written.digest}
    )["all_reproduced"]


@pytest.mark.parametrize(
    "property_id",
    [
        "monotonicity",
        "exact_request_commitment",
        "protocol_separation",
        "tool_identity",
        "history_observations",
        "delegation_subset",
        "trust_origin",
        "review_to_use_binding",
    ],
)
def test_every_core_property_retains_a_valid_benign_counterpart(property_id):
    run = challenge_property(
        property_id=property_id,
        seed=14,
        revision="fixture-v1",
        trials=32,
        variant="seeded_unsafe_checker",
    )
    case = prepare_boundary_regression(
        run.counterexamples[0], case_id=property_id, expected_revision="fixture-v1"
    )
    assert (
        replay_boundary_regression(case, expected_revision="fixture-v1")
        == "verified_failure_with_benign_control"
    )


def test_optional_model_fixture_is_a_dedicated_regression_not_core_trace(monkeypatch):
    monkeypatch.syspath_prepend(
        str(Path(__file__).resolve().parents[2] / "integrations/decision_models")
    )
    run = challenge_property(
        property_id="optional_failure_mode",
        seed=14,
        revision="fixture-v1",
        trials=32,
        variant="seeded_unsafe_checker",
    )
    case = prepare_boundary_regression(
        run.counterexamples[0], case_id="optional-outage", expected_revision="fixture-v1"
    )
    assert case.provenance_kind == "closed_fixture_regression" and not case.reviewed
    assert (
        replay_boundary_regression(case, expected_revision="fixture-v1")
        == "verified_failure_with_benign_control"
    )


def test_hardlinked_corpus_file_is_not_loaded(setup, tmp_path):
    _, destination, *_ = setup
    original = tmp_path / "owned-marker"
    original.write_bytes(b"Owned synthetic marker")
    try:
        os.link(original, destination.root / ("b" * 64 + ".json"))
    except OSError:
        pytest.skip("hardlink creation unavailable")
    with pytest.raises(ValueError):
        load_boundary_regressions(destination)


def test_stale_lock_is_never_stolen_or_treated_as_a_case(setup):
    case, destination, source, profile, approval = setup
    lock = destination.root / ".ordin-boundary-lock"
    lock.write_bytes(b"Owned stale lease marker")
    with pytest.raises(FileExistsError):
        promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    assert lock.read_bytes() == b"Owned stale lease marker"
    with pytest.raises(ValueError):
        load_boundary_regressions(destination)


def test_case_budget_and_concurrent_same_id_cannot_overwrite(setup, monkeypatch):
    import concurrent.futures
    import ordin.assurance.regression as module

    case, destination, source, profile, approval = setup

    def publish():
        try:
            return promote_reviewed_boundary_regression(
                case, destination, source, profile, approval
            )
        except FileExistsError:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: publish(), range(2)))
    assert sum(v is not None for v in results) == 1
    assert len(load_boundary_regressions(destination)) == 1
    monkeypatch.setattr(module, "MAX_CASES", 1)
    other = replace(case, case_id="another-case")
    other_approval = source.record_approval(
        regression_promotion_action(other, destination, source),
        profile,
        receipt_id="owned-budget-review",
    )
    with pytest.raises(ValueError, match="case budget"):
        promote_reviewed_boundary_regression(other, destination, source, profile, other_approval)
    assert len(list(destination.root.iterdir())) == 1


def test_directory_replacement_invalidates_review_before_write(setup):
    case, destination, source, profile, approval = setup
    original = destination.root.with_name("original-corpus")
    destination.root.rename(original)
    destination.root.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="approval"):
        promote_reviewed_boundary_regression(case, destination, source, profile, approval)
    assert list(destination.root.iterdir()) == list(original.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO and private permissions")
def test_fifo_and_public_permissions_are_refused_before_read(setup):
    _, destination, *_ = setup
    fifo = destination.root / ("c" * 64 + ".json")
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError):
        load_boundary_regressions(destination)
    destination.root.chmod(0o777)
    with pytest.raises(ValueError, match="protected"):
        load_boundary_regressions(destination)


def test_cli_proposal_and_replay_are_data_only_without_adoption(record, tmp_path, capsys):
    from ordin.assurance.cli import main

    source = tmp_path / "record.json"
    source.write_text(json.dumps(record.as_dict()))
    proposal = tmp_path / "proposal.json"
    assert (
        main(
            [
                "counterexample",
                "regression-propose",
                str(source),
                "--revision",
                REPO.revision,
                "--case-id",
                "owned-case",
                "--report",
                str(proposal),
            ]
        )
        == 0
    )
    packet = json.loads(capsys.readouterr().out)
    assert packet["review_digest"] is None and packet["advisory_only"]
    assert (
        main(["counterexample", "regression-replay", str(proposal), "--revision", REPO.revision])
        == 0
    )
    assert (
        json.loads(capsys.readouterr().out)["replay_outcome"]
        == "verified_failure_with_benign_control"
    )
    assert {p.name for p in tmp_path.iterdir()} == {"record.json", "proposal.json"}
    assert main(["counterexample", "regression-replay", str(proposal), "--revision", "wrong"]) == 2


def test_owned_runnable_demo_is_offline_and_retains_no_artifacts(tmp_path, monkeypatch):
    from ordin.assurance.regression_demo import run_demo

    def forbidden(*args, **kwargs):
        pytest.fail("regression example attempted process/network work")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    result = run_demo(scratch_root=tmp_path)
    assert (
        result["case_reviewed"]
        and result["failure_and_benign_replayed"]
        and result["duplicate_refused"]
    )
    assert result["case_count"] == 1 and result["synthetic_review_only"]
    assert not any(
        result[key]
        for key in (
            "actions_executed",
            "target_code_executed",
            "live_corpus_or_policy_changed",
            "host_boundary_exercised",
            "artifacts_retained",
        )
    )
    assert list(tmp_path.iterdir()) == []
