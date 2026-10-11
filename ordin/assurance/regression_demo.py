"""Owned synthetic review/promotion/replay; no real policy or action changes."""

import hashlib
import json
from pathlib import Path
import tempfile

from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_observation import RuntimeEvidenceSource

from .challenge import challenge_authority_subset
from .host import HostEvidenceSource
from .models import RepositoryScope, SecurityProfile
from .profiles import ProtectedProfileSelection, load_approved_profile
from .regression import (
    ProtectedRegressionDestination,
    prepare_boundary_regression,
    regression_promotion_action,
    promote_reviewed_boundary_regression,
    replay_boundary_regression_corpus,
)


def run_demo(*, scratch_root=None):
    repo = RepositoryScope("fixture/regression-example", "fixture-v1")
    profile = SecurityProfile("fixture-review", "1", repo)
    policy = "a" * 64
    boundary = RuntimeCapabilityBoundary(
        "fixture-agent",
        filesystem=(FilesystemCapability("write", "/fixture", "prefix"),),
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )
    runtime = RuntimeEvidenceSource("fixture-host", "b" * 64, "fixture-sandbox", policy)
    with tempfile.TemporaryDirectory(prefix="ordin-regression-example-", dir=scratch_root) as name:
        root = Path(name)
        protected, corpus = root / "protected", root / "corpus"
        protected.mkdir(mode=0o700)
        corpus.mkdir(mode=0o700)
        raw = json.dumps(profile.as_dict()).encode()
        path = protected / "profile.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        selection = ProtectedProfileSelection(
            protected,
            "profile.json",
            "/operator/profile.json",
            repo,
            profile.digest,
            hashlib.sha256(raw).hexdigest(),
            "1",
            "synthetic-operator",
            boundary,
            runtime,
        )
        approved = load_approved_profile(
            selection, current_repository=repo, active_runtime_policy_digest=policy
        )
        source = HostEvidenceSource(
            "synthetic-operator", repo, "b" * 64, 1, policy, selection.digest
        )
        record = challenge_authority_subset(
            seed=14, revision=repo.revision, trials=16, variant="seeded_prefix_bug"
        ).counterexamples[0]
        proposal = prepare_boundary_regression(
            record, case_id="synthetic-prefix-regression", expected_revision=repo.revision
        )
        destination = ProtectedRegressionDestination(
            corpus, "/operator/regressions", repo, boundary, runtime
        )
        action = regression_promotion_action(proposal, destination, source)
        # Explicitly synthetic review, not human approval of an application
        # case or installation of a live corpus.
        approval = source.record_approval(action, approved, receipt_id="synthetic-review-only")
        saved = promote_reviewed_boundary_regression(
            proposal, destination, source, approved, approval
        )
        replay = replay_boundary_regression_corpus(
            destination, expected_cases={saved.case_id: saved.digest}
        )
        duplicate_refused = False
        try:
            promote_reviewed_boundary_regression(proposal, destination, source, approved, approval)
        except FileExistsError:
            duplicate_refused = True
        result = {
            "schema_version": "ordin.assurance_regression_demo.v1",
            "synthetic_review_only": True,
            "case_reviewed": saved.reviewed,
            "failure_and_benign_replayed": replay["all_reproduced"],
            "duplicate_refused": duplicate_refused,
            "case_count": len(replay["cases"]),
            "case_digest": saved.digest,
            "provenance_kind": saved.provenance_kind,
            "actions_executed": False,
            "target_code_executed": False,
            "live_corpus_or_policy_changed": False,
            "host_boundary_exercised": False,
            "artifacts_retained": False,
        }
    return result


if __name__ == "__main__":
    print(json.dumps(run_demo(), sort_keys=True))
