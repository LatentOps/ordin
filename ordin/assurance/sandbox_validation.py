"""Measured source validation and fix verification for a closed synthetic predicate."""

from dataclasses import dataclass, field

from ordin._runtime_json import digest as core_digest

from .inventory import verify_source_reference
from .models import JsonRecord, RepositoryScope
from .validation import _issue, _check_review, _link
from .validation_models import FindingValidation, _ValidationAuthority
from .synthetic_tests import PATH_PROPERTY_DIGEST, VettedProgram, SelectedSyntheticSuite
from .sandbox_tests import run_sandbox_test, sandbox_test_action, SandboxTestRun
from .source_patch import SourcePatchProposal
from ._sandbox_worker import vet_program

CANONICAL_FIX = vet_program(
    "def within_root(path, root):\n    return path == root or path.startswith(root + '/')\n"
)
PREFIX_BUG = vet_program("def within_root(path, root):\n    return path.startswith(root)\n")


def validate_finding_sandboxed(
    scope, source, candidate, review, program, suite, runtime, consent, *, cancel=None
):
    if not isinstance(program, VettedProgram) or not isinstance(suite, SelectedSyntheticSuite):
        raise ValueError("sandbox validation requires pinned vetted source and tests")
    gaps = _check_review(scope, source, candidate, review)
    if (
        candidate.issue_class != "synthetic_path_boundary"
        or review.rubric.expected_authority_digest != PATH_PROPERTY_DIGEST
    ):
        gaps.append("No vetted source predicate matches the candidate and expected property.")
    if program.source.digest not in {
        reference.digest for reference in review.verified_sources
    } or not verify_source_reference(scope, suite.source):
        gaps.append("Executed source/test provenance differs from the inspected finding.")
    action = sandbox_test_action(runtime, program, suite, source)
    run = None
    if not gaps:
        run = run_sandbox_test(scope, source, runtime, program, suite, consent, cancel=cancel)
        gaps.extend(run.proof_gaps)
    result = "inconclusive"
    evidence, counter = list(review.evidence), list(review.counterevidence)
    if run is not None and run.status == "completed" and not gaps:
        link = _link(
            "runtime_backend_observed",
            "vetted-test:" + run.digest[:24],
            action_digest=core_digest(action.as_dict()),
            session=source.session_digest,
        )
        if any(not row["expected"] and row["actual"] for row in run.results):
            result = "confirmed"
            evidence.append(link)
        else:
            result = "refuted"
            counter.append(link)
    elif not gaps:
        gaps.append("No completed vetted test result is available.")
    gaps.extend(_check_review(scope, source, candidate, review))
    if gaps:
        result = "inconclusive"
    validation = _issue(
        FindingValidation,
        dict(
            validation_id="validation:"
            + core_digest([candidate.digest, program.digest, suite.digest])[:24],
            finding_digest=candidate.digest,
            review_digest=review.digest,
            repository=scope.repository,
            mode="sandboxed_test",
            result=result,
            invariant_id=review.rubric.invariant_id,
            boundary_digest=PATH_PROPERTY_DIGEST,
            action_digest=core_digest(action.as_dict()),
            action_kind="validation",
            fixture_digest=suite.source.content_digest,
            fixture_source=suite.source,
            configuration_digest=runtime.digest,
            evidence=tuple(evidence),
            counterevidence=tuple(counter),
            proof_gaps=tuple(dict.fromkeys(gaps)),
            safe_reproducer_ref=suite.suite.suite_id,
            tested_scope="synthetic_path_boundary",
            contract_authorization_digest=None,
            sandbox_test_digest=run.digest if run else None,
            limitations=(
                "Only the selected canonical synthetic lexical path predicate was executed.",
                "Filesystem aliases, real assets, other source code and broader exploitability are outside coverage.",
                "Actual broker isolation must be verified by the protected host; this SDK does not supply an OS sandbox.",
            ),
            source_key=source.key,
            advisory_only=True,
        ),
    )
    return validation, run


@dataclass(frozen=True)
class SourceFixVerification(JsonRecord):
    SCHEMA = "assurance_source_fix"
    NESTED = {"repository_before": RepositoryScope, "repository_after": RepositoryScope}
    proposal_digest: str
    original_validation_digest: str
    original_run_digest: str | None
    candidate_run_digest: str | None
    repository_before: RepositoryScope
    repository_after: RepositoryScope
    original_source_digest: str
    candidate_source_digest: str
    suite_digest: str
    result: str
    authority_delta: str
    benign_regressions: int
    false_allows: int
    proof_gaps: tuple[str, ...]
    tested_scope: str = "synthetic_path_boundary"
    integrated: bool = False
    limitations: tuple[str, ...] = (
        "Closure covers exact vetted source/test bytes and the declared canonical lexical namespace only.",
        "Full safety/unit/integration/release suites and physical broker acceptance remain separate.",
    )
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("source fix requires an actual matched execution receipt")
        if self.result == "fixed-verified" and (
            self.proof_gaps
            or self.benign_regressions
            or self.false_allows
            or self.authority_delta not in {"unchanged", "narrowed"}
            or not self.original_run_digest
            or not self.candidate_run_digest
        ):
            raise ValueError(
                "verified source fix needs preserved tests, benign behavior and non-widening proof"
            )

    def public_dict(self):
        packet = self.as_dict()
        packet["repository_before"] = self.repository_before.digest
        packet["repository_after"] = self.repository_after.digest
        packet["schema_version"] = "ordin.assurance_source_fix_summary.v1"
        packet["report_digest"] = self.digest
        return packet


def verify_source_fix(
    proposal, original_validation, *, before, after, before_profile, after_profile
):
    """Selections are host-owned dictionaries, never command/issuance inputs to a worker.

    Each selection contains scope/source/candidate/review/program/suite/runtime/
    consent. Two fresh approvals are required to repeat original then candidate.
    """
    if (
        not isinstance(proposal, SourcePatchProposal)
        or not isinstance(original_validation, FindingValidation)
        or proposal.validation_digest != original_validation.digest
        or original_validation.result != "confirmed"
        or original_validation.mode != "sandboxed_test"
    ):
        raise ValueError("source fix needs its original confirmed source execution")
    expected_fields = {
        "scope",
        "source",
        "candidate",
        "review",
        "program",
        "suite",
        "runtime",
        "consent",
    }
    if (
        not isinstance(before, dict)
        or not isinstance(after, dict)
        or set(before) != expected_fields
        or set(after) != expected_fields
    ):
        raise ValueError("source fix requires exact protected execution selections")
    a, b = before["program"], after["program"]
    if (
        not isinstance(a, VettedProgram)
        or not isinstance(b, VettedProgram)
        or proposal.repository != a.repository
        or a.repository.id != b.repository.id
        or a.source.digest != proposal.source.digest
        or original_validation.finding_digest != before["candidate"].digest
        or original_validation.review_digest != before["review"].digest
        or original_validation.source_key != before["source"].key
        or original_validation.boundary_digest != PATH_PROPERTY_DIGEST
    ):
        raise ValueError("source fix proposal/finding/repository mismatch")
    gaps = []
    if b.source.content_digest != proposal.candidate_file_digest or a.source.path != b.source.path:
        gaps.append("Candidate source bytes do not match the exact proposed patch.")
    if (
        before["suite"].source.content_digest != after["suite"].source.content_digest
        or before["suite"].suite.digest != after["suite"].suite.digest
        or original_validation.fixture_digest != before["suite"].source.content_digest
    ):
        gaps.append(
            "Original test bytes or case semantics were changed instead of preserving reproduction."
        )
    if (
        before["runtime"].digest != after["runtime"].digest
        or original_validation.configuration_digest != before["runtime"].digest
        or before["source"].principal != after["source"].principal
        or before["source"].runtime_policy_digest != after["source"].runtime_policy_digest
        or before["review"].rubric.allowed_permissions != after["review"].rubric.allowed_permissions
        or before["review"].rubric.invariant_id != after["review"].rubric.invariant_id
    ):
        gaps.append(
            "Host actor/runtime/policy configuration changed outside the proposed source fix."
        )
    for selected, profile in ((before, before_profile), (after, after_profile)):
        selected["source"]._check_profile(profile)
    old_profile, new_profile = before_profile.profile.as_dict(), after_profile.profile.as_dict()
    old_profile.pop("repository")
    new_profile.pop("repository")
    if old_profile != new_profile:
        gaps.append(
            "Protected profile/capability configuration differs; containment is unverified."
        )
    old_run = new_run = None
    benign_regressions = false_allows = 0
    result, delta = "inconclusive", "unknown"
    if not gaps:
        original, old_run = validate_finding_sandboxed(**before)
        if original.result != "confirmed" or old_run is None:
            gaps.append("The original failing source path did not reproduce first.")
        else:
            candidate, new_run = validate_finding_sandboxed(**after)
            gaps.extend(candidate.proof_gaps)
            if new_run is not None and new_run.status == "completed":
                false_allows = sum(not row["expected"] and row["actual"] for row in new_run.results)
                benign_regressions = sum(
                    row["expected"] and not row["actual"] for row in new_run.results
                )
                widened = any(
                    not old["actual"] and new["actual"]
                    for old, new in zip(old_run.results, new_run.results)
                )
                delta = (
                    "widened"
                    if widened
                    else "unchanged"
                    if a._program == b._program
                    else "narrowed"
                    if a._program == PREFIX_BUG and b._program == CANONICAL_FIX
                    else "unknown"
                )
                if false_allows:
                    result = "still-vulnerable"
                elif benign_regressions:
                    gaps.append("Proposed code breaks a preserved benign counterpart.")
                elif delta not in {"unchanged", "narrowed"}:
                    gaps.append(
                        "Changed source semantics lack a reviewed non-widening proof for all supported inputs."
                    )
                elif candidate.result == "refuted" and not gaps:
                    result = "fixed-verified"
    for selected in (before, after):
        if not verify_source_reference(
            selected["scope"], selected["program"].source
        ) or not verify_source_reference(selected["scope"], selected["suite"].source):
            gaps.append("Source/test provenance changed during source-fix verification.")
    if gaps and result == "fixed-verified":
        result = "inconclusive"
    return _issue(
        SourceFixVerification,
        dict(
            proposal_digest=proposal.digest,
            original_validation_digest=original_validation.digest,
            original_run_digest=old_run.digest if old_run else None,
            candidate_run_digest=new_run.digest if new_run else None,
            repository_before=a.repository,
            repository_after=b.repository,
            original_source_digest=a.source.content_digest,
            candidate_source_digest=b.source.content_digest,
            suite_digest=before["suite"].source.content_digest,
            result=result,
            authority_delta=delta,
            benign_regressions=benign_regressions,
            false_allows=false_allows,
            proof_gaps=tuple(dict.fromkeys(gaps)),
            tested_scope="synthetic_path_boundary",
            integrated=False,
            limitations=(
                "Closure covers exact vetted source/test bytes and the declared canonical lexical namespace only.",
                "Full safety/unit/integration/release suites and physical broker acceptance remain separate.",
            ),
        ),
    )
