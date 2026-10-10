"""Policy proposals and finite fix verification; no apply, publish or subprocess API."""

from __future__ import annotations

from dataclasses import dataclass, field

from ordin._runtime_json import digest as core_digest
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import derive_runtime_capability_contract

from ._json import digest
from .models import (
    JsonRecord,
    RepositoryScope,
    SecurityProfileDraft,
    SecurityInvariant,
    InvariantSelectors,
)
from .inventory import verify_source_reference
from .simulation import (
    SimulationPolicy,
    FrozenCase,
    FrozenCorpus,
    policy_authority_delta,
    simulate_policy_change,
)
from .validation_models import FindingValidation, _ValidationAuthority
from .validation import (
    _issue,
    _check_review,
    ReplayFixture,
    validate_finding_replay,
)
from .requests import verify_assurance_capability


@dataclass(frozen=True)
class RemediationProposal(JsonRecord):
    SCHEMA = "assurance_remediation_proposal"
    NESTED = {"repository_before": RepositoryScope, "repository_after": RepositoryScope}
    proposal_id: str
    validation_digest: str
    finding_digest: str
    repository_before: RepositoryScope
    repository_after: RepositoryScope
    baseline_policy_digest: str
    candidate_policy_digest: str
    expected_authority_digest: str
    authority_delta: str
    protected_host_configuration_changed: bool
    proposed_source_patch_digest: str | None
    review_required: bool = True
    applied: bool = False
    limitations: tuple[str, ...] = (
        "A proposal is never applied, activated, published or integrated.",
        "Profile/host configuration changes with unknown containment remain unresolved.",
    )
    _baseline: SimulationPolicy | None = field(default=None, repr=False, compare=False)
    _candidate: SimulationPolicy | None = field(default=None, repr=False, compare=False)
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
            or not isinstance(self._baseline, SimulationPolicy)
            or not isinstance(self._candidate, SimulationPolicy)
            or self._baseline.digest != self.baseline_policy_digest
            or self._candidate.digest != self.candidate_policy_digest
        ):
            raise ValueError(
                "remediation proposal requires selected immutable policy configurations"
            )
        if self.repository_before.id != self.repository_after.id:
            raise ValueError("remediation must retain repository identity")

    def private_policy_artifact(self):
        """Explicit review material; profile digests do not recreate approved handles."""
        assert isinstance(self._baseline, SimulationPolicy) and isinstance(
            self._candidate, SimulationPolicy
        )
        return {
            "proposal": self.as_dict(),
            "before": self._baseline.as_dict(),
            "after": self._candidate.as_dict(),
        }

    def public_dict(self):
        packet = self.as_dict()
        packet["repository_before"] = self.repository_before.digest
        packet["repository_after"] = self.repository_after.digest
        packet["schema_version"] = "ordin.assurance_remediation_proposal_summary.v1"
        packet["report_digest"] = self.digest
        return packet


@dataclass(frozen=True)
class FixVerification(JsonRecord):
    SCHEMA = "assurance_fix_verification"
    NESTED = {"repository_before": RepositoryScope, "repository_after": RepositoryScope}
    proposal_digest: str
    original_validation_digest: str
    candidate_validation_digest: str | None
    repository_before: RepositoryScope
    repository_after: RepositoryScope
    result: str
    tested_scope: str
    original_fixture_digest: str
    candidate_fixture_digest: str
    benign_fixture_digests: tuple[str, ...]
    benign_regressions: int
    alternative_route_misses: int
    authority_delta: str
    simulation_digest: str | None
    baseline_p95_ms: float | None
    candidate_p95_ms: float | None
    proof_gaps: tuple[str, ...]
    limitations: tuple[str, ...]
    integrated: bool = False
    advisory_only: bool = True
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("fix verification requires an actual matched replay receipt")
        if self.result == "fixed-verified" and (
            self.proof_gaps
            or self.benign_regressions
            or self.alternative_route_misses
            or self.authority_delta not in {"unchanged", "narrowed"}
            or not self.candidate_validation_digest
            or not self.simulation_digest
            or not self.benign_fixture_digests
            or self.original_fixture_digest != self.candidate_fixture_digest
        ):
            raise ValueError(
                "verified fix requires unchanged reproduction, benign controls and containment"
            )

    def public_dict(self):
        packet = self.as_dict()
        packet["repository_before"] = self.repository_before.digest
        packet["repository_after"] = self.repository_after.digest
        packet["schema_version"] = "ordin.assurance_fix_verification_summary.v1"
        packet["report_digest"] = self.digest
        return packet


def propose_remediation(
    validation, before, after, candidate_repository, *, source_patch_digest=None
):
    if (
        not isinstance(validation, FindingValidation)
        or validation.result != "confirmed"
        or validation.mode != "replay"
        or not isinstance(before, SimulationPolicy)
        or not isinstance(after, SimulationPolicy)
        or not isinstance(candidate_repository, RepositoryScope)
        or before.build_gate().configuration_digest != validation.configuration_digest
    ):
        raise ValueError("remediation needs a confirmed matching original policy replay")
    changed = (
        before.approved_profile != after.approved_profile
        or before.require_profile != after.require_profile
        or before.capability_authorities != after.capability_authorities
        or before.request_authorities != after.request_authorities
    )
    return _issue(
        RemediationProposal,
        dict(
            proposal_id="proposal:"
            + digest("remediation_selection", [validation.digest, after.digest])[:24],
            validation_digest=validation.digest,
            finding_digest=validation.finding_digest,
            repository_before=validation.repository,
            repository_after=candidate_repository,
            baseline_policy_digest=before.digest,
            candidate_policy_digest=after.digest,
            expected_authority_digest=validation.boundary_digest,
            authority_delta=policy_authority_delta(before, after),
            protected_host_configuration_changed=changed,
            proposed_source_patch_digest=source_patch_digest,
            review_required=True,
            applied=False,
            limitations=(
                "A proposal is never applied, activated, published or integrated.",
                "Profile/host configuration changes with unknown containment remain unresolved.",
            ),
            _baseline=before,
            _candidate=after,
        ),
    )


def propose_invariant_remediation(validation: FindingValidation):
    if (
        not isinstance(validation, FindingValidation)
        or validation.result != "confirmed"
        or validation.action_kind is None
    ):
        raise ValueError("invariant suggestion requires independently confirmed scoped evidence")
    rule = SecurityInvariant(
        validation.invariant_id,
        "resource_subset",
        InvariantSelectors(kinds=(validation.action_kind,)),
        on_violation="escalate",
        authority_ref="finding.expected-bound",
    )
    return SecurityProfileDraft(
        "remediation:" + validation.digest[:24],
        validation.repository,
        "ordin.assurance.scoped-validation.v1",
        invariant_suggestions=(rule,),
        unresolved_facts=(
            "Operator must select and verify the exact expected authority and supported mapping.",
            "This draft must preserve benign operations before protected activation.",
        ),
    )


def _check_pair(old_scope, new_scope, old_fixture, new_fixture):
    if not isinstance(old_fixture, ReplayFixture) or not isinstance(new_fixture, ReplayFixture):
        raise ValueError("fix verification requires pairs of pinned replay fixtures")
    if old_fixture.source.content_digest != new_fixture.source.content_digest or core_digest(
        old_fixture.action.as_dict()
    ) != core_digest(new_fixture.action.as_dict()):
        return "Original test/labels/action bytes were changed instead of preserving reproduction."
    if not verify_source_reference(old_scope, old_fixture.source) or not verify_source_reference(
        new_scope, new_fixture.source
    ):
        return "Original or candidate test provenance is stale, missing or unavailable."
    return None


def verify_fix(
    proposal,
    original_validation,
    *,
    before_scope,
    before_source,
    before_finding,
    before_review,
    after_scope,
    after_source,
    after_finding,
    after_review,
    reproduction,
    benign_controls,
    boundary,
    alternative_routes=(),
):
    """Run the preserved failing path first, then candidate/control/simulation replays."""
    if (
        not isinstance(proposal, RemediationProposal)
        or not isinstance(original_validation, FindingValidation)
        or proposal.validation_digest != original_validation.digest
        or original_validation.result != "confirmed"
        or proposal.repository_before != before_scope.repository
        or proposal.repository_after != after_scope.repository
        or not isinstance(boundary, RuntimeCapabilityBoundary)
        or boundary.digest != proposal.expected_authority_digest
        or original_validation.finding_digest != before_finding.digest
        or original_validation.review_digest != before_review.digest
        or original_validation.source_key != before_source.key
        or after_review.rubric.invariant_id != before_review.rubric.invariant_id
        or after_review.rubric.expected_authority_digest
        != before_review.rubric.expected_authority_digest
        or after_review.rubric.actor != before_review.rubric.actor
        or after_review.rubric.allowed_permissions != before_review.rubric.allowed_permissions
    ):
        raise ValueError("fix verification proposal/finding/property scope mismatch")
    if not isinstance(reproduction, tuple) or len(reproduction) != 2:
        raise ValueError("fix verification requires original and candidate reproduction")
    for pairs in (benign_controls, alternative_routes):
        if (
            not isinstance(pairs, tuple)
            or len(pairs) > 64
            or any(not isinstance(pair, tuple) or len(pair) != 2 for pair in pairs)
        ):
            raise ValueError("fix controls require bounded frozen fixture pairs")
    old_fixture, new_fixture = reproduction
    gaps = _check_review(
        before_scope, before_source, before_finding, before_review, boundary, old_fixture
    )
    gaps += _check_review(
        after_scope, after_source, after_finding, after_review, boundary, new_fixture
    )
    for pair in (reproduction, *benign_controls, *alternative_routes):
        gap = _check_pair(before_scope, after_scope, *pair)
        if gap:
            gaps.append(gap)
    if (
        original_validation.fixture_digest != old_fixture.source.content_digest
        or original_validation.action_digest != core_digest(old_fixture.action.as_dict())
    ):
        gaps.append("Reproduction differs from the originally confirmed test.")
    if not benign_controls:
        gaps.append("A benign counterpart with unchanged test provenance is required.")
    before_policy, after_policy = proposal._baseline, proposal._candidate
    assert isinstance(before_policy, SimulationPolicy) and isinstance(
        after_policy, SimulationPolicy
    )
    if (
        before_policy.digest != proposal.baseline_policy_digest
        or after_policy.digest != proposal.candidate_policy_digest
    ):
        raise ValueError("selected proposal policy changed after review")
    can_replay = not gaps
    delta = policy_authority_delta(before_policy, after_policy)
    if delta not in {"unchanged", "narrowed"}:
        gaps.append("Exact policy/authority containment is widened, unsupported or unknown.")
    if proposal.proposed_source_patch_digest is not None:
        gaps.append(
            "Policy replay does not exercise target source code; a source patch needs vetted independent test execution."
        )
    result, candidate_result, simulation = "inconclusive", None, None
    benign_regressions = alternative_misses = 0
    cases = []
    if can_replay:
        old_gate, new_gate = before_policy.build_gate(), after_policy.build_gate()
        original = validate_finding_replay(
            before_scope,
            before_source,
            before_finding,
            before_review,
            old_fixture,
            old_gate,
            boundary,
        )
        if original.result != "confirmed":
            gaps.append("The original failing path was not reproduced before testing the proposal.")
        else:
            candidate_result = validate_finding_replay(
                after_scope,
                after_source,
                after_finding,
                after_review,
                new_fixture,
                new_gate,
                boundary,
            )
            cases.append(
                FrozenCase(
                    new_fixture.case_id,
                    new_fixture.action,
                    expected="escalate",
                    label="adversarial",
                    critical=True,
                )
            )
            for old_control, new_control in benign_controls:
                a = old_gate.evaluate_action(
                    old_control.action, host_context=before_source.context()
                )
                b = new_gate.evaluate_action(
                    new_control.action, host_context=after_source.context()
                )
                bounds = [
                    verify_assurance_capability(
                        derive_runtime_capability_contract(row.review), boundary
                    )
                    for row in (a, b)
                ]
                if not a.may_execute or not bounds[0].ok:
                    gaps.append(
                        "The declared benign counterpart is not a supported baseline control."
                    )
                if not b.may_execute or not bounds[1].ok:
                    benign_regressions += 1
                cases.append(
                    FrozenCase(
                        new_control.case_id, new_control.action, expected="execute", label="benign"
                    )
                )
            for old_alternative, new_alternative in alternative_routes:
                a = old_gate.evaluate_action(
                    old_alternative.action, host_context=before_source.context()
                )
                original_bound = verify_assurance_capability(
                    derive_runtime_capability_contract(a.review), boundary
                )
                if not a.may_execute or original_bound.result != "exceeds_boundary":
                    gaps.append(
                        "An alternative route does not reproduce a supported original property violation."
                    )
                b = new_gate.evaluate_action(
                    new_alternative.action, host_context=after_source.context()
                )
                checked = verify_assurance_capability(
                    derive_runtime_capability_contract(b.review), boundary
                )
                if checked.result in {"unsupported", "inconclusive"}:
                    gaps.append("An alternative route has an unresolved capability mapping.")
                elif b.may_execute and checked.result == "exceeds_boundary":
                    alternative_misses += 1
                cases.append(
                    FrozenCase(
                        new_alternative.case_id,
                        new_alternative.action,
                        expected="escalate",
                        label="adversarial",
                        critical=True,
                    )
                )
            corpus = FrozenCorpus.synthetic(tuple(cases))
            simulation = simulate_policy_change(
                before_policy,
                after_policy,
                corpus,
                baseline_revision=before_scope.repository.revision,
                candidate_revision=after_scope.repository.revision,
                expected_corpus_digest=corpus.digest,
            )
            if candidate_result.result == "confirmed" or alternative_misses:
                result = "still-vulnerable"
            elif (
                candidate_result.result == "refuted"
                and not benign_regressions
                and simulation.activation_safe
            ):
                result = "fixed-verified"
            else:
                gaps.append(
                    "Candidate, benign or affected policy replay remains inconclusive or regressed."
                )
    for pair in (reproduction, *benign_controls, *alternative_routes):
        gap = _check_pair(before_scope, after_scope, *pair)
        if gap:
            gaps.append(gap)
    gaps += _check_review(
        before_scope, before_source, before_finding, before_review, boundary, old_fixture
    )
    gaps += _check_review(
        after_scope, after_source, after_finding, after_review, boundary, new_fixture
    )
    if gaps and result == "fixed-verified":
        result = "inconclusive"
    return _issue(
        FixVerification,
        dict(
            proposal_digest=proposal.digest,
            original_validation_digest=original_validation.digest,
            candidate_validation_digest=candidate_result.digest if candidate_result else None,
            repository_before=before_scope.repository,
            repository_after=after_scope.repository,
            result=result,
            tested_scope="policy_replay",
            original_fixture_digest=old_fixture.source.content_digest,
            candidate_fixture_digest=new_fixture.source.content_digest,
            benign_fixture_digests=tuple(pair[0].source.content_digest for pair in benign_controls),
            benign_regressions=benign_regressions,
            alternative_route_misses=alternative_misses,
            authority_delta=delta,
            simulation_digest=simulation.digest if simulation else None,
            baseline_p95_ms=simulation.baseline_latency.p95_ms if simulation else None,
            candidate_p95_ms=simulation.candidate_latency.p95_ms if simulation else None,
            proof_gaps=tuple(dict.fromkeys(gaps)),
            limitations=(
                "Verified means the exact tested policy/fixture property, not all vulnerabilities or physical host enforcement.",
                "This finite affected-boundary replay does not replace safety/unit/integration or full release suites.",
                "Latency samples are reported, not repeated matched performance acceptance.",
                "Unprovided alternative routes remain outside coverage; source patches are not exercised.",
            ),
            integrated=False,
            advisory_only=True,
        ),
    )
