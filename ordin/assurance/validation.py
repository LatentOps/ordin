"""Scoped finding review/replay. Target source and reviewed actions stay inert."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, fields

from ordin import ActionEnvelope, ActionHistory
from ordin._runtime_json import digest as core_digest
from ordin.runtime_contract import RuntimeCapabilityContract, derive_runtime_capability_contract
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_observation import (
    RuntimeObservation,
    RuntimeObservationHistory,
    RuntimeEvidenceSource,
    RuntimeCorrelationError,
)

from ._files import read_scoped_file, ScopedFileError
from ._json import digest, loads, validate
from .attack_paths import ReviewedAction
from .gate import AssuranceGate
from .host import HostEvidenceSource
from .inventory import AuthorizedRepository, verify_source_reference, inventory_repository
from .models import (
    EvidenceLink,
    SecurityFinding,
    SourceReference,
    _EvidenceAuthority,
    _FindingAuthority,
)
from .requests import verify_assurance_capability
from .validation_models import (
    FindingRubric,
    FindingReview,
    FindingValidation,
    HostContractAuthorization,
    _ValidationAuthority,
)


def _issue(model, values, authority=_ValidationAuthority):
    preview = object.__new__(model)
    for name, value in values.items():
        object.__setattr__(preview, name, value)
    return model(**values, _authority=authority(preview.digest))


def _link(origin, identity, *, source=None, action_digest=None, contract_id=None, session=None):
    return _issue(
        EvidenceLink,
        dict(
            evidence_id=identity,
            origin=origin,
            source=source,
            action_digest=action_digest,
            contract_id=contract_id,
            session_digest=session,
            proof_gaps=(),
        ),
        _EvidenceAuthority,
    )


def _scope_pin_gaps(scope):
    if scope.expected_snapshot_digest is None:
        return []
    try:
        inspected = inventory_repository(scope)
    except ScopedFileError:
        return ["The pinned authorized repository snapshot changed or is unavailable."]
    return (
        []
        if inspected.completeness == "complete"
        else ["The pinned repository inventory has unsupported inspection coverage."]
    )


def review_finding(scope: AuthorizedRepository, candidate: SecurityFinding, rubric: FindingRubric):
    if (
        not isinstance(scope, AuthorizedRepository)
        or not isinstance(candidate, SecurityFinding)
        or not isinstance(rubric, FindingRubric)
        or candidate.repository != scope.repository
    ):
        raise ValueError("finding review requires matching authorized source/rubric")
    if candidate.status in {"confirmed", "refuted"}:
        raise ValueError("review starts from a candidate, not an existing closure")
    references = {
        reference.digest: reference
        for reference in (
            *candidate.affected_sources,
            *rubric.controlled_sources,
            *rubric.source_to_sink,
            *rubric.existing_controls,
        )
    }
    if len(references) > 128:
        raise ValueError("finding source inspection limit exceeded")
    verified = tuple(
        reference
        for _, reference in sorted(references.items())
        if verify_source_reference(scope, reference)
    )
    gaps = _scope_pin_gaps(scope)
    if len(verified) != len(references):
        gaps.append("One or more source references are stale, invalid or unavailable.")
    if not candidate.affected_sources or not rubric.controlled_sources or not rubric.source_to_sink:
        gaps.append("Attacker-controlled source and source-to-sink references are required.")
    if candidate.invariant_id != rubric.invariant_id:
        gaps.append("Candidate invariant does not match the reviewed security property.")
    if rubric.unknowns:
        gaps.append("The reviewed rubric retains unresolved facts.")
    by_digest = {reference.digest for reference in verified}
    controls = {reference.digest for reference in rubric.existing_controls}
    evidence: list[EvidenceLink] = []
    counter: list[EvidenceLink] = []
    for reference in verified:
        link = _link("static_evidence", "source:" + reference.digest[:24], source=reference)
        (counter if reference.digest in controls else evidence).append(link)
    return _issue(
        FindingReview,
        dict(
            finding_digest=candidate.digest,
            repository=scope.repository,
            rubric=rubric,
            source_snapshot_digest=digest("finding_source_snapshot", sorted(by_digest)),
            verified_sources=verified,
            evidence=tuple(evidence),
            counterevidence=tuple(counter),
            proof_gaps=tuple(gaps),
            status="inconclusive" if gaps else "reviewed",
            advisory_only=True,
        ),
    )


@dataclass(frozen=True)
class _FixtureAuthority:
    payload_digest: str


@dataclass(frozen=True)
class ReplayFixture:
    case_id: str
    action: ActionEnvelope = field(repr=False)
    source: SourceReference
    _authority: _FixtureAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if (
            not isinstance(self.action, ActionEnvelope)
            or not isinstance(self.source, SourceReference)
            or not isinstance(self._authority, _FixtureAuthority)
            or self._authority.payload_digest != self.digest
            or self.action.action_id != self.case_id
        ):
            raise ValueError("replay fixture requires exact inspected bytes and action identity")

    @property
    def digest(self):
        return digest(
            "finding_replay_fixture",
            {
                "case_id": self.case_id,
                "action": self.action.as_dict(),
                "source": self.source.as_dict(),
            },
        )


def load_replay_fixture(scope: AuthorizedRepository, reference: SourceReference):
    if not verify_source_reference(scope, reference) or reference.symbol is not None:
        raise ValueError("replay fixture source reference is invalid")
    raw = read_scoped_file(scope.root, reference.path, maximum=65536)
    if hashlib.sha256(raw).hexdigest() != reference.content_digest:
        raise ValueError("replay fixture changed during inspection")
    packet = loads(raw)
    validate("assurance_replay_input", packet)
    action = ActionEnvelope.from_dict(packet["action"])
    values = dict(case_id=packet["case_id"], action=action, source=reference)
    preview = object.__new__(ReplayFixture)
    for name, value in values.items():
        object.__setattr__(preview, name, value)
    return ReplayFixture(**values, _authority=_FixtureAuthority(preview.digest))


def _check_review(scope, source, candidate, review, boundary=None, fixture=None):
    if (
        not isinstance(scope, AuthorizedRepository)
        or not isinstance(source, HostEvidenceSource)
        or not isinstance(candidate, SecurityFinding)
        or not isinstance(review, FindingReview)
        or candidate.repository != scope.repository
        or review.repository != scope.repository
        or source.repository != scope.repository
        or review.finding_digest != candidate.digest
    ):
        raise ValueError("validation source/candidate/review scope mismatch")
    gaps = [*review.proof_gaps, *_scope_pin_gaps(scope)]
    if review.rubric.actor != source.principal:
        gaps.append("The tested host principal does not match the reviewed actor.")
    if any(not verify_source_reference(scope, reference) for reference in review.verified_sources):
        gaps.append("Reviewed source bytes changed after static inspection.")
    if review.rubric.preconditions:
        gaps.append("Additional declared preconditions lack authenticated setup verification.")
    if boundary is not None and (
        not isinstance(boundary, RuntimeCapabilityBoundary)
        or boundary.digest != review.rubric.expected_authority_digest
    ):
        raise ValueError("validation authority bound differs from reviewed property")
    if fixture is not None:
        if not isinstance(fixture, ReplayFixture):
            raise ValueError("replay requires a pinned inspected fixture")
        if not verify_source_reference(scope, fixture.source):
            gaps.append("Replay fixture bytes/revision changed after selection.")
    return gaps


def _result(
    source,
    candidate,
    review,
    mode,
    *,
    result="inconclusive",
    fixture=None,
    configuration=None,
    authorization_digest=None,
    evidence=(),
    counter=(),
    gaps=(),
    scope="static_references",
):
    return _issue(
        FindingValidation,
        dict(
            validation_id="validation:"
            + digest(
                "validation_identity",
                [candidate.digest, mode, fixture.digest if fixture else None, configuration],
            )[:24],
            finding_digest=candidate.digest,
            review_digest=review.digest,
            repository=review.repository,
            mode=mode,
            result=result,
            invariant_id=review.rubric.invariant_id,
            boundary_digest=review.rubric.expected_authority_digest,
            action_digest=core_digest(fixture.action.as_dict()) if fixture else None,
            action_kind=fixture.action.kind if fixture else None,
            fixture_digest=fixture.source.content_digest if fixture else None,
            fixture_source=fixture.source if fixture else None,
            configuration_digest=configuration,
            evidence=tuple(evidence),
            counterevidence=tuple(counter),
            proof_gaps=tuple(dict.fromkeys(gaps)),
            safe_reproducer_ref=fixture.case_id if fixture else None,
            tested_scope=scope,
            contract_authorization_digest=authorization_digest,
            source_key=source.key,
            limitations=(
                "Closure is limited to this exact revision, fixture, bound and configuration.",
                "Replay does not execute proposals or establish backend exploit reachability.",
                "Static references establish bytes; they do not prove causality or control effectiveness.",
            ),
            advisory_only=True,
        ),
    )


def validate_finding_static(scope, source, candidate, review):
    gaps = _check_review(scope, source, candidate, review)
    gaps.append(
        "Static inspection cannot establish runtime reproduction or decisive falsification."
    )
    return _result(
        source,
        candidate,
        review,
        "static",
        evidence=review.evidence,
        counter=review.counterevidence,
        gaps=gaps,
    )


def validate_finding_replay(scope, source, candidate, review, fixture, gate, boundary):
    gaps = _check_review(scope, source, candidate, review, boundary, fixture)
    if not isinstance(gate, AssuranceGate):
        raise ValueError("replay requires an actual Assurance gate")
    configuration = gate.configuration_digest
    if candidate.issue_class != "gate_authority_subset":
        gaps.append("No vetted replay predicate is registered for this finding class.")
    if gaps:
        return _result(
            source,
            candidate,
            review,
            "replay",
            fixture=fixture,
            configuration=configuration,
            gaps=gaps,
            scope="gate_authority_subset",
        )
    decision = gate.evaluate_action(fixture.action, host_context=source.context())
    contract = derive_runtime_capability_contract(decision.review)
    verification = verify_assurance_capability(contract, boundary)
    after_gaps = _check_review(scope, source, candidate, review, boundary, fixture)
    if configuration != gate.configuration_digest:
        after_gaps.append("Gate configuration changed during replay.")
    link = _link(
        "deterministically_derived",
        "replay:" + decision.evidence_digest[:24],
        action_digest=decision.action_digest,
        contract_id=contract.contract_id,
        session=source.session_digest,
    )
    result = "inconclusive"
    counter, evidence = list(review.counterevidence), list(review.evidence)
    if verification.result in {"unsupported", "inconclusive"}:
        after_gaps.append(
            "The requested capability/property mapping is unsupported or inconclusive."
        )
    elif decision.may_execute and verification.result == "exceeds_boundary":
        result = "confirmed"
        evidence.append(link)
    else:
        result = "refuted"
        counter.append(link)
    if after_gaps:
        result = "inconclusive"
    return _result(
        source,
        candidate,
        review,
        "replay",
        result=result,
        fixture=fixture,
        configuration=configuration,
        evidence=evidence,
        counter=counter,
        gaps=after_gaps,
        scope="gate_authority_subset",
    )


def validate_finding_host_observation(
    scope,
    source,
    candidate,
    review,
    fixture,
    reviewed,
    boundary,
    observation,
    runtime_source,
    *,
    contract_authorization=None,
):
    gaps = _check_review(scope, source, candidate, review, boundary, fixture)
    if not isinstance(reviewed, ReviewedAction) or not isinstance(
        runtime_source, RuntimeEvidenceSource
    ):
        raise ValueError("host validation requires actual sealed review and runtime source")
    reviewed.validate()
    if reviewed.context.source.key != source.key or reviewed.decision.action_digest != core_digest(
        fixture.action.as_dict()
    ):
        raise ValueError("host validation review/action/session mismatch")
    if (runtime_source.session_digest, runtime_source.policy_digest) != (
        source.session_digest,
        source.runtime_policy_digest,
    ):
        raise ValueError("host observation belongs to another session/policy")
    contract = derive_runtime_capability_contract(reviewed.decision.review)
    verification = verify_assurance_capability(contract, boundary)
    if candidate.issue_class != "gate_authority_subset":
        gaps.append("No vetted observation predicate is registered for this finding class.")
    if not isinstance(observation, RuntimeObservation) or observation.trust not in {
        "backend_observed",
        "backend_enforced",
    }:
        gaps.append("Caller assertions cannot supply authenticated runtime validation.")
    else:
        try:
            RuntimeObservationHistory((observation,), (contract,)).correlate(
                ActionHistory((fixture.action,)),
                session_digest=source.session_digest,
                allowed_sources=(runtime_source,),
            )
        except RuntimeCorrelationError:
            gaps.append("Runtime evidence failed exact action/contract/session correlation.")
    if (
        reviewed.decision.denied
        and isinstance(observation, RuntimeObservation)
        and observation.outcome != "denied"
    ):
        gaps.append("A successful observation cannot follow a denied Assurance action.")
    evidence, counter = list(review.evidence), list(review.counterevidence)
    result = "inconclusive"
    grant_verified = (
        isinstance(observation, RuntimeObservation)
        and observation.trust == "backend_enforced"
        and isinstance(contract_authorization, HostContractAuthorization)
        and contract_authorization.source_key == source.key
        and contract_authorization.runtime_source_key == runtime_source.key
        and contract_authorization.observation_digest == observation.digest
        and contract_authorization.contract_digest == contract.digest
        and contract_authorization.repository == scope.repository
    )
    if not gaps:
        link = _link(
            "runtime_backend_observed",
            "observation:" + observation.digest[:24],
            action_digest=contract.action_digest,
            contract_id=contract.contract_id,
            session=source.session_digest,
        )
        if observation.outcome == "denied":
            result = "refuted"
            counter.append(link)
        elif (
            observation.outcome in {"completed", "allowed"}
            and verification.result == "exceeds_boundary"
        ):
            # Completion does not mean every requested right was granted or
            # exercised. Require an actual backend authorization attestation.
            if grant_verified:
                result = "confirmed"
                evidence.append(link)
            else:
                gaps.append(
                    "Backend completion/allowance does not attest authorization of the entire exact contract."
                )
        elif (
            observation.outcome in {"completed", "allowed"}
            and verification.result == "within_boundary"
        ):
            if grant_verified:
                result = "refuted"
                counter.append(link)
            else:
                gaps.append(
                    "The completed request does not establish the actual entire grant scope."
                )
        else:
            gaps.append(
                "Failed/unknown execution or incomplete capability mapping does not settle the claim."
            )
    gaps.extend(_check_review(scope, source, candidate, review, boundary, fixture))
    if gaps:
        result = "inconclusive"
    return _result(
        source,
        candidate,
        review,
        "host_observation",
        result=result,
        fixture=fixture,
        configuration=reviewed.decision.assurance_configuration_digest,
        authorization_digest=contract_authorization.digest if grant_verified else None,
        evidence=evidence,
        counter=counter,
        gaps=gaps,
        scope="observed_contract_authorization",
    )


def record_contract_authorization(source, runtime_source, observation, granted_contract):
    """Protected host only, after actual backend verification of the whole grant.

    This channel authenticates the host result; calling it does not establish
    OS enforcement or turn a requested contract into an observed grant.
    """
    if (
        not isinstance(source, HostEvidenceSource)
        or not isinstance(runtime_source, RuntimeEvidenceSource)
        or not isinstance(observation, RuntimeObservation)
        or not isinstance(granted_contract, RuntimeCapabilityContract)
        or observation.trust != "backend_enforced"
        or observation.outcome not in {"allowed", "completed"}
        or observation.source_key != runtime_source.key
        or observation.action_id != granted_contract.action_id
        or observation.action_digest != granted_contract.action_digest
        or observation.contract_id != granted_contract.contract_id
        or (runtime_source.session_digest, runtime_source.policy_digest)
        != (source.session_digest, source.runtime_policy_digest)
    ):
        raise ValueError("actual backend contract grant does not match the protected event/source")
    return _issue(
        HostContractAuthorization,
        dict(
            source_key=source.key,
            runtime_source_key=runtime_source.key,
            observation_digest=observation.digest,
            contract_digest=granted_contract.digest,
            repository=source.repository,
            authorization_scope="entire_contract",
        ),
    )


def close_finding(scope, source, candidate, review, validation):
    gaps = _check_review(scope, source, candidate, review)
    if (
        not isinstance(validation, FindingValidation)
        or validation.finding_digest != candidate.digest
        or validation.review_digest != review.digest
        or validation.source_key != source.key
        or validation.repository != scope.repository
    ):
        raise ValueError("finding closure requires the matching protected validation")
    if gaps and validation.result != "inconclusive":
        raise ValueError("finding closure source/preconditions are stale or unresolved")
    if validation.result != "inconclusive" and (
        validation.fixture_source is None
        or not verify_source_reference(scope, validation.fixture_source)
    ):
        raise ValueError("finding closure test provenance changed after validation")
    values = {
        member.name: getattr(candidate, member.name)
        for member in fields(candidate)
        if not member.name.startswith("_")
    }
    values.update(
        status=validation.result,
        verification_method=validation.mode,
        evidence=validation.evidence,
        counterevidence=validation.counterevidence,
        proof_gaps=tuple(dict.fromkeys((*validation.proof_gaps, *gaps))),
        confidence=None,
        safe_reproducer_ref=validation.safe_reproducer_ref,
        origin="static_evidence",
        validation_digest=validation.digest,
        verification_scope=validation.tested_scope,
    )
    return _issue(SecurityFinding, values, _FindingAuthority)


def deduplicate_findings(candidates):
    if not isinstance(candidates, (tuple, list)) or not 1 <= len(candidates) <= 256:
        raise ValueError("deduplication requires bounded finding occurrences")
    groups: dict[str, list[str]] = {}
    for candidate in candidates:
        if not isinstance(candidate, SecurityFinding):
            raise ValueError("deduplication accepts only typed candidate findings")
        key = digest(
            "finding_occurrence_group", [candidate.repository.digest, candidate.dedupe_key]
        )
        # Same supplied ID can describe distinct occurrences. Retain each exact
        # record digest rather than choosing a strongest verdict or dropping it.
        groups.setdefault(key, []).append(candidate.digest)
    return tuple(
        (key, tuple(sorted(set(identifiers)))) for key, identifiers in sorted(groups.items())
    )
