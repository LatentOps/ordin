"""Conservative source-flow guard results from authenticated exact-byte provenance."""

from ordin._runtime_json import digest as core_digest

from .attack_paths import ReviewedAction
from .host import HostConstraintAssessment
from .models import ApprovedSecurityProfile
from .origins import InstructionOrigin, SourceProvenance, SourceUse, verify_source_use


def assess_source_flow(
    reviewed: ReviewedAction,
    profile: ApprovedSecurityProfile,
    *,
    invariant_id: str,
    provenance: SourceProvenance,
    origins: tuple[InstructionOrigin, ...] = (),
    uses: tuple[SourceUse, ...] = (),
) -> HostConstraintAssessment:
    """Issue a scope-bound guard result; never authorize execution or claim causality.

    Sensitive bytes in proposed egress arguments and untrusted bytes supplied as
    instruction context violate the guard. A satisfied result requires explicit
    complete host collection and known classifications, or a non-applicable rule.
    Use the resulting receipt in a fresh exact-action gate review. The original
    escalation remains an escalation until the host performs that review.
    """
    if (
        not isinstance(reviewed, ReviewedAction)
        or not isinstance(profile, ApprovedSecurityProfile)
        or not isinstance(provenance, SourceProvenance)
    ):
        raise ValueError("source-flow assessment requires protected review/profile/provenance")
    reviewed.validate()
    source = reviewed.context.source
    source._check_profile(profile)
    if reviewed.decision.profile_digest != profile.digest:
        raise ValueError("source-flow review selected another profile")
    action = reviewed.decision.review.action
    if provenance.source_key != source.key or provenance.action_digest != core_digest(
        action.as_dict()
    ):
        raise ValueError("source-flow provenance belongs to another action or host scope")
    if (
        not isinstance(origins, (tuple, list))
        or not isinstance(uses, (tuple, list))
        or len(origins) > 128
        or len(uses) > 128
        or any(not isinstance(v, InstructionOrigin) for v in origins)
        or any(not isinstance(v, SourceUse) for v in uses)
    ):
        raise ValueError("source-flow handles must be bounded and typed")
    if (
        tuple(sorted(v.digest for v in origins)) != provenance.origin_digests
        or tuple(sorted(v.digest for v in uses)) != provenance.use_digests
    ):
        raise ValueError("source-flow collection changed after host declaration")
    rule = next((r for r in profile.profile.invariants if r.invariant_id == invariant_id), None)
    if rule is None or rule.kind != "source_flow_guard":
        raise ValueError("source-flow invariant is not selected by the protected profile")
    prior = next(
        (r for r in reviewed.decision.invariant_evaluations if r.invariant_id == invariant_id), None
    )
    gaps: tuple[str, ...]
    status, gaps = "inconclusive", ("Complete authenticated source provenance is unavailable.",)
    if prior is not None and prior.reason_code.endswith("_not_applicable"):
        status, gaps = "satisfied", ()
    else:
        by_digest = {o.digest: o for o in origins}
        if any(
            use.origin_digest not in by_digest
            or not verify_source_use(source, by_digest[use.origin_digest], use, action)
            for use in uses
        ):
            raise ValueError("source-flow use no longer matches its source or exact action")
        effects = set(reviewed.decision.review.effects)
        egress = any(e.startswith("network.") for e in effects)
        violations = [
            use
            for use in uses
            if (by_digest[use.origin_digest].classification == "sensitive" and egress)
            or (
                use.usage == "instruction_context"
                and by_digest[use.origin_digest].kind != "authorized_user"
            )
        ]
        if violations:
            status, gaps = "violated", ()
        elif prior is not None and prior.status == "unsupported":
            status, gaps = (
                "unsupported",
                ("Rule scope is not representable by the current source-flow verifier.",),
            )
        elif provenance.completeness == "complete" and all(
            o.classification != "unknown" and o.kind != "unknown_origin" for o in origins
        ):
            status, gaps = "satisfied", ()
    return source.record_assessment(
        action,
        profile,
        assessment_id="source-flow:" + provenance.digest[:24] + ":" + rule.digest[:12],
        invariant_id=invariant_id,
        kind="source_flow_guard",
        status=status,
        proof_gaps=gaps,
    )
