"""Useful data-only CLI diagnostics; no file, label or preview creates authority."""

import posixpath

from ordin import ActionEnvelope, AgentGate, ActionReview
from ordin._runtime_json import digest as core_digest
from ordin.runtime_contract import _safe_path
from ordin.data import load_effect_catalog

from ._json import digest, validate
from .models import SecurityProfile, SecurityFinding
from .inventory import AuthorizedRepository, verify_source_reference
from .profiles import MUTATION_EFFECTS
from .validation_models import FindingRubric
from .validation import review_finding
from .delegation import DelegationAuthority, verify_delegation_subset


def inspect_profile_content(profile: SecurityProfile, *, include_details=False):
    if not isinstance(profile, SecurityProfile):
        raise ValueError("profile inspection requires validated content")
    return {
        "schema_version": "ordin.assurance_profile_inspection.v1",
        "profile_digest": profile.digest,
        "repository_digest": profile.repository.digest,
        "assets": len(profile.protected_assets),
        "invariants": [
            {
                "invariant_digest": rule.digest,
                "kind": rule.kind,
                "on_violation": rule.on_violation,
                "host_authority_required": rule.kind
                not in {"forbid_effect", "protected_policy_mutation"},
            }
            for rule in profile.invariants
        ],
        "approved": False,
        "activation_authorized": False,
        "profile": profile.as_dict() if include_details else None,
    }


def preview_invariants(profile: SecurityProfile, action: ActionEnvelope, *, gate=None):
    """Evaluate intrinsic selectors; host-dependent requirements remain unknown.

    This is prospective diagnostics on supplied content. It returns no approved
    profile, compiled policy or issued host fact, and changes no disposition.
    """
    if not isinstance(profile, SecurityProfile) or not isinstance(action, ActionEnvelope):
        raise ValueError("invariant preview needs typed profile content and action")
    baseline = (gate or AgentGate()).evaluate_action(action)
    review = baseline.review
    assert isinstance(review, ActionReview)
    assets = {asset.id: asset for asset in profile.protected_assets}
    known_effects = frozenset(load_effect_catalog())
    rows = []
    for rule in profile.invariants:
        status, reason = "inconclusive", "preview.host_authority_required"
        selectors = rule.selectors
        if selectors.kinds and action.kind not in selectors.kinds:
            status, reason = "not_applicable", "preview.kind_not_applicable"
        elif selectors.principal is not None or rule.authority_ref is not None:
            pass
        elif rule.kind in {"forbid_effect", "protected_policy_mutation"}:
            effects = (
                selectors.effects
                if rule.kind == "forbid_effect"
                else tuple(
                    effect
                    for effect in MUTATION_EFFECTS
                    if not selectors.effects or effect in selectors.effects
                )
            )
            if set(effects) - known_effects:
                status, reason = "unsupported", "preview.effect_label_unmodeled"
            elif (
                not effects
                or rule.kind == "protected_policy_mutation"
                and selectors.resource_ref is None
            ):
                status, reason = "unsupported", "preview.selector_incomplete"
            elif not set(effects).intersection(review.effects):
                status, reason = (
                    ("inconclusive", "preview.effect_unknown")
                    if review.risk == "unknown"
                    else ("not_applicable", "preview.effect_not_applicable")
                )
            else:
                status, reason = "violated", "preview.declared_forbidden_effect_matches"
                if selectors.resource_ref is not None:
                    asset = assets[selectors.resource_ref]
                    paths = [
                        resource.value for resource in review.resources if resource.type == "path"
                    ]
                    if asset.kind not in {"path", "policy"}:
                        status, reason = "unsupported", "preview.resource_identity_unmodeled"
                    elif not paths:
                        status, reason = "inconclusive", "preview.resource_missing"
                    elif any(
                        not _safe_path(path) or posixpath.normpath(path) != path for path in paths
                    ):
                        status, reason = "unsupported", "preview.path_alias_unproven"
                    elif not any(
                        path == asset.value
                        or asset.match == "prefix"
                        and path.startswith(asset.value.rstrip("/") + "/")
                        for path in paths
                    ):
                        status, reason = "not_applicable", "preview.resource_not_applicable"
                    elif len(paths) != 1:
                        status, reason = "inconclusive", "preview.effect_resource_binding_ambiguous"
        rows.append(
            {
                "invariant_digest": rule.digest,
                "kind": rule.kind,
                "status": status,
                "reason_code": reason,
                "proposed_on_violation": rule.on_violation,
            }
        )
    return {
        "schema_version": "ordin.assurance_invariant_preview.v1",
        "profile_digest": profile.digest,
        "action_digest": core_digest(action.as_dict()),
        "baseline_disposition": baseline.disposition,
        "evaluations": rows,
        "mode": "unapproved_content_preview",
        "activation_authorized": False,
        "limitations": [
            "Supplied profile content has not been approved or applied.",
            "Host-dependent scope/approval/grant/provenance/credential requirements remain unknown.",
            "Intrinsic matches describe requested declared rules, not active host enforcement.",
        ],
    }


def inspect_attack_path(payload, *, source_scope: AuthorizedRepository | None = None):
    """Inspect imported graph data without restoring strong evidence labels."""
    validate("assurance_attack_path", payload)
    sources = [
        link["source"]
        for link in (*payload["supporting_evidence"], *payload["counterevidence"])
        if link["source"] is not None
    ]
    from .models import SourceReference

    checked = 0
    if source_scope is not None:
        checked = sum(
            verify_source_reference(source_scope, SourceReference.from_dict(source))
            for source in sources
        )
    return {
        "schema_version": "ordin.assurance_attack_path_inspection.v1",
        "artifact_digest": digest("imported_attack_path", payload),
        "nodes": len(payload["nodes"]),
        "edges": len(payload["edges"]),
        "source_references": len(sources),
        "verified_source_references": checked,
        "reported_exposure": payload["exposure"],
        "reported_reachability": payload["reachability"],
        "reported_permissions": payload["permissions"],
        "origin": "imported_claim",
        "runtime_evidence_authenticated": False,
        "finding_confirmation": "not_performed",
        "limitations": [
            "JSON graph labels and edges are unverified claims; strong runtime/policy facts require protected SDK handles.",
            "Fresh source-byte checks establish references, not persuasion, exploitation or completed effects.",
        ],
    }


def compare_delegation_data(child, parent, *, operator=None, task=None):
    if not isinstance(child, DelegationAuthority) or not isinstance(parent, DelegationAuthority):
        raise ValueError("delegation inspection needs typed declared authority maxima")
    if operator is None or task is None:
        return {
            "schema_version": "ordin.assurance_delegation_inspection.v1",
            "result": "inconclusive",
            "child_digest": child.digest,
            "parent_digest": parent.digest,
            "proof_gaps": [
                "Operator and task maxima must be supplied separately; they cannot be inferred from parent JSON."
            ],
            "grant_issued": False,
            "lifecycle_checked": False,
            "authority_origin": "declared_data",
            "verification": None,
        }
    result = verify_delegation_subset(child, parent, operator, task)
    return {
        "schema_version": "ordin.assurance_delegation_inspection.v1",
        "result": result.result,
        "verification": result.as_dict(),
        "grant_issued": False,
        "lifecycle_checked": False,
        "authority_origin": "declared_data",
        "child_digest": child.digest,
        "parent_digest": parent.digest,
        "proof_gaps": list(result.proof_gaps),
    }


def review_static_candidate(scope, candidate: SecurityFinding, rubric: FindingRubric):
    review = review_finding(scope, candidate, rubric)
    return {
        "schema_version": "ordin.assurance_static_finding_review.v1",
        "review": review.public_dict(),
        "mode": "static",
        "result": "inconclusive",
        "finding_digest": candidate.digest,
        "runtime_reproduction": False,
        "closure": "not_performed",
        "proof_gaps": [
            *review.proof_gaps,
            "Read-only source review cannot supply runtime reproduction or decisive falsification.",
        ],
    }
