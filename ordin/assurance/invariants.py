"""Pure bounded checks over the exact baseline review and protected host facts."""

from __future__ import annotations

import posixpath
from dataclasses import replace

from ordin.action import ActionHistory, ActionReview
from ordin.action_policy import PolicyResourceMatcher
from ordin.audit import action_digest
from ordin._runtime_json import digest as core_digest
from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.runtime_contract import (
    RuntimeCapabilityContract,
    CredentialBinding,
    ProcessCapability,
    PrivilegeCapability,
    _safe_path,
    derive_runtime_capability_contract,
)
from ordin.runtime_requests_v2 import (
    derive_runtime_request_contract_v2,
)

from .host import AssuranceHostContext
from .models import ApprovedSecurityProfile, InvariantEvaluation, SecurityInvariant
from .profiles import MUTATION_EFFECTS
from .requests import verify_assurance_capability, verify_assurance_request_authority


def profile_scope_error(
    profile: ApprovedSecurityProfile, host: AssuranceHostContext | None
) -> str | None:
    if host is None:
        return "assurance.host_context_missing"
    if not isinstance(host, AssuranceHostContext):
        return "assurance.host_context_untrusted"
    if host.source.repository != profile.profile.repository:
        return "assurance.repository_scope_changed"
    if host.source.selection_digest != profile.selection_digest:
        return "assurance.profile_selection_changed"
    if host.source.runtime_policy_digest != profile.runtime_policy_digest:
        return "assurance.runtime_policy_changed"
    return None


def evaluate_approved_invariants(
    review: ActionReview,
    profile: ApprovedSecurityProfile,
    *,
    host_context: AssuranceHostContext | None = None,
    history: ActionHistory | None = None,
    contract: RuntimeCapabilityContract | None = None,
) -> tuple[InvariantEvaluation, ...]:
    if not isinstance(review, ActionReview) or not isinstance(profile, ApprovedSecurityProfile):
        raise ValueError(
            "invariant evaluation requires a baseline ActionReview and approved profile"
        )
    if history is not None and not isinstance(history, ActionHistory):
        raise ValueError("invariant evaluation requires exact typed history")
    scope_error = profile_scope_error(profile, host_context)
    policy_hash = profile.digest
    action_hash = action_digest(review)
    if contract is not None and (
        not isinstance(contract, RuntimeCapabilityContract) or contract.action_digest != action_hash
    ):
        raise ValueError("invariant runtime contract does not match the reviewed action")
    assets = {asset.id: asset for asset in profile.profile.protected_assets}
    effective_contract: RuntimeCapabilityContract | None = None

    def runtime_contract() -> RuntimeCapabilityContract:
        nonlocal effective_contract
        if effective_contract is None:
            effective_contract = derive_runtime_capability_contract(review)
            if isinstance(host_context, AssuranceHostContext):
                credentials = tuple(
                    dict.fromkeys(
                        CredentialBinding(item.binding, item.host, item.port)
                        for item in host_context.credential_uses
                        if item.action_digest == action_hash and item.profile_digest == policy_hash
                    )
                )
                if credentials:
                    effective_contract = replace(
                        effective_contract, credentials=credentials, contract_id=""
                    )
            if contract is not None and contract != effective_contract:
                raise ValueError(
                    "supplied contract differs from reviewed and host-bound requirements"
                )
        return effective_contract

    def result(
        rule: SecurityInvariant,
        status: str,
        code: str,
        *,
        matched: tuple[str, ...] = (),
        unknowns: tuple[str, ...] = (),
    ) -> InvariantEvaluation:
        return InvariantEvaluation(
            rule.invariant_id,
            status,
            code,
            policy_hash,
            action_hash,
            matched,
            unknowns,
            effective_contract.contract_id if effective_contract else None,
        )

    evaluations = []
    for rule in profile.profile.invariants:
        selectors = rule.selectors
        if selectors.kinds and review.action.kind not in selectors.kinds:
            evaluations.append(result(rule, "satisfied", "assurance.kind_not_applicable"))
            continue
        if scope_error:
            evaluations.append(
                result(
                    rule,
                    "inconclusive",
                    scope_error,
                    unknowns=("Protected host scope is unavailable or changed.",),
                )
            )
            continue
        assert isinstance(host_context, AssuranceHostContext)
        if selectors.principal is not None and selectors.principal != host_context.source.principal:
            evaluations.append(result(rule, "satisfied", "assurance.principal_not_applicable"))
            continue
        effects = selectors.effects
        if rule.kind == "protected_policy_mutation":
            effects = tuple(
                effect
                for effect in MUTATION_EFFECTS
                if not selectors.effects or effect in selectors.effects
            )
            if not effects or selectors.resource_ref is None:
                evaluations.append(
                    result(rule, "unsupported", "assurance.protected_mutation_scope_missing")
                )
                continue
        if rule.kind == "forbid_effect" and not effects:
            evaluations.append(result(rule, "unsupported", "assurance.forbidden_effect_missing"))
            continue
        if effects and not set(effects).intersection(review.effects):
            if review.adapter is None or review.risk == "unknown":
                evaluations.append(
                    result(
                        rule,
                        "inconclusive",
                        "assurance.effect_evidence_missing",
                        unknowns=("Core did not establish the requested effect coverage.",),
                    )
                )
            else:
                evaluations.append(result(rule, "satisfied", "assurance.effect_not_applicable"))
            continue
        matched = tuple("effect:" + effect for effect in effects if effect in review.effects)
        if selectors.resource_ref is not None:
            asset = assets[selectors.resource_ref]
            if asset.kind not in {"path", "policy"}:
                evaluations.append(
                    result(rule, "unsupported", "assurance.resource_identity_unmodeled")
                )
                continue
            paths = [resource for resource in review.resources if resource.type == "path"]
            if not paths:
                evaluations.append(
                    result(
                        rule,
                        "inconclusive",
                        "assurance.resource_evidence_missing",
                        unknowns=("The reviewed action has no established path resource.",),
                    )
                )
                continue
            if any(
                not _safe_path(path.value) or posixpath.normpath(path.value) != path.value
                for path in paths
            ):
                evaluations.append(result(rule, "unsupported", "assurance.resource_alias_unproven"))
                continue
            matchers: tuple[PolicyResourceMatcher, ...] = (
                PolicyResourceMatcher("path", asset.value),
            )
            if asset.match == "prefix":
                matchers += (
                    PolicyResourceMatcher("path", asset.value.rstrip("/") + "/", "prefix"),
                )
            if not any(matcher.matches(path) for matcher in matchers for path in paths):
                evaluations.append(result(rule, "satisfied", "assurance.resource_not_applicable"))
                continue
            matched += ("asset:" + asset.id,)
            if len(paths) > 1 and rule.kind in {
                "forbid_effect",
                "protected_policy_mutation",
                "require_approval",
            }:
                evaluations.append(
                    result(
                        rule,
                        "inconclusive",
                        "assurance.effect_resource_binding_ambiguous",
                        matched=matched,
                        unknowns=(
                            "Multiple resources do not establish which object receives the effect.",
                        ),
                    )
                )
                continue
        if rule.kind in {"forbid_effect", "protected_policy_mutation"}:
            if rule.authority_ref is not None:
                evaluations.append(
                    result(
                        rule,
                        "unsupported",
                        "assurance.effect_authority_scope_unmodeled",
                        matched=matched,
                    )
                )
            else:
                evaluations.append(
                    result(
                        rule, "violated", "assurance.protected_effect_forbidden", matched=matched
                    )
                )
        elif rule.kind == "require_approval":
            # Contract-specific receipts may constrain more than action bytes.
            current_contract = runtime_contract()
            approval = next(
                (
                    receipt
                    for receipt in host_context.approvals
                    if receipt.action_digest == action_hash
                    and receipt.profile_digest == policy_hash
                    and receipt.contract_id in {None, current_contract.contract_id}
                ),
                None,
            )
            evaluations.append(
                result(
                    rule,
                    "satisfied" if approval else "violated",
                    "assurance.host_approval_present"
                    if approval
                    else "assurance.host_approval_required",
                    matched=matched,
                )
            )
        elif rule.kind in {"resource_subset", "credential_binding"}:
            authority = next(
                (
                    item
                    for item in host_context.capability_authorities
                    if item.authority_id == rule.authority_ref
                ),
                None,
            )
            if authority is None:
                evaluations.append(
                    result(
                        rule,
                        "inconclusive",
                        "assurance.capability_authority_missing",
                        matched=matched,
                    )
                )
                continue
            current_contract = runtime_contract()
            check = verify_assurance_capability(current_contract, authority.boundary)
            if rule.kind == "credential_binding" and not current_contract.credentials:
                evaluations.append(
                    result(
                        rule,
                        "inconclusive",
                        "assurance.credential_binding_missing",
                        matched=matched,
                    )
                )
                continue
            if rule.kind == "credential_binding":
                destinations = {(item.host, item.port) for item in current_contract.network}
                if not destinations or any(
                    host is None or port is None for host, port in destinations
                ):
                    evaluations.append(
                        result(
                            rule,
                            "inconclusive",
                            "assurance.credential_destination_unproven",
                            matched=matched,
                        )
                    )
                    continue
                if any(
                    (item.host, item.port) not in destinations
                    for item in current_contract.credentials
                ):
                    evaluations.append(
                        result(
                            rule,
                            "violated",
                            "assurance.credential_destination_mismatch",
                            matched=matched,
                        )
                    )
                    continue
                # This invariant asks about independent credential routing,
                # not full filesystem/process/protocol authorization. Reuse
                # the existing verifier for that explicitly isolated domain;
                # never return this projection as an execution contract.
                credential_question = replace(
                    current_contract,
                    filesystem=(),
                    network=(),
                    tools=(),
                    process=ProcessCapability(False, (), False),
                    privilege=PrivilegeCapability(False),
                    unknowns=tuple(
                        item
                        for item in current_contract.unknowns
                        if item.domain in {"credential", "semantics"}
                    ),
                    contract_id="",
                )
                credential_maximum = RuntimeCapabilityBoundary(
                    "credential-domain", credentials=authority.boundary.credentials
                )
                check = verify_runtime_capability(credential_question, credential_maximum)
            status = {
                "within_boundary": "satisfied",
                "exceeds_boundary": "violated",
                "unsupported": "unsupported",
                "inconclusive": "inconclusive",
            }[check.result]
            evaluations.append(
                result(
                    rule,
                    status,
                    "assurance.credential_binding_" + status
                    if rule.kind == "credential_binding"
                    else check.reason_code,
                    matched=matched,
                    unknowns=tuple(check.unsupported_fields)[:32],
                )
            )
        elif rule.kind == "network_request_subset":
            request_authority = next(
                (
                    item
                    for item in host_context.request_authorities
                    if item.authority_id == rule.authority_ref
                ),
                None,
            )
            if request_authority is None:
                evaluations.append(
                    result(
                        rule, "inconclusive", "assurance.request_authority_missing", matched=matched
                    )
                )
                continue
            try:
                request = derive_runtime_request_contract_v2(review)
                request = replace(request, capability=runtime_contract(), request_contract_id="")
                request_check = verify_assurance_request_authority(
                    request, request_authority.boundary
                )
                status = {
                    "within_boundary": "satisfied",
                    "exceeds_boundary": "violated",
                    "unsupported": "unsupported",
                    "inconclusive": "inconclusive",
                }[request_check.result]
                evaluations.append(
                    result(
                        rule,
                        status,
                        request_check.reason_code,
                        matched=matched,
                        unknowns=tuple(request_check.unsupported_fields)[:32],
                    )
                )
            except ValueError:
                evaluations.append(
                    result(
                        rule,
                        "unsupported",
                        "assurance.request_binding_unsupported",
                        matched=matched,
                    )
                )
        elif rule.kind == "temporal_action_guard":
            if rule.authority_ref is None:
                evaluations.append(
                    result(rule, "unsupported", "assurance.temporal_category_missing")
                )
            elif rule.authority_ref in review.trajectory_categories:
                evaluations.append(
                    result(
                        rule,
                        "violated",
                        "assurance.temporal_guard_violated",
                        matched=matched + ("trajectory:" + rule.authority_ref,),
                    )
                )
            elif history is None or host_context.history_digest != core_digest(history.as_dict()):
                evaluations.append(
                    result(
                        rule, "inconclusive", "assurance.history_coverage_unproven", matched=matched
                    )
                )
            else:
                evaluations.append(
                    result(rule, "satisfied", "assurance.temporal_guard_satisfied", matched=matched)
                )
        elif rule.kind in {"source_flow_guard", "delegated_authority_subset"}:
            assessment = next(
                (
                    item
                    for item in host_context.assessments
                    if item.invariant_id == rule.invariant_id
                    and item.kind == rule.kind
                    and item.action_digest == action_hash
                    and item.profile_digest == policy_hash
                    and item.contract_id in {None, runtime_contract().contract_id}
                ),
                None,
            )
            if assessment is None:
                evaluations.append(
                    result(
                        rule,
                        "inconclusive",
                        "assurance.host_assessment_missing",
                        matched=matched,
                        unknowns=(
                            "Authenticated causal-flow or current delegation verification is absent.",
                        ),
                    )
                )
            else:
                evaluations.append(
                    result(
                        rule,
                        assessment.status,
                        "assurance.host_assessment_" + assessment.status,
                        matched=matched,
                        unknowns=assessment.proof_gaps,
                    )
                )
        else:
            evaluations.append(result(rule, "unsupported", "assurance.invariant_kind_unsupported"))
    return tuple(evaluations)
