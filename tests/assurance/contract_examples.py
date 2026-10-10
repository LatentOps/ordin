"""Canonical executable-constructor examples for every additive Assurance schema."""

from pathlib import Path

from ordin import ActionEnvelope
from ordin.assurance import (
    AssuranceGate,
    AuthorizedRepository,
    HostEvidenceSource,
    RepositoryScope,
    build_threat_model,
    compile_approved_profile,
    inventory_repository,
)
from ordin.runtime_contract import CredentialBinding
from ordin.assurance.challenge import challenge_authority_subset
from ordin.assurance.property_challenge import challenge_security_properties
from ordin.assurance.delegation import (
    DelegationAuthority,
    DelegationIssuer,
    verify_delegation_subset,
)
from ordin.assurance.delegating_gate import DelegatingAssuranceGate
from ordin.assurance.codex_security import import_codex_json
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.assurance.origins import (
    register_instruction_origin,
    correlate_source_use,
    record_source_provenance,
)

from .test_models import examples
from .test_profiles import POLICY_HASH, REPO, approve, config_profile, selected


def assurance_contract_examples(tmp_path):
    samples = {record.SCHEMA: record.as_dict() for record in examples()}
    from .test_codex_import import bundle

    scan_directory = tmp_path / "scan-import-fixture"
    scan_directory.mkdir()
    scan_scope, _, _, _ = bundle(scan_directory)
    imported_scan = import_codex_json(scan_scope)
    samples["assurance_scan_import"] = imported_scan.as_dict()
    samples["assurance_imported_finding"] = imported_scan.findings[0].as_dict()
    scope = AuthorizedRepository(
        (Path(__file__).parent / "fixtures/repositories/payment").resolve(),
        RepositoryScope("fixture/payment", "fixture-v1"),
        "/fixture/payment",
    )
    inventory = inventory_repository(scope)
    model = build_threat_model(scope, inventory)
    approved = approve(selected(tmp_path, config_profile()))
    source = HostEvidenceSource(
        "fixture-agent", REPO, "b" * 64, 1, POLICY_HASH, approved.selection_digest
    )
    action = ActionEnvelope.shell("git status --short", action_id="contract-fixture")
    approval = source.record_approval(action, approved, receipt_id="fixture-approved")
    assessment = source.record_assessment(
        action,
        approved,
        assessment_id="fixture-assessment",
        invariant_id="fixture-flow",
        kind="source_flow_guard",
        status="inconclusive",
        proof_gaps=("Synthetic fixture has no causal-flow observation.",),
    )
    routing = source.record_credential_use(
        action,
        approved,
        receipt_id="fixture-route",
        binding=CredentialBinding("opaque-ref", "fixture.invalid", 443),
    )
    host = source.context(
        approvals=(approval,), assessments=(assessment,), credential_uses=(routing,)
    )
    decision = AssuranceGate(approved_profile=approved).evaluate_action(action, host_context=host)
    maximum = DelegationAuthority(RuntimeCapabilityBoundary("fixture"))
    issuer = DelegationIssuer(source, approved, maximum, maximum, clock=lambda: 100)
    grant = issuer.authorize_root(maximum, grant_id="fixture-root", expires_at=200)
    delegated = DelegatingAssuranceGate(
        AssuranceGate(approved_profile=approved), issuer, grant, source
    ).evaluate_action(action)
    origin = register_instruction_origin(
        source,
        origin_id="fixture-origin",
        kind="authorized_user",
        classification="public",
        content="git status --short",
    )
    use = correlate_source_use(
        source,
        origin,
        action,
        use_id="fixture-use",
        argument_path=("parameters", "command"),
        usage="instruction_context",
    )
    samples.update(
        {
            "assurance_repository_inventory": inventory.as_dict(),
            "assurance_repository_threat_model": model.as_dict(),
            "assurance_profile_compilation": compile_approved_profile(approved).as_dict(),
            "assurance_host_approval": approval.as_dict(),
            "assurance_host_assessment": assessment.as_dict(),
            "assurance_host_credential_use": routing.as_dict(),
            "assurance_host_context": host.as_dict(),
            "assurance_decision": decision.as_dict(),
            "assurance_delegated_decision": delegated.as_dict(),
            "assurance_delegation_verification": verify_delegation_subset(
                *([DelegationAuthority(RuntimeCapabilityBoundary("fixture"))] * 4)
            ).as_dict(),
            "assurance_instruction_origin": origin.as_dict(),
            "assurance_source_use": use.as_dict(),
            "assurance_source_provenance": record_source_provenance(
                source, action, origins=(origin,), uses=(use,)
            ).as_dict(),
            "assurance_challenge_suite": challenge_security_properties(
                seed=14, revision="fixture-v1", trials_per_property=1, properties=("trust_origin",)
            ).as_dict(),
            "assurance_challenge_run": challenge_authority_subset(
                seed=14, revision="fixture-v1", trials=2
            ).as_dict(),
        }
    )
    return samples
