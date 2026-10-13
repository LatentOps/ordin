"""Owned synthetic REST approval/binding example; no request is sent."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path
import tempfile

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_observation import RuntimeEvidenceSource

from .models import RepositoryScope, SecurityProfile, SecurityInvariant, InvariantSelectors
from .profiles import ProtectedProfileSelection, load_approved_profile
from .host import HostEvidenceSource, HostRequestAuthority
from .gate import AssuranceGate
from .rest import RestSemantics, RestRequestBoundary, derive_rest_request_contract


def run_demo():
    repository = RepositoryScope("fixture/rest-example", "snapshot-1")
    profile = SecurityProfile(
        "rest-example",
        "1",
        repository,
        invariants=(
            SecurityInvariant(
                "exact-rest",
                "network_request_subset",
                InvariantSelectors(),
                authority_ref="rest-maximum",
                on_violation="block",
            ),
        ),
    )
    policy = "a" * 64
    with tempfile.TemporaryDirectory(prefix="ordin-rest-example-") as name:
        directory = Path(name).resolve(strict=True)
        directory.chmod(0o700)
        path = directory / "profile.json"
        path.write_text(json.dumps(profile.as_dict()), encoding="utf-8")
        path.chmod(0o600)
        selection = ProtectedProfileSelection(
            directory.resolve(),
            "profile.json",
            "/operator/rest-profile.json",
            repository,
            profile.digest,
            hashlib.sha256(path.read_bytes()).hexdigest(),
            "1",
            "fixture-operator",
            RuntimeCapabilityBoundary(
                "synthetic-agent",
                filesystem=(FilesystemCapability("read", "/synthetic", "prefix"),),
                filesystem_semantics="lexical_prefix",
                runtime_filesystem_guarantees=True,
            ),
            RuntimeEvidenceSource("fixture", "b" * 64, "synthetic-sandbox", policy),
        )
        approved = load_approved_profile(
            selection, current_repository=repository, active_runtime_policy_digest=policy
        )
        source = HostEvidenceSource(
            "fixture-agent", repository, "b" * 64, 1, policy, selection.digest
        )
        baseline = AgentGate(Ordin(rest_semantics=RestSemantics()))
        gate = AssuranceGate(baseline, approved)
        action = ActionEnvelope(
            "network",
            "http.request",
            {
                "url": "https://fixture.invalid/docs",
                "method": "GET",
            },
            action_id="rest-read",
        )
        contract = derive_rest_request_contract(baseline.evaluate_action(action).review)
        maximum = RestRequestBoundary(
            RuntimeCapabilityBoundary("rest-example-max", network=contract.capability.network),
            (contract.request,),
        )
        context = source.context(
            request_authorities=(HostRequestAuthority("rest-maximum", maximum),)
        )
        reviewed = gate.evaluate_action(action, host_context=context)
        changes = []
        for altered in (
            {"method": "DELETE"},
            {"url": "https://fixture.invalid/admin"},
            {"body": {"operation": "delete"}},
        ):
            proposal = replace(action, parameters={**action.parameters, **altered})
            result = gate.evaluate_action(proposal, host_context=context)
            changes.append(
                {
                    "changed_fields": list(altered),
                    "disposition": result.disposition,
                    "invariant_status": result.invariant_evaluations[0].status,
                    "old_binding_matches": gate.binding_matches(
                        reviewed, proposal, host_context=context
                    ),
                }
            )
        return {
            "schema_version": "ordin.assurance_rest_example.v1",
            "synthetic_only": True,
            "actions_executed": False,
            "network_called": False,
            "profile_installed": False,
            "default_disposition": AgentGate().evaluate_action(action).disposition,
            "selected_disposition": reviewed.disposition,
            "request_digest": contract.request.digest,
            "changes": changes,
            "limitations": [
                "Owned synthetic protected host declarations, not physical transport/backend enforcement.",
                "Query/encoded URI forms, raw HTTP bytes and ambient credentials remain unsupported.",
            ],
        }


def main():
    print(json.dumps(run_demo(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
