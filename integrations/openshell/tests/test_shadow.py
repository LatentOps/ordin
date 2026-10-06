import json
from dataclasses import replace

import pytest

from ordin import ActionEnvelope, Ordin
from ordin.enforcement_backend import CompilationResult
from ordin.execution import ObservedResource
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import derive_runtime_capability_contract
from ordin.schema import validate_named_schema
from ordin_openshell.compiler import OpenShellBackend
from ordin_openshell.shadow import ShadowCase, ShadowReport, build_shadow_report
from test_compiler import supported_contract
from test_observations import source_context


def boundary_for(contract):
    return RuntimeCapabilityBoundary(
        "fixture",
        filesystem=contract.filesystem,
        network=contract.network,
        process=contract.process,
        privilege=contract.privilege,
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )


def event_for(contract, *, method="GET", outcome="allowed", event_id="event-1", binary=True):
    source = source_context()
    metadata = {
        "host": "api.github.com",
        "port": 443,
        "method": method,
        "path": "/repos/LatentOps/ordin/issues/37",
        "event_digest": "c" * 64,
    }
    if binary:
        metadata["binary"] = "/usr/bin/curl"
    return source.observe(
        contract,
        observation_id=event_id,
        trust="backend_enforced" if outcome == "denied" else "backend_observed",
        enforcement_point="network",
        operation="http.request",
        outcome=outcome,
        effects=("network.download" if method == "GET" else "network.upload",),
        resources=(ObservedResource("host", "api.github.com"),),
        reason_code="policy_denied" if outcome == "denied" else "observed",
        metadata=metadata,
    )


def evaluate(contract=None, observations=(), boundary=None, backend=None):
    contract = contract or supported_contract()
    case = ShadowCase(
        contract,
        boundary or boundary_for(contract),
        tuple(observations),
        source_context(),
        backend or OpenShellBackend((1000, 1000), mode="shadow"),
    )
    return build_shadow_report((case,))


def test_shadow_compares_prediction_policy_and_observed_get_without_execution(monkeypatch):
    import socket
    import subprocess

    contract = supported_contract()

    def forbidden(*args, **kwargs):
        raise AssertionError("shadow evaluation performed runtime I/O")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    report = evaluate(contract, (event_for(contract),))
    assert report.metrics["contracts_fully_representable"] == 1
    assert report.metrics["runtime_events_correlated"] == 1
    assert report.metrics["would_deny_events"] == 0
    assert report.boundary_outcomes["within_boundary"] == 1
    assert report.actions[0]["events"][0]["prediction"] == "predicted"
    assert report.actions[0]["events"][0]["policy_match"] == "within_policy"
    assert report.actions[0]["review_decision"] == "allow"
    assert validate_named_schema("runtime_shadow_report", report.as_dict()) == []
    assert ShadowReport.from_dict(json.loads(json.dumps(report.as_dict()))).digest == report.digest
    assert evaluate(contract, (event_for(contract),)).as_dict() == report.as_dict()


def test_audited_delete_and_denied_post_expose_unpredicted_and_expected_denial():
    contract = supported_contract()
    observations = (
        event_for(contract, method="DELETE"),
        event_for(contract, method="POST", outcome="denied", event_id="event-2"),
    )
    report = evaluate(contract, observations)
    assert report.metrics["observed_but_unpredicted_capabilities"] == 2
    assert report.metrics["would_deny_events"] == 2
    assert "observed_but_not_predicted" in report.actions[0]["mismatches"]
    assert "runtime_denial_expected" in report.actions[0]["mismatches"]
    assert report.actions[0]["review_decision"] == "allow"


def test_allowed_projection_never_asserts_successful_runtime_execution():
    contract = supported_contract()
    report = evaluate(contract, (event_for(contract, outcome="denied"),))
    assert "runtime_denial_unexpected" in report.actions[0]["mismatches"]
    assert report.actions[0]["events"][0]["outcome"] == "denied"
    assert report.metrics["predicted_but_unused_capabilities"] > 0
    report = evaluate(contract, (event_for(contract, binary=False),))
    assert report.actions[0]["events"][0]["policy_match"] == "inconclusive"
    assert "runtime_event_inconclusive" in report.actions[0]["mismatches"]


def test_unrepresentable_contract_and_boundary_exceedance_remain_visible():
    contract = derive_runtime_capability_contract(
        Ordin().review_action(ActionEnvelope.shell("curl https://example.com", action_id="unknown"))
    )
    report = evaluate(contract)
    assert report.metrics["contracts_unsupported"] == 1
    assert report.actions[0]["unsupported_fields"]
    assert "unrepresentable_capability" in report.actions[0]["mismatches"]
    contract = supported_contract()
    report = evaluate(contract, boundary=replace(boundary_for(contract), network=()))
    assert report.boundary_outcomes["exceeds_boundary"] == 1
    assert report.actions[0]["boundary_result"] == "exceeds_boundary"


def test_widening_rejection_is_counted_without_providing_a_policy():
    contract = supported_contract()
    contract = replace(contract, contract_id="", filesystem=(contract.filesystem[0],))
    report = evaluate(contract)
    assert report.metrics["compiler_widening_failures"] == 1
    assert "compiler_widening_detected" in report.actions[0]["mismatches"]
    assert report.actions[0]["policy_digest"] is None


def test_changed_policy_is_detected_before_using_it_for_shadow_comparison():
    class DriftingBackend(OpenShellBackend):
        def compile(self, contract):
            result = super().compile(contract)
            if result.plan is None:
                return result
            policy = result.plan.as_dict()["policy"]
            next(iter(policy["network_policies"].values()))["endpoints"][0]["rules"][0]["allow"][
                "method"
            ] = "DELETE"
            return CompilationResult(
                "success", "openshell", "fixture", plan=replace(result.plan, policy=policy)
            )

    backend = DriftingBackend((1000, 1000), mode="shadow")
    report = evaluate(backend=backend)
    assert report.metrics["compiler_widening_failures"] == 1
    assert report.metrics["contracts_unsupported"] == 1
    assert report.actions[0]["compilation_status"] == "unsupported"
    assert report.actions[0]["policy_digest"] is None


def test_cross_session_and_duplicate_events_do_not_enter_prediction_metrics():
    contract = supported_contract()
    observation = event_for(contract)
    report = evaluate(contract, (observation, observation))
    assert report.metrics["runtime_events_correlated"] == 1
    assert report.metrics["correlation_mismatches"] == 1
    wrong_source = replace(source_context(), session_digest="d" * 64)
    case = ShadowCase(
        contract,
        boundary_for(contract),
        (observation,),
        wrong_source,
        OpenShellBackend((1000, 1000), mode="shadow"),
    )
    report = build_shadow_report((case,))
    assert report.metrics["runtime_events_correlated"] == 0
    assert report.metrics["correlation_mismatches"] == 1
    assert "action_correlation_mismatch" in report.actions[0]["mismatches"]


def test_report_omits_action_arguments_event_payload_and_resources_by_default():
    contract = supported_contract()
    packet = evaluate(contract, (event_for(contract),)).as_dict()
    text = json.dumps(packet)
    assert "api.github.com" not in text and "/usr/bin/curl" not in text
    assert "parameters" not in text and "command" not in text
    assert "action_id" not in text and "sandbox-abc123" not in text
    with pytest.raises(TypeError):
        evaluate().metrics["actions_reviewed"] = 0


def test_empty_report_is_valid_and_collection_bounds_reject_excess_input():
    empty = build_shadow_report(())
    assert sum(empty.metrics.values()) == 0
    assert validate_named_schema("runtime_shadow_report", empty.as_dict()) == []
    case = ShadowCase(supported_contract(), boundary_for(supported_contract()))
    with pytest.raises(ValueError, match="capacity"):
        build_shadow_report((case,) * 129)
    with pytest.raises(ValueError, match="duplicate"):
        build_shadow_report((case, case))
