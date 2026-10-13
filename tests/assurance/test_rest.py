"""Host-selected REST semantics and exact request scope; never a network call."""

from dataclasses import replace
import json

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import (
    AssuranceGate,
    HostRequestAuthority,
    InvariantSelectors,
    SecurityInvariant,
    RestSemantics,
    RestRequestAuthority,
    RestRequestBoundary,
    RestRequestContract,
    derive_rest_request_contract,
    verify_rest_request_authority,
)
from ordin.assurance.simulation import SimulationPolicy
from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.runtime_contract import (
    ProcessCapability,
    NetworkCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_requests_v2 import (
    derive_runtime_request_contract_v2,
    verify_runtime_request_authority,
)
from ordin.session import configuration_digest

from .test_invariants import setup_gate

GET = ActionEnvelope(
    "network",
    "http.request",
    {"url": "https://fixture.invalid/docs", "method": "GET"},
    action_id="rest-get",
)


def configured(tmp_path, action=GET):
    baseline = AgentGate(Ordin(rest_semantics=RestSemantics()))
    rule = SecurityInvariant(
        "rest-exact",
        "network_request_subset",
        InvariantSelectors(),
        authority_ref="request",
        on_violation="block",
    )
    approved, source, gate = setup_gate(tmp_path, rule, baseline=baseline)
    contract = derive_rest_request_contract(baseline.evaluate_action(action).review)
    maximum = RestRequestBoundary(
        RuntimeCapabilityBoundary("rest-max", network=contract.capability.network),
        (contract.request,),
    )
    context = source.context(request_authorities=(HostRequestAuthority("request", maximum),))
    return approved, source, gate, contract, maximum, context


def test_default_unsupported_and_host_selection_are_distinct():
    default = AgentGate()
    assert default.evaluate_action(GET).requires_approval
    with pytest.raises(ValueError):
        Ordin(rest_semantics={"enabled": True})
    selected = AgentGate(Ordin(rest_semantics=RestSemantics()))
    assert selected.evaluate_action(GET).may_execute
    assert default.evaluate_action(GET).requires_approval
    assert configuration_digest(default) != configuration_digest(selected)
    for action in (ActionEnvelope.shell("rm -rf /"), ActionEnvelope.shell("git status --short")):
        assert (
            selected.evaluate_action(action).review.as_dict()
            == default.evaluate_action(action).review.as_dict()
        )


def test_approved_get_and_unknown_maximum_refuse_without_transport(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("REST review used a network or process transport")

    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    _, source, gate, contract, maximum, context = configured(tmp_path)
    assert verify_rest_request_authority(contract, maximum).ok
    result = gate.evaluate_action(GET, host_context=context)
    assert result.may_execute and result.invariant_evaluations[0].status == "satisfied"
    missing = gate.evaluate_action(GET, host_context=source.context())
    assert not missing.may_execute and missing.invariant_evaluations[0].status == "inconclusive"
    with pytest.raises(ValueError):
        type(context).from_dict(context.as_dict())


@pytest.mark.parametrize(
    "change",
    [
        {"method": "DELETE"},
        {"url": "https://fixture.invalid/admin"},
        {"url": "http://fixture.invalid:443/docs"},
        {"body": {"operation": "delete"}},
        {"body": None},
        {"headers": {"X-Request": "different"}},
    ],
)
def test_method_path_scheme_headers_or_body_cannot_reuse_get(tmp_path, change):
    _, _, gate, _, _, context = configured(tmp_path)
    initial = gate.evaluate_action(GET, host_context=context)
    changed = replace(GET, parameters={**GET.parameters, **change})
    result = gate.evaluate_action(changed, host_context=context)
    assert not result.may_execute
    assert result.invariant_evaluations[0].status in {"violated", "unsupported"}
    assert not gate.binding_matches(initial, changed, host_context=context)


def test_json_body_values_types_and_header_case_are_exact():
    parameters = {
        "url": "https://fixture.invalid/api",
        "method": "POST",
        "headers": {"Content-Type": "application/json", "X-Value": "a"},
        "body": {"count": 1, "name": "fixture"},
    }
    original = RestRequestAuthority.from_parameters(parameters)
    reordered = RestRequestAuthority.from_parameters(
        {
            **parameters,
            "headers": {"x-value": "a", "content-type": "application/json"},
            "body": {"name": "fixture", "count": 1},
        }
    )
    assert original == reordered
    for body in (
        {"count": 2, "name": "fixture"},
        {"count": "1", "name": "fixture"},
        {"count": True, "name": "fixture"},
    ):
        assert (
            RestRequestAuthority.from_parameters({**parameters, "body": body}).commitment
            != original.commitment
        )
    with pytest.raises(ValueError):
        RestRequestAuthority.from_parameters(
            {**parameters, "headers": {"x-value": "a", "X-Value": "a"}}
        )


def test_material_post_body_change_fails_after_network_scope_matches(tmp_path):
    post = ActionEnvelope(
        "network",
        "http.request",
        {
            "url": "https://fixture.invalid/api",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": {"operation": "read", "count": 1},
        },
        action_id="rest-post",
    )
    _, _, gate, contract, maximum, context = configured(tmp_path, post)
    assert verify_rest_request_authority(contract, maximum).ok
    original = gate.evaluate_action(post, host_context=context)
    assert original.requires_approval and original.invariant_evaluations[0].status == "satisfied"
    changed = replace(
        post, parameters={**post.parameters, "body": {"operation": "delete", "count": 1}}
    )
    review = gate.baseline_gate.evaluate_action(changed).review
    candidate = derive_rest_request_contract(review)
    assert candidate.capability.network == contract.capability.network
    checked = verify_rest_request_authority(candidate, maximum)
    assert not checked.ok and checked.reason_code == "assurance.rest_request_commitment_exceeds"
    result = gate.evaluate_action(changed, host_context=context)
    assert result.denied and not gate.binding_matches(original, changed, host_context=context)


@pytest.mark.parametrize(
    "parameters",
    [
        {"url": "https://user:secret@fixture.invalid/docs", "method": "GET"},
        {"url": "https://fixture.invalid/%2e%2e/docs", "method": "GET"},
        {"url": "https://fixture.invalid/docs?operation=delete", "method": "GET"},
        {"url": "https://fixture.invalid/docs?", "method": "GET"},
        {"url": "https://fixture.invalid/docs#", "method": "GET"},
        {"url": "https://fixture.invalid/docs", "method": "get"},
        {"url": "https://fixture.invalid/docs", "method": "TRACE"},
        {
            "url": "https://fixture.invalid/docs",
            "method": "GET",
            "headers": {"Host": "other.invalid"},
        },
        {
            "url": "https://fixture.invalid/docs",
            "method": "GET",
            "headers": {"Authorization": "private"},
        },
        {
            "url": "https://fixture.invalid/docs",
            "method": "GET",
            "headers": {"Connection": "upgrade"},
        },
        {"url": "https://fixture.invalid/docs", "method": "GET", "approved": True},
    ],
)
def test_unmodeled_request_fields_are_not_classified_or_committed(parameters):
    action = ActionEnvelope("network", "http.request", parameters)
    result = AgentGate(Ordin(rest_semantics=RestSemantics())).evaluate_action(action)
    assert result.requires_approval and result.review.adapter is None
    with pytest.raises(ValueError):
        RestRequestAuthority.from_parameters(parameters)


def test_legacy_capability_and_v2_do_not_ignore_rest_binding_requirement(tmp_path):
    _, _, gate, contract, maximum, _ = configured(tmp_path)
    assert not verify_runtime_capability(contract.capability, maximum.capability).ok
    v2 = derive_runtime_request_contract_v2(gate.baseline_gate.evaluate_action(GET).review)
    with pytest.raises(ValueError):
        verify_runtime_request_authority(v2, maximum)
    from ordin.runtime_requests_v2 import RuntimeRequestBoundaryV2

    assert not verify_runtime_request_authority(
        v2, RuntimeRequestBoundaryV2(maximum.capability, ())
    ).ok


def test_rest_composite_accounts_for_every_other_capability_domain(tmp_path):
    _, _, _, contract, maximum, _ = configured(tmp_path)
    expanded = replace(
        contract.capability,
        process=ProcessCapability(True, ("/synthetic/unapproved",)),
        contract_id="",
    )
    proposal = RestRequestContract(expanded, contract.request)
    result = verify_rest_request_authority(proposal, maximum)
    assert not result.ok and not result.coverage["process"]
    from ordin.runtime_contract import CapabilityUnknown

    unknown = replace(
        contract.capability,
        unknowns=contract.capability.unknowns
        + (
            CapabilityUnknown(
                "privilege", "fixture_unknown_privilege", "Explicit unmodeled rights."
            ),
        ),
        contract_id="",
    )
    assert not verify_rest_request_authority(
        RestRequestContract(unknown, contract.request), maximum
    ).ok


def test_rest_declarations_roundtrip_but_do_not_claim_backend_authority(tmp_path):
    _, _, _, contract, maximum, _ = configured(tmp_path)
    assert (
        RestRequestAuthority.from_json(json.dumps(contract.request.as_dict())) == contract.request
    )
    assert RestRequestContract.from_dict(contract.as_dict()) == contract
    assert RestRequestBoundary.from_dict(maximum.as_dict()) == maximum
    assert contract.capability.grant_state == "diagnostic"
    redacted = json.dumps(contract.as_dict())
    assert "https://fixture.invalid" not in redacted
    with pytest.raises(ValueError):
        RestRequestContract.from_dict({**contract.as_dict(), "approved": True})
    for source in (
        {**contract.capability.source, "kind": "shell"},
        {**contract.capability.source, "operation": "execute"},
        {**contract.capability.source, "effects": ["network.upload"]},
    ):
        with pytest.raises(ValueError):
            RestRequestContract(
                replace(contract.capability, source=source, contract_id=""), contract.request
            )


def test_rest_semantics_snapshot_changes_session_binding_and_replay():
    default = SimulationPolicy()
    selected = SimulationPolicy(Ordin(rest_semantics=RestSemantics(("GET",))))
    assert selected.build_gate().baseline_gate.ordin.rest_semantics == RestSemantics(("GET",))
    assert selected.digest != default.digest
    assert selected.build_gate().baseline_gate.evaluate_action(GET).may_execute
    limited = AgentGate(Ordin(rest_semantics=RestSemantics(("HEAD",))))
    assert limited.evaluate_action(GET).requires_approval


def test_changed_semantic_selection_cannot_reuse_a_review(tmp_path):
    _, _, gate, _, _, context = configured(tmp_path)
    original = gate.evaluate_action(GET, host_context=context)
    other = AssuranceGate(
        AgentGate(Ordin(rest_semantics=RestSemantics(("HEAD",)))), gate.approved_profile
    )
    assert not other.binding_matches(original, GET, host_context=context)
    assert not other.evaluate_action(GET, host_context=context).may_execute


def test_packaged_rest_example_is_inert_and_explains_exact_scope(monkeypatch):
    from ordin.assurance.rest_demo import run_demo

    def forbidden(*a, **k):
        raise AssertionError("REST example executed a process or network request")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    result = run_demo()
    assert (
        result["default_disposition"] == "escalate" and result["selected_disposition"] == "execute"
    )
    assert not result["actions_executed"] and not result["network_called"]
    assert all(
        r["disposition"] == "deny" and not r["old_binding_matches"] for r in result["changes"]
    )
    assert "https://fixture.invalid" not in json.dumps(result)
