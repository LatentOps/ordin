"""Initial host-credential correlation uses original review proof, without effects."""

from dataclasses import replace

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import (
    AssuranceGate,
    DelegatingAssuranceGate,
    DelegationAuthority,
    DelegationIssuer,
    HostEvidenceSource,
    RestSemantics,
)
from ordin.assurance.delegating_gate import _ChildSessionGate
from ordin.assurance.host import HostCredentialUse
from ordin.assurance.rest import derive_rest_request_contract
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import CredentialBinding, derive_runtime_capability_contract
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin.session import IntegrationSession, SessionIdentity

from .test_profiles import REPO, POLICY_HASH, approve, selected, config_profile


def configured(tmp_path):
    profile = approve(selected(tmp_path, config_profile()))
    core = Ordin(rest_semantics=RestSemantics())
    action = ActionEnvelope(
        "network",
        "http.request",
        {"url": "https://fixture.invalid/docs", "method": "GET"},
        action_id="credential-review",
    )
    complete = derive_rest_request_contract(core.review_action(action))
    credential = CredentialBinding("private-route", "fixture.invalid", 443)
    authority = DelegationAuthority(
        RuntimeCapabilityBoundary(
            "credential-maximum", network=complete.capability.network, credentials=(credential,)
        ),
        rest_requests=(complete.request,),
    )
    identity = SessionIdentity("credential-child", "original-session")
    planned = IntegrationSession(identity, AgentGate(core))
    parent = HostEvidenceSource("parent", REPO, "a" * 64, 0, POLICY_HASH, profile.selection_digest)
    source = replace(parent, principal="child", session_digest=planned.runtime_session_digest)
    clock = [100]
    issuer = DelegationIssuer(parent, profile, authority, authority, clock=lambda: clock[0])
    root = issuer.authorize_root(authority, grant_id="root", expires_at=200)
    child = issuer.issue_child(root, source, authority, grant_id="child", expires_at=150)
    gate = DelegatingAssuranceGate(
        AssuranceGate(AgentGate(core), profile), issuer, child, source, identity=identity
    )
    collector = RuntimeEvidenceSource(
        "credential-collector", source.session_digest, "sandbox", POLICY_HASH
    )
    gate.bind_runtime_source(collector)
    use = source.record_credential_use(
        action, profile, receipt_id="original-use", binding=credential
    )
    context = source.context(credential_uses=(use,))
    return gate, issuer, root, source, collector, action, credential, use, context, clock


def observation(collector, contract, identifier="actual-original"):
    return collector.observe(
        contract,
        observation_id=identifier,
        trust="backend_observed",
        enforcement_point="network",
        outcome="completed",
        operation="network.http.request",
        effects=("network.request",),
    )


def test_initial_session_retains_original_credential_contract_and_rest_unknown(tmp_path):
    gate, _, _, _, collector, action, credential, _, context, _ = configured(tmp_path)
    result = gate.evaluate_action(action, host_context=context)
    assert result.may_execute
    baseline = derive_runtime_capability_contract(result.assurance.review)
    expected = replace(baseline, credentials=(credential,), contract_id="")
    full = derive_rest_request_contract(result.assurance.review, capability=expected)
    assert result.contract_digest == full.digest
    retained = gate._session.runtime_contract(action.action_id)
    assert retained == expected and retained.unknowns == baseline.unknowns
    assert retained.grant_state == "diagnostic" and baseline.credentials == ()
    before = gate._session.runtime_snapshot()
    assert gate.commit_use(result, result.assurance.review.action)
    actual = observation(collector, full.capability)
    gate.observe_runtime(actual)
    after = gate._session.runtime_snapshot()
    assert after["history"]["contracts"] == before["history"]["contracts"]
    assert after["history"]["observations"] == [actual.as_dict()]
    assert gate._session_runtime_binding is None and gate._captured == []


@pytest.mark.parametrize("change", ["missing", "destination", "extra", "action"])
def test_observation_for_a_different_credential_contract_still_fails(tmp_path, change):
    gate, _, _, _, collector, action, credential, _, context, _ = configured(tmp_path)
    result = gate.evaluate_action(action, host_context=context)
    original = gate._session.runtime_contract(action.action_id)
    changed = replace(
        original,
        credentials=()
        if change == "missing"
        else (replace(credential, host="other.invalid"),)
        if change == "destination"
        else (credential, CredentialBinding("extra", "fixture.invalid", 443)),
        contract_id="",
    )
    if change == "action":
        changed = replace(original, action_id="other-action", contract_id="")
    before = gate._session.runtime_snapshot()
    with pytest.raises(ValueError, match="mismatch"):
        gate.observe_runtime(observation(collector, changed))
    assert gate._session.runtime_snapshot() == before
    assert gate.commit_use(result, result.assurance.review.action)


@pytest.mark.parametrize("mode", ["expired", "revoked"])
def test_invalid_grant_still_retains_a_denied_proposal_without_credentials(tmp_path, mode):
    gate, issuer, root, _, _, action, _, _, context, clock = configured(tmp_path)
    if mode == "expired":
        clock[0] = 150
    else:
        issuer.revoke(root)
    denied = gate.evaluate_action(action, host_context=context)
    assert denied.denied and not denied.may_execute
    assert gate.snapshot()["denied_action_ids"] == [action.action_id]
    assert gate._session.runtime_contract(action.action_id).credentials == ()
    assert gate._session_runtime_binding is None and gate._captured == []


def test_receipt_json_and_foreign_scope_never_activate_host_correlation(tmp_path):
    gate, _, _, source, _, action, _, use, _, _ = configured(tmp_path)
    with pytest.raises(ValueError, match="protected host channel"):
        HostCredentialUse.from_dict(use.as_dict())
    foreign = replace(source, principal="foreign")
    receipt = foreign.record_credential_use(
        action,
        gate.issuer.profile,
        receipt_id="foreign",
        binding=CredentialBinding("private-route", "fixture.invalid", 443),
    )
    with pytest.raises(ValueError, match="another host scope"):
        source.context(credential_uses=(receipt,))
    assert gate.snapshot()["history"]["actions"] == []


def test_copied_decision_is_rejected_before_history_append_and_capture_is_cleared(
    tmp_path, monkeypatch
):
    gate, _, _, _, _, action, _, _, context, _ = configured(tmp_path)
    original_hook = _ChildSessionGate._runtime_credential_bindings

    def copied(self, decision):
        return original_hook(self, replace(decision))

    before = gate._session.runtime_snapshot()
    pending = dict(gate.issuer._pending)
    with monkeypatch.context() as patch:
        patch.setattr(_ChildSessionGate, "_runtime_credential_bindings", copied)
        with pytest.raises(ValueError, match="original immediate"):
            gate.evaluate_action(action, host_context=context)
    assert gate._session.runtime_snapshot() == before
    assert gate.snapshot()["history"]["actions"] == []
    assert gate._session_runtime_binding is None and gate._captured == []
    assert gate.issuer._pending == pending and gate._issued_inputs == {}
    # A rejected review never forwarded and retains no unusable pending ticket.
    assert gate.evaluate_action(action, host_context=context).may_execute


def test_altered_receipt_cached_digest_does_not_activate_correlation(tmp_path, monkeypatch):
    gate, _, _, _, _, action, _, use, context, _ = configured(tmp_path)
    original_hook = _ChildSessionGate._runtime_credential_bindings
    original_host = use.host

    def altered(self, decision):
        # The receipt/context caches already exist. A fresh payload check must
        # reject the altered original object, rather than trusting that cache.
        object.__setattr__(use, "host", "changed.invalid")
        return original_hook(self, decision)

    before, pending = gate._session.runtime_snapshot(), dict(gate.issuer._pending)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(_ChildSessionGate, "_runtime_credential_bindings", altered)
            with pytest.raises(ValueError, match="sealed credential"):
                gate.evaluate_action(action, host_context=context)
    finally:
        object.__setattr__(use, "host", original_host)
    assert gate._session.runtime_snapshot() == before and gate._captured == []
    assert gate._session_runtime_binding is None and gate.issuer._pending == pending
    assert gate.evaluate_action(action, host_context=context).may_execute


def test_unrelated_action_receipt_is_not_added_to_initial_contract(tmp_path):
    gate, _, _, source, collector, action, credential, _, _, _ = configured(tmp_path)
    unrelated = replace(action, action_id="unrelated-action")
    use = source.record_credential_use(
        unrelated, gate.issuer.profile, receipt_id="other-action-use", binding=credential
    )
    result = gate.evaluate_action(action, host_context=source.context(credential_uses=(use,)))
    assert result.may_execute
    retained = gate._session.runtime_contract(action.action_id)
    assert retained.credentials == ()
    incorrect = replace(retained, credentials=(credential,), contract_id="")
    with pytest.raises(ValueError, match="contract_mismatch"):
        gate.observe_runtime(observation(collector, incorrect))
