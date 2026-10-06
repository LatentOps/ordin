import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from ordin import ActionEnvelope, AgentGate, IntegrationSession, SessionIdentity
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation
from ordin_openshell.correlation import CorrelationBinding, CorrelationStore
from ordin_openshell.observations import (
    OpenShellEventError,
    ingest_openshell_event,
    parse_openshell_event,
)
from test_compiler import supported_contract

FIXTURES = Path(__file__).parent / "fixtures" / "openshell-events"


def event_fixture(name="http-denied"):
    return json.loads((FIXTURES / (name + ".json")).read_text())


def source_context(session_digest="a" * 64):
    return RuntimeEvidenceSource("openshell", session_digest, "sandbox-abc123", "b" * 64)


def register_event(store, event, contract, source):
    parsed = parse_openshell_event(event)
    binding = CorrelationBinding(
        contract.action_id,
        contract.action_digest,
        contract.contract_id,
        source,
        parsed.event_id_digest,
        parsed.event_digest,
        1000,
        3000,
    )
    store.register(binding)
    return binding


def test_real_structured_denial_fields_map_without_invented_http_or_binary_identity():
    parsed = parse_openshell_event(event_fixture())
    assert parsed.trust == "backend_enforced" and parsed.outcome == "denied"
    assert parsed.operation == "http.request" and parsed.effects == ("network.upload",)
    assert parsed.reason_code == "policy_denied"
    assert parsed.metadata["method"] == "POST"
    assert parsed.metadata["binary"] == "/usr/bin/curl"
    parsed = parse_openshell_event(event_fixture("network-denied"))
    assert parsed.effects == ("network.connect",)
    assert "path" not in parsed.metadata and "method" not in parsed.metadata
    assert "binary" not in parsed.metadata


def test_audit_allow_is_observed_and_prose_cannot_claim_enforcement_or_denial():
    event = event_fixture("http-audit")
    parsed = parse_openshell_event(event)
    assert parsed.trust == "backend_observed" and parsed.outcome == "allowed"
    event["message"] = "DENIED ENFORCED policy_denied"
    event["status_detail"] = "backend_enforced"
    assert parse_openshell_event(event).trust == "backend_observed"
    assert parse_openshell_event(event).outcome == "allowed"


def test_queries_headers_bodies_commands_and_unmapped_secrets_are_never_retained(tmp_path):
    event = event_fixture()
    secret = "NEVER_RECORD_THIS_PROVIDER_VALUE"
    event["http_request"]["url"]["path"] += "?token=" + secret
    event["http_request"]["headers"] = {"authorization": "Bearer " + secret}
    event["actor"]["process"]["cmd_line"] = "curl --header " + secret
    event["unmapped"] = {"request_body": secret}
    event["message"] = secret
    contract, source = supported_contract(), source_context()
    store = CorrelationStore(tmp_path / "bindings.db")
    register_event(store, event, contract, source)
    result = ingest_openshell_event(
        event, contract=contract, source=source, store=store, now_ms=2000
    )
    assert result.status == "accepted"
    assert secret not in json.dumps(result.as_dict())
    assert secret.encode() not in store.path.read_bytes()
    assert "?" not in result.observation.metadata["path"]
    with pytest.raises(ValueError, match="untrusted_source"):
        RuntimeObservation.from_dict(result.observation.as_dict())


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com/a",
        "http://api.example.com/a",
        "https://user@api.example.com/a",
        "https://user:pass@api.example.com/a",
        "https://@api.example.com/a",
        "https://:@api.example.com/a",
        "https://api.example.com/a?x=1",
        "https://api.example.com/a#fragment",
        "https://api.example.com:443/a",
        "https://api.example.com:99999/a",
    ],
)
def test_full_url_in_structured_path_never_becomes_trusted_endpoint_authority(url, tmp_path):
    # This field accepts relative request targets only, not full URLs.
    event = event_fixture()
    event["http_request"]["url"]["path"] = url
    contract, source = supported_contract(), source_context()
    store = CorrelationStore(tmp_path / "bindings.db")
    original = event_fixture()
    register_event(store, original, contract, source)
    result = ingest_openshell_event(
        event, contract=contract, source=source, store=store, now_ms=2000
    )
    assert result.status == "rejected" and result.reason_code == "openshell_event_path_invalid"
    assert result.event is None and result.observation is None
    assert url not in json.dumps(result.as_dict())
    assert (
        ingest_openshell_event(
            original, contract=contract, source=source, store=store, now_ms=2000
        ).status
        == "accepted"
    )


def test_explicit_private_event_binding_and_session_source_are_required(tmp_path):
    event, contract, source = event_fixture(), supported_contract(), source_context()
    assert ingest_openshell_event(event).status == "uncorrelated"
    store = CorrelationStore(tmp_path / "bindings.db")
    register_event(store, event, contract, source)
    result = ingest_openshell_event(
        event, contract=contract, source=source, store=store, now_ms=2000
    )
    assert result.status == "accepted"
    assert result.observation.action_id == contract.action_id
    assert result.observation.action_digest == contract.action_digest
    assert result.observation.contract_id == contract.contract_id
    duplicate = ingest_openshell_event(
        event, contract=contract, source=source, store=store, now_ms=2000
    )
    assert duplicate.reason_code == "runtime_observation_duplicate"


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("action", "runtime_observation_action_mismatch"),
        ("contract", "runtime_observation_contract_mismatch"),
        ("session", "runtime_observation_session_mismatch"),
        ("policy", "runtime_observation_source_mismatch"),
        ("sandbox", "runtime_observation_source_mismatch"),
        ("payload", "openshell_correlation_event_mismatch"),
        ("stale", "openshell_correlation_stale"),
    ],
)
def test_conflicting_or_stale_correlation_is_rejected_without_consuming_binding(
    tmp_path, mutation, reason
):
    event, contract, source = event_fixture(), supported_contract(), source_context()
    store = CorrelationStore(tmp_path / "bindings.db")
    register_event(store, event, contract, source)
    changed_contract, changed_source, changed_event, now = (
        contract,
        source,
        copy.deepcopy(event),
        2000,
    )
    if mutation == "action":
        changed_contract = replace(contract, action_digest="c" * 64, contract_id="")
    elif mutation == "contract":
        changed_contract = replace(contract, risk="high", contract_id="")
    elif mutation == "session":
        changed_source = replace(source, session_digest="c" * 64)
    elif mutation == "policy":
        changed_source = replace(source, policy_digest="c" * 64)
    elif mutation == "sandbox":
        changed_source = replace(source, sandbox_id="other-sandbox")
    elif mutation == "payload":
        changed_event["http_request"]["http_method"] = "DELETE"
    else:
        now = 4000
    result = ingest_openshell_event(
        changed_event, contract=changed_contract, source=changed_source, store=store, now_ms=now
    )
    assert result.status == "rejected" and result.reason_code == reason
    assert (
        ingest_openshell_event(
            event, contract=contract, source=source, store=store, now_ms=2000
        ).status
        == "accepted"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"time": True},
        {"type_uid": 400201},
        {"action_id": "denied"},
        {"action": "Allowed"},
        {"disposition_id": 1},
        {"metadata": {}},
        {"http_request": {"http_method": "UNKNOWN"}},
        {"dst_endpoint": {"domain": "other.example.com", "port": 443}},
    ],
)
def test_malformed_or_conflicting_structured_fields_fail_closed(change):
    event = event_fixture()
    event.update(change)
    result = ingest_openshell_event(event)
    assert result.status == "rejected" and result.observation is None


def test_unknown_class_and_unavailable_filesystem_class_are_explicitly_unsupported():
    for class_uid in (9999, 1001):
        event = event_fixture()
        event.update(class_uid=class_uid, type_uid=class_uid * 100 + 99)
        result = ingest_openshell_event(event)
        assert result.status == "unsupported"
        assert result.reason_code == "openshell_event_class_unsupported"
        assert result.observation is None


def test_process_launch_uses_subject_process_and_omits_command_line():
    event = event_fixture()
    event.update(
        class_uid=1007,
        activity_id=1,
        type_uid=100701,
        process={"name": "/usr/bin/git", "pid": 22, "cmd_line": "secret-argument"},
        actor={"process": {"name": "openshell-sandbox", "pid": 1}},
    )
    parsed = parse_openshell_event(event)
    assert parsed.enforcement_point == "process"
    assert parsed.metadata["binary"] == "/usr/bin/git"
    assert parsed.metadata["process_id"] == 22
    assert "secret-argument" not in json.dumps(parsed.as_dict())


def test_duplicate_json_fields_nonfinite_and_nested_or_oversized_data_fail_closed():
    assert ingest_openshell_event('{"class_uid":4002,"class_uid":4001}').status == "rejected"
    assert ingest_openshell_event('{"time":NaN}').status == "rejected"
    event = event_fixture()
    event["unmapped"] = {"payload": "x" * 4097}
    with pytest.raises(OpenShellEventError):
        parse_openshell_event(event)


def test_ingested_denial_attaches_to_original_session_and_is_retained_for_later_review(tmp_path):
    session = IntegrationSession(SessionIdentity("python", "openshell-demo"), AgentGate())
    source = source_context(session.runtime_session_digest)
    session.bind_runtime_source(source)
    session.evaluate(ActionEnvelope.shell("curl https://api.github.com", action_id="step-1"))
    contract = session.runtime_contract("step-1")
    event = event_fixture()
    store = CorrelationStore(tmp_path / "bindings.db")
    register_event(store, event, contract, source)
    result = ingest_openshell_event(
        event, contract=contract, source=source, store=store, now_ms=2000
    )
    assert result.status == "accepted"
    session.observe_runtime(result.observation)
    state = session.runtime_snapshot()
    assert state["history"]["observations"][0]["trust"] == "backend_enforced"
    # The ordinary session observation path still validates the original action/contract.
    with pytest.raises(ValueError, match="duplicate"):
        session.observe_runtime(result.observation)
